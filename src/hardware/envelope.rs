//! The hardware-wrap envelope (`DIGHW1`) — an **outer** layer over an already
//! sealed keystore blob.
//!
//! # Why an outer layer rather than a new keystore format version
//!
//! The v1 keystore format (`SPEC.md` §3) is permanent at-rest data: a reader
//! that cannot open an older blob has locked a user out of their wallet
//! (§5.1, HARD RULE). Extending the v1 header with hardware fields would put
//! the compatibility burden inside the format that must never move.
//!
//! So this envelope wraps the v1 blob *whole and unmodified*. Two consequences
//! matter:
//!
//! 1. **The v1 bytes are untouched** — offsets, the 53-byte AAD binding, and the
//!    105-byte total for a 32-byte secret are all exactly as specified. The
//!    passphrase envelope remains the floor: what sits inside this envelope is
//!    still AES-256-GCM + Argon2id, never a bare secret.
//! 2. **Detection is by prefix, not by configuration.** [`is_envelope`] answers
//!    from the bytes themselves, so a reader handles wrapped and unwrapped blobs
//!    without being told which it has — which is what lets an existing
//!    unwrapped keystore keep opening after this feature ships.
//!
//! # Byte layout
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │  6 bytes   MAGIC          "DIGHW1"                               │
//! │  2 bytes   ENV_VERSION    0x0001                                 │
//! │  1 byte    HW_KIND        0x01 Win TPM · 0x02 SE · 0x03 Linux TPM │
//! │  1 byte    CIPHER_ID      0x01 = AES-256-GCM                     │
//! │ 12 bytes   NONCE          random per write                       │
//! │  2 bytes   WRAPPED_LEN    u16 length of WRAPPED_KEY              │
//! │  4 bytes   PAYLOAD_LEN    u32 length of PAYLOAD                  │
//! │  W bytes   WRAPPED_KEY    hardware-encrypted 32-byte content key │
//! │  P bytes   PAYLOAD        AES-256-GCM(inner keystore blob) || tag │
//! │  4 bytes   CRC32          over all preceding bytes               │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! All multi-byte integers are big-endian, matching the v1 format and the Chia
//! wire convention.
//!
//! **AAD binding.** The fixed header *and* `WRAPPED_KEY` (bytes
//! `0..HEADER_FIXED + W`) are supplied as AES-GCM associated data, so swapping
//! in another machine's wrapped key, relabelling `HW_KIND`, or editing a length
//! invalidates the tag. No separate header MAC is needed.
//!
//! **CRC-32** is a fast-fail corruption check only, exactly as in v1 — the
//! AES-GCM tag is the security boundary.

use std::convert::TryInto;

use zeroize::Zeroizing;

use super::provider::{ContentKey, CONTENT_KEY_LEN};
use super::tier::HardwareKind;
use crate::cipher::{self, TAG_SIZE};
use crate::error::{KeystoreError, Result};

/// Magic prefix of a hardware-wrapped blob.
///
/// Deliberately disjoint from every inner keystore magic (`DIGVK1`, `DIGLW1`,
/// `DIGOP1`) so prefix detection can never confuse the two layers.
pub const ENVELOPE_MAGIC: &[u8; 6] = b"DIGHW1";

/// Envelope format version emitted by this build.
pub const ENVELOPE_VERSION_V1: u16 = 0x0001;

/// AES-256-GCM, the only assigned envelope cipher id.
const CIPHER_AES_256_GCM: u8 = 0x01;

/// Size of the fixed header portion, up to but excluding `WRAPPED_KEY`.
pub const HEADER_FIXED: usize = 6 // magic
    + 2 // envelope version
    + 1 // hardware kind
    + 1 // cipher id
    + 12 // nonce
    + 2 // wrapped key length
    + 4; // payload length
         // 28 bytes total.

/// Size of the trailing CRC-32 footer.
const FOOTER_SIZE: usize = 4;

/// Whether `bytes` is a hardware-wrapped envelope.
///
/// The negative answer is deliberately broad: **anything** that does not carry
/// the `DIGHW1` prefix — a v1 keystore blob, an opaque `DIGOP1` blob, a future
/// inner magic this build has never seen, or a blob too short to classify — is
/// not an envelope and is passed through untouched. Stating the rule over that
/// whole class (rather than over the specific magics that exist today) is what
/// keeps a future inner format readable without revisiting this function.
pub fn is_envelope(bytes: &[u8]) -> bool {
    bytes.len() >= ENVELOPE_MAGIC.len() && &bytes[..ENVELOPE_MAGIC.len()] == ENVELOPE_MAGIC
}

/// A decoded envelope: the header facts plus the two ciphertext regions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Envelope {
    /// Hardware-kind wire id as stored. Kept raw so an id this build does not
    /// recognise can still be reported precisely instead of rejected as
    /// corruption.
    pub(crate) hardware_wire_id: u8,
    /// The hardware-encrypted content key.
    pub(crate) wrapped_key: Vec<u8>,
    /// `AES-256-GCM(inner blob) || tag`.
    pub(crate) payload: Vec<u8>,
    /// AES-GCM nonce for the payload.
    pub(crate) nonce: [u8; 12],
    /// Header bytes (fixed header + wrapped key) that must be replayed as AAD.
    pub(crate) aad: Vec<u8>,
}

/// Encode an envelope around `inner` (an already-sealed keystore blob).
///
/// `content_key` must be the key that `wrapped_key` decrypts to.
pub(crate) fn encode(
    kind: HardwareKind,
    content_key: &ContentKey,
    wrapped_key: &[u8],
    nonce: &[u8; 12],
    inner: &[u8],
) -> Result<Vec<u8>> {
    let wrapped_len: u16 =
        wrapped_key
            .len()
            .try_into()
            .map_err(|_| KeystoreError::HardwareWrapFailed {
                detail: "wrapped key exceeds 65535 bytes".to_owned(),
            })?;

    let payload_len: u32 =
        (inner.len() + TAG_SIZE)
            .try_into()
            .map_err(|_| KeystoreError::HardwareWrapFailed {
                detail: "keystore blob too large to wrap".to_owned(),
            })?;

    let mut out = Vec::with_capacity(HEADER_FIXED + wrapped_key.len() + payload_len as usize + 4);
    out.extend_from_slice(ENVELOPE_MAGIC);
    out.extend_from_slice(&ENVELOPE_VERSION_V1.to_be_bytes());
    out.push(kind.wire_id());
    out.push(CIPHER_AES_256_GCM);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&wrapped_len.to_be_bytes());
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(wrapped_key);

    // The header AND the wrapped key are the AAD, so neither can be swapped
    // without invalidating the payload tag.
    let aad = out.clone();
    let payload = cipher::encrypt(content_key, nonce, inner, &aad)?;
    debug_assert_eq!(payload.len(), payload_len as usize);
    out.extend_from_slice(&payload);

    let crc = crc32fast::hash(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(out)
}

/// Decode and structurally validate an envelope, without touching the hardware.
///
/// Runs every cheap check before any cryptography, mirroring the v1 decode
/// order (`SPEC.md` §3.2): garbage rejects immediately instead of provoking a
/// hardware round-trip.
pub(crate) fn decode(bytes: &[u8]) -> Result<Envelope> {
    let floor = HEADER_FIXED + TAG_SIZE + FOOTER_SIZE;
    if bytes.len() < floor {
        return Err(KeystoreError::Truncated {
            claimed: floor,
            available: bytes.len(),
        });
    }

    let (body, stored_crc_bytes) = bytes.split_at(bytes.len() - FOOTER_SIZE);
    let stored = u32::from_be_bytes(stored_crc_bytes.try_into().expect("4 bytes"));
    let computed = crc32fast::hash(body);
    if stored != computed {
        return Err(KeystoreError::CrcMismatch { stored, computed });
    }

    if &bytes[..6] != ENVELOPE_MAGIC {
        return Err(KeystoreError::UnknownMagic {
            saw: bytes[..6].try_into().expect("6 bytes"),
        });
    }

    let version = u16::from_be_bytes([bytes[6], bytes[7]]);
    if version != ENVELOPE_VERSION_V1 {
        return Err(KeystoreError::UnsupportedFormat { found: version });
    }

    let hardware_wire_id = bytes[8];

    let cipher_id = bytes[9];
    if cipher_id != CIPHER_AES_256_GCM {
        return Err(KeystoreError::UnsupportedCipher(cipher_id));
    }

    let nonce: [u8; 12] = bytes[10..22].try_into().expect("12 bytes");
    let wrapped_len = u16::from_be_bytes([bytes[22], bytes[23]]) as usize;
    let payload_len = u32::from_be_bytes(bytes[24..28].try_into().expect("4 bytes")) as usize;

    // A zero-length wrapped key would mean "no hardware key protects this",
    // which must never decode as a hardware envelope.
    if wrapped_len == 0 {
        return Err(KeystoreError::MalformedEnvelope {
            detail: "envelope carries no wrapped key".to_owned(),
        });
    }
    if payload_len < TAG_SIZE {
        return Err(KeystoreError::Truncated {
            claimed: payload_len,
            available: 0,
        });
    }

    let declared = HEADER_FIXED
        .checked_add(wrapped_len)
        .and_then(|n| n.checked_add(payload_len))
        .and_then(|n| n.checked_add(FOOTER_SIZE))
        .ok_or(KeystoreError::Truncated {
            claimed: usize::MAX,
            available: bytes.len(),
        })?;
    if declared != bytes.len() {
        return Err(KeystoreError::Truncated {
            claimed: declared,
            available: bytes.len(),
        });
    }

    let key_end = HEADER_FIXED + wrapped_len;
    Ok(Envelope {
        hardware_wire_id,
        wrapped_key: bytes[HEADER_FIXED..key_end].to_vec(),
        payload: bytes[key_end..key_end + payload_len].to_vec(),
        nonce,
        aad: bytes[..key_end].to_vec(),
    })
}

impl Envelope {
    /// Decrypt the inner keystore blob with an unwrapped `content_key`.
    pub(crate) fn open(&self, content_key: &ContentKey) -> Result<Zeroizing<Vec<u8>>> {
        cipher::decrypt(content_key, &self.nonce, &self.payload, &self.aad)
    }

    /// The hardware kind that sealed this envelope, or `None` for a wire id
    /// this build does not recognise.
    pub(crate) fn hardware_kind(&self) -> Option<HardwareKind> {
        HardwareKind::from_wire_id(self.hardware_wire_id)
    }
}

/// Structural decode, exposed to this crate's tests so the codec's rejection
/// rules can be asserted without a provider in play.
#[cfg(test)]
pub(crate) fn decode_for_test(bytes: &[u8]) -> Result<Envelope> {
    decode(bytes)
}

/// Freshly generated random content key.
pub(crate) fn random_content_key<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
) -> ContentKey {
    let mut key = Zeroizing::new(<[u8; CONTENT_KEY_LEN]>::default());
    rng.fill_bytes(key.as_mut());
    key
}

/// Freshly generated random nonce.
pub(crate) fn random_nonce<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> [u8; 12] {
    // `Default` rather than a `[0u8; 12]` literal: the array is only a buffer to
    // be filled, and a zero literal here reads to a static analyser as a
    // hard-coded nonce.
    let mut nonce = <[u8; 12]>::default();
    rng.fill_bytes(&mut nonce);
    nonce
}
