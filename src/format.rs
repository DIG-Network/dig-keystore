//! On-disk file format v1.
//!
//! # Byte layout
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  6 bytes   MAGIC             "DIGVK1" or "DIGLW1"           │
//! │  2 bytes   FORMAT_VERSION    0x0001                         │
//! │  2 bytes   KEY_SCHEME        0x0001=BlsSigning              │
//! │                              0x0003=L1WalletBls             │
//! │  1 byte    KDF_ID            0x01 = Argon2id                │
//! │  4 bytes   KDF_MEMORY_KIB    u32 (default 65536 = 64 MiB)   │
//! │  4 bytes   KDF_ITERATIONS    u32 (default 3)                │
//! │  1 byte    KDF_LANES         u8  (default 4)                │
//! │  1 byte    CIPHER_ID         0x01 = AES-256-GCM             │
//! │ 16 bytes   SALT              random per file                │
//! │ 12 bytes   NONCE             random per file                │
//! │  4 bytes   PAYLOAD_LEN       u32 (ciphertext+tag length)    │
//! │  N bytes   CIPHERTEXT+TAG    AES-256-GCM(plaintext) || tag  │
//! │  4 bytes   CRC32             over all preceding bytes       │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! Total header size is **53 bytes**. Total file size for a 32-byte secret
//! (every shipped scheme) is `53 + 48 + 4 = 105 bytes`.
//!
//! # Encoding conventions
//!
//! - **All multi-byte integers big-endian.** Consistent with the Chia wire
//!   format which `dig-protocol` re-exports.
//! - **Header bound into AES-GCM AAD.** The 53 bytes of header are fed to
//!   `aes-gcm::encrypt` as associated data so any header edit invalidates
//!   the authentication tag — no separate header MAC needed.
//! - **Outer CRC-32.** Provides a fast-fail check before we spend ~0.5 s on
//!   Argon2id for a file that's been bit-rotten. CRC is **not** a security
//!   check — it catches accidents, not attacks.
//!
//! # Why not bincode / serde
//!
//! We hand-code the encoder/decoder so the byte layout is exact and stable
//! across every Rust version and serde variant. Keystore files are meant to
//! survive operator OS upgrades, Rust-toolchain churn, and occasionally
//! cross-tool migration. A serde-derived format would couple the on-disk
//! shape to the current serde conventions; hand-coding makes the format
//! a proper specification (see `docs/resources/SPEC.md`).
//!
//! # Forward compatibility
//!
//! `FORMAT_VERSION` is a `u16`, giving room for 65 535 versions. This crate
//! parses `0x0001` only; older or newer versions fail cleanly with
//! [`KeystoreError::UnsupportedFormat`]. When v2 ships (e.g., to add a new
//! KDF algorithm or extend `CipherId`), the decoder will route based on
//! `FORMAT_VERSION` and the shipped v1 files will continue to load.
//!
//! # References
//!
//! - [IEEE 802.3 CRC-32](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) — the
//!   CRC polynomial used by [`crc32fast`](https://docs.rs/crc32fast).
//! - [`aes-gcm` AAD](https://docs.rs/aes-gcm/latest/aes_gcm/struct.Aes256Gcm.html#method.encrypt)
//!   — the associated-data semantics we rely on.
//! - [RFC 5116 §3](https://datatracker.ietf.org/doc/html/rfc5116#section-3) —
//!   generic AEAD interface including AAD definition.

use std::convert::TryInto;

use crate::cipher::TAG_SIZE;
use crate::error::{KeystoreError, Result};

/// File format version supported by this library.
pub const FORMAT_VERSION_V1: u16 = 0x0001;

/// Header (fixed-size portion of the file).
pub(crate) const HEADER_SIZE: usize = 6 // magic
    + 2 // format version
    + 2 // scheme id
    + 1 // kdf id
    + 4 // kdf memory
    + 4 // kdf iterations
    + 1 // kdf lanes
    + 1 // cipher id
    + 16 // salt
    + 12 // nonce
    + 4; // payload len
// 53 bytes total.

/// Footer (CRC32) size.
pub(crate) const FOOTER_SIZE: usize = 4;

/// Identifies the symmetric cipher used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherId {
    /// AES-256 in Galois/Counter Mode (RFC 5116).
    Aes256Gcm = 0x01,
}

impl CipherId {
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Self::Aes256Gcm),
            other => Err(KeystoreError::UnsupportedCipher(other)),
        }
    }
}

/// Identifies the key derivation function used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KdfId {
    /// Argon2id per RFC 9106.
    Argon2id = 0x01,
}

impl KdfId {
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Self::Argon2id),
            other => Err(KeystoreError::UnsupportedKdf(other)),
        }
    }
}

/// Parameters for the key derivation function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Function identifier.
    pub id: KdfId,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Iteration count.
    pub iterations: u32,
    /// Parallelism (lanes).
    pub lanes: u8,
}

impl KdfParams {
    /// Recommended default (matches `dig-l1-wallet`): 64 MiB / 3 iterations / 4 lanes.
    pub const DEFAULT: Self = Self {
        id: KdfId::Argon2id,
        memory_kib: 65536,
        iterations: 3,
        lanes: 4,
    };

    /// Strong preset for high-value keys: 256 MiB / 4 iterations / 4 lanes.
    pub const STRONG: Self = Self {
        id: KdfId::Argon2id,
        memory_kib: 262144,
        iterations: 4,
        lanes: 4,
    };

    /// Fast preset suitable only for tests: 8 MiB / 1 iteration / 1 lane.
    /// Never use this for real keys.
    #[doc(hidden)]
    pub const FAST_TEST: Self = Self {
        id: KdfId::Argon2id,
        memory_kib: 8 * 1024,
        iterations: 1,
        lanes: 1,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Parsed file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeystoreHeader {
    /// Magic bytes (identifies scheme family).
    pub magic: [u8; 6],
    /// Format version.
    pub format_version: u16,
    /// Scheme id — must match the `KeyScheme::SCHEME_ID` of the type parameter.
    pub scheme_id: u16,
    /// KDF parameters used to derive the encryption key.
    pub kdf: KdfParams,
    /// Symmetric cipher used.
    pub cipher: CipherId,
    /// Random salt for the KDF.
    pub salt: [u8; 16],
    /// Random nonce for AES-GCM.
    pub nonce: [u8; 12],
    /// Length of the following ciphertext + tag blob, in bytes.
    pub payload_len: u32,
}

impl KeystoreHeader {
    /// Serialize the header into `HEADER_SIZE` bytes.
    pub(crate) fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        let mut i = 0;
        out[i..i + 6].copy_from_slice(&self.magic);
        i += 6;
        out[i..i + 2].copy_from_slice(&self.format_version.to_be_bytes());
        i += 2;
        out[i..i + 2].copy_from_slice(&self.scheme_id.to_be_bytes());
        i += 2;
        out[i] = self.kdf.id as u8;
        i += 1;
        out[i..i + 4].copy_from_slice(&self.kdf.memory_kib.to_be_bytes());
        i += 4;
        out[i..i + 4].copy_from_slice(&self.kdf.iterations.to_be_bytes());
        i += 4;
        out[i] = self.kdf.lanes;
        i += 1;
        out[i] = self.cipher as u8;
        i += 1;
        out[i..i + 16].copy_from_slice(&self.salt);
        i += 16;
        out[i..i + 12].copy_from_slice(&self.nonce);
        i += 12;
        out[i..i + 4].copy_from_slice(&self.payload_len.to_be_bytes());
        i += 4;
        debug_assert_eq!(i, HEADER_SIZE);
        out
    }

    /// Parse a header from raw bytes. Returns `UnknownMagic`, `UnsupportedFormat`,
    /// `UnsupportedKdf`, or `UnsupportedCipher` on failure.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(KeystoreError::Truncated {
                claimed: HEADER_SIZE,
                available: bytes.len(),
            });
        }
        let mut i = 0;
        let magic: [u8; 6] = bytes[i..i + 6].try_into().unwrap();
        i += 6;
        if !is_known_magic(&magic) {
            return Err(KeystoreError::UnknownMagic { saw: magic });
        }

        let format_version = u16::from_be_bytes(bytes[i..i + 2].try_into().unwrap());
        i += 2;
        if format_version != FORMAT_VERSION_V1 {
            return Err(KeystoreError::UnsupportedFormat {
                found: format_version,
            });
        }

        let scheme_id = u16::from_be_bytes(bytes[i..i + 2].try_into().unwrap());
        i += 2;

        let kdf_id = KdfId::from_byte(bytes[i])?;
        i += 1;
        let memory_kib = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap());
        i += 4;
        let iterations = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap());
        i += 4;
        let lanes = bytes[i];
        i += 1;

        let cipher = CipherId::from_byte(bytes[i])?;
        i += 1;

        let salt: [u8; 16] = bytes[i..i + 16].try_into().unwrap();
        i += 16;
        let nonce: [u8; 12] = bytes[i..i + 12].try_into().unwrap();
        i += 12;
        let payload_len = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap());
        i += 4;
        debug_assert_eq!(i, HEADER_SIZE);

        Ok(Self {
            magic,
            format_version,
            scheme_id,
            kdf: KdfParams {
                id: kdf_id,
                memory_kib,
                iterations,
                lanes,
            },
            cipher,
            salt,
            nonce,
            payload_len,
        })
    }
}

/// Known magic prefixes. Extended by schemes; see `scheme/*`.
fn is_known_magic(m: &[u8; 6]) -> bool {
    // Matches MAGIC constants in the scheme impls. Kept inline here for
    // decode-time validation without needing generic parameters.
    matches!(m, b"DIGVK1" | b"DIGLW1")
}

/// Serialize the complete file: `header || ciphertext_and_tag || crc32`.
pub(crate) fn encode_file(header: &KeystoreHeader, ciphertext_and_tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + ciphertext_and_tag.len() + FOOTER_SIZE);
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(ciphertext_and_tag);
    let crc = crc32fast::hash(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    out
}

/// Parse a complete file: returns `(header, ciphertext_and_tag, header_bytes_for_aad)`.
///
/// The header bytes are returned separately so they can be fed to AES-GCM as AAD.
pub(crate) fn decode_file(bytes: &[u8]) -> Result<(KeystoreHeader, Vec<u8>, [u8; HEADER_SIZE])> {
    if bytes.len() < HEADER_SIZE + TAG_SIZE + FOOTER_SIZE {
        return Err(KeystoreError::Truncated {
            claimed: HEADER_SIZE + TAG_SIZE + FOOTER_SIZE,
            available: bytes.len(),
        });
    }

    // CRC32 is over everything except the trailing 4 bytes.
    let crc_stored = u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
    let crc_computed = crc32fast::hash(&bytes[..bytes.len() - 4]);
    if crc_stored != crc_computed {
        return Err(KeystoreError::CrcMismatch {
            stored: crc_stored,
            computed: crc_computed,
        });
    }

    let header_bytes: [u8; HEADER_SIZE] = bytes[..HEADER_SIZE].try_into().unwrap();
    let header = KeystoreHeader::decode(&header_bytes)?;

    let payload_start = HEADER_SIZE;
    let payload_end = payload_start + header.payload_len as usize;
    if payload_end + FOOTER_SIZE > bytes.len() {
        return Err(KeystoreError::Truncated {
            claimed: payload_end + FOOTER_SIZE,
            available: bytes.len(),
        });
    }

    let ciphertext_and_tag = bytes[payload_start..payload_end].to_vec();
    Ok((header, ciphertext_and_tag, header_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> KeystoreHeader {
        KeystoreHeader {
            magic: *b"DIGVK1",
            format_version: FORMAT_VERSION_V1,
            scheme_id: 0x0001,
            kdf: KdfParams::FAST_TEST,
            cipher: CipherId::Aes256Gcm,
            salt: [9u8; 16],
            nonce: [2u8; 12],
            payload_len: 48,
        }
    }

    /// **Proves:** `KeystoreHeader::encode` then `KeystoreHeader::decode`
    /// recovers every field of the header bit-exactly.
    ///
    /// **Why it matters:** The header carries the scheme id, KDF params,
    /// salt, nonce, and payload length — every byte must round-trip so the
    /// file's internal pointers stay valid. Also pins [`HEADER_SIZE`] to 53
    /// bytes: the encoded form must exactly match the pre-declared size.
    ///
    /// **Catches:** an endian bug (writing LE but reading BE), a field
    /// reordering, or a field accidentally dropped from either the encoder
    /// or the decoder.
    #[test]
    fn header_roundtrip() {
        let h = sample_header();
        let bytes = h.encode();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let h2 = KeystoreHeader::decode(&bytes).unwrap();
        assert_eq!(h, h2);
    }

    /// **Proves:** a file whose first 6 bytes are not a recognized magic
    /// (here we flip the first byte from `D` → `X`) is rejected with
    /// [`KeystoreError::UnknownMagic`] before any cryptography runs.
    ///
    /// **Why it matters:** If a user points `Keystore::load` at an arbitrary
    /// file on disk (a `.txt`, a deleted keystore, a different project's
    /// wallet file), we must fail with a clear error rather than attempting
    /// Argon2 + AES-GCM on garbage. This is also a cheap DoS guard —
    /// bogus files reject in microseconds.
    ///
    /// **Catches:** a regression that skips the magic check and runs the
    /// KDF anyway; a new scheme whose magic was registered in a constant
    /// but not in `is_known_magic`.
    #[test]
    fn unknown_magic_rejected() {
        let mut bytes = sample_header().encode();
        bytes[0] = b'X';
        let err = KeystoreHeader::decode(&bytes).unwrap_err();
        assert!(matches!(err, KeystoreError::UnknownMagic { .. }));
    }

    /// **Proves:** `FORMAT_VERSION = 999` is rejected with
    /// [`KeystoreError::UnsupportedFormat { found: 999 }`].
    ///
    /// **Why it matters:** Future versions (v2, v3) will bump the format
    /// version. A v1-only binary must refuse v2 files with a clear error
    /// rather than misinterpret their bytes. Conversely, a v2 binary will
    /// see this test's behaviour as the correct template for how to handle
    /// v1 files if we ever deprecate them.
    ///
    /// **Catches:** a decoder that silently assumes `FORMAT_VERSION_V1`
    /// and ignores the field.
    #[test]
    fn bad_format_version_rejected() {
        let mut h = sample_header();
        h.format_version = 999;
        let err = KeystoreHeader::decode(&h.encode()).unwrap_err();
        assert!(matches!(err, KeystoreError::UnsupportedFormat { found: 999 }));
    }

    /// **Proves:** the KDF-id byte at offset 10 is checked — writing `0xFF`
    /// (an unassigned value) is rejected with [`KeystoreError::UnsupportedKdf`].
    ///
    /// **Why it matters:** The KDF id is a forward-compatibility hinge —
    /// when scrypt or a future KDF is added, files with the new id will
    /// fail on older binaries this way. If the check were missing, the
    /// decoder would silently try to use Argon2id on scrypt-derived
    /// parameters, producing wrong keys.
    ///
    /// **Catches:** a decoder that hard-codes `KdfId::Argon2id` without
    /// reading and validating the header byte.
    #[test]
    fn bad_kdf_id_rejected() {
        let mut bytes = sample_header().encode();
        // KDF id byte is at offset 6 + 2 + 2 = 10
        bytes[10] = 0xFF;
        let err = KeystoreHeader::decode(&bytes).unwrap_err();
        assert!(matches!(err, KeystoreError::UnsupportedKdf(0xFF)));
    }

    /// **Proves:** the cipher-id byte at offset 20 is checked — writing
    /// `0xFE` (an unassigned value) is rejected with
    /// [`KeystoreError::UnsupportedCipher`].
    ///
    /// **Why it matters:** Parallels the KDF-id check. If someone swaps in
    /// ChaCha20-Poly1305 as cipher id `0x02`, older binaries must reject
    /// that file rather than attempt AES-256-GCM on it.
    ///
    /// **Catches:** a decoder that hard-codes `CipherId::Aes256Gcm`.
    #[test]
    fn bad_cipher_id_rejected() {
        let mut bytes = sample_header().encode();
        // Cipher id byte is at offset 6+2+2 + 1+4+4+1 = 20
        bytes[20] = 0xFE;
        let err = KeystoreHeader::decode(&bytes).unwrap_err();
        assert!(matches!(err, KeystoreError::UnsupportedCipher(0xFE)));
    }

    /// **Proves:** whole-file round-trip (`encode_file` → `decode_file`)
    /// recovers the header and the payload bit-exactly, and the CRC-32 is
    /// validated.
    ///
    /// **Why it matters:** This is the unit-test-level equivalent of
    /// "create a file, load it back, make sure nothing got corrupted."
    /// Decouples the file-layout logic from all upstream cryptography so
    /// format bugs surface in isolation.
    ///
    /// **Catches:** off-by-one in CRC coverage (e.g., crc computed over
    /// the whole file including itself), header/payload size miscalculation.
    #[test]
    fn file_roundtrip_valid_crc() {
        let h = sample_header();
        let payload = vec![0x42u8; h.payload_len as usize];
        let bytes = encode_file(&h, &payload);
        let (h2, pl2, _) = decode_file(&bytes).unwrap();
        assert_eq!(h2, h);
        assert_eq!(pl2, payload);
    }

    /// **Proves:** flipping the last byte of a file (inside the 4-byte CRC-32
    /// footer) causes [`KeystoreError::CrcMismatch`] at decode time.
    ///
    /// **Why it matters:** CRC is our fast-fail for bit-rot and accidental
    /// truncation. It runs before we spend ~0.5s on Argon2id, so a torn
    /// file errors in microseconds rather than forcing the user to wait for
    /// a KDF run. This test pins the CRC coverage: the last byte must be
    /// included in the input to the check.
    ///
    /// **Catches:** an off-by-one where CRC is computed over `&bytes[..len]`
    /// instead of `&bytes[..len - 4]`, or where the stored-CRC is read
    /// from the wrong offset.
    #[test]
    fn crc_mismatch_detected() {
        let h = sample_header();
        let payload = vec![0x42u8; h.payload_len as usize];
        let mut bytes = encode_file(&h, &payload);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let err = decode_file(&bytes).unwrap_err();
        assert!(matches!(err, KeystoreError::CrcMismatch { .. }));
    }

    /// **Proves:** a file shorter than `HEADER_SIZE + TAG_SIZE + FOOTER_SIZE`
    /// is rejected with [`KeystoreError::Truncated`] rather than producing
    /// a panic or an out-of-bounds slice.
    ///
    /// **Why it matters:** Partial writes, network transfers cut mid-file,
    /// `truncate(path, n)` attacks — all should fail cleanly. A panic here
    /// would crash the fullnode / validator binary at startup.
    ///
    /// **Catches:** a slice-index regression that would panic on truncated
    /// input; e.g. `bytes[0..HEADER_SIZE]` without length check.
    #[test]
    fn truncated_file_rejected() {
        let err = decode_file(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, KeystoreError::Truncated { .. }));
    }

    /// **Proves:** the header encoded to bytes is exactly 53 bytes long, and
    /// the [`HEADER_SIZE`] constant equals 53.
    ///
    /// **Why it matters:** This is a wire-format constant — every keystore
    /// file ever written has 53-byte header. If we change it, every
    /// deployed keystore becomes unreadable. The test makes accidental
    /// drift impossible without a visible test failure.
    ///
    /// **Catches:** adding a field to [`KeystoreHeader`] without updating
    /// [`HEADER_SIZE`], or vice versa.
    #[test]
    fn header_size_constant_correct() {
        assert_eq!(sample_header().encode().len(), HEADER_SIZE);
        assert_eq!(HEADER_SIZE, 53);
    }
}
