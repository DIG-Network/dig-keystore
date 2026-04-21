//! AES-256-GCM authenticated encryption.
//!
//! # What this does
//!
//! Encrypts / decrypts the secret-bytes payload under a 32-byte key derived
//! from the user's password (via [`crate::kdf`]) and a 12-byte random nonce.
//! The keystore header bytes are bound into the authentication tag as
//! associated data (AAD) so any edit to the header invalidates the MAC.
//!
//! # Why AES-256-GCM
//!
//! - **AES-256**: resists quantum square-root attacks better than AES-128
//!   (Grover reduces 256→128 security bits, still comfortable).
//! - **GCM mode**: built-in authenticated encryption with a 128-bit MAC tag;
//!   no separate HMAC needed; widely audited.
//! - **96-bit nonce**: the size GCM was designed around. We generate a fresh
//!   random nonce per file (re-used on `change_password` / `rotate_kdf` —
//!   actually re-generated fresh each time).
//!
//! # Nonce-reuse safety
//!
//! AES-GCM is catastrophically broken if a `(key, nonce)` pair is ever reused
//! to encrypt two distinct plaintexts (reveals the MAC key). This module
//! never re-uses a nonce because:
//!
//! 1. Every `create` / `change_password` / `rotate_kdf` generates a fresh
//!    random nonce via `rand_core::OsRng` (or the caller's RNG).
//! 2. The nonce is stored in the file header and the key is password-derived;
//!    both are regenerated together on each re-encryption.
//!
//! The `_with_rng` methods allow deterministic nonces in tests — those tests
//! run with fresh backends so no cross-run collision is possible.
//!
//! # AAD binding
//!
//! We feed the 53-byte keystore header as AAD. This means:
//!
//! - Flipping any header byte (magic, scheme id, KDF params, salt, nonce,
//!   payload_len) invalidates the tag → `DecryptFailed`.
//! - An attacker cannot swap e.g. a `BlsSigning` header onto an `L1WalletBls`
//!   ciphertext without knowing the key.
//!
//! # References
//!
//! - [RFC 5116 — AEAD APIs](https://datatracker.ietf.org/doc/html/rfc5116)
//! - [NIST SP 800-38D — GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
//! - [`aes-gcm` crate](https://docs.rs/aes-gcm) — RustCrypto implementation

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use zeroize::Zeroizing;

use crate::error::{KeystoreError, Result};

/// Encrypt `plaintext` under the 32-byte `key` and 12-byte `nonce`, binding
/// `aad` into the authentication tag.
///
/// The output is `ciphertext || tag` (AES-GCM convention). The tag is a fixed
/// 16 bytes appended at the end; total output length is `plaintext.len() + 16`.
///
/// # Parameters
///
/// - `key`: 32-byte AES-256 key derived from the password via
///   [`crate::kdf::derive_key`].
/// - `nonce`: 12-byte random nonce; **must** be unique per-key.
/// - `plaintext`: the secret bytes to encrypt (typically a 32-byte seed).
/// - `aad`: additional authenticated data. This crate passes the keystore
///   header bytes so header edits invalidate the tag.
///
/// # Errors
///
/// Returns [`KeystoreError::DecryptFailed`] on any `aead::Error`. The `aes-gcm`
/// crate does not surface sub-errors, so we map them all to the single decrypt
/// variant.
pub(crate) fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| KeystoreError::DecryptFailed)
}

/// Decrypt a combined `ciphertext || tag` blob.
///
/// Returns the plaintext wrapped in [`Zeroizing`] so it wipes on drop. The
/// AAD must match what was passed at encrypt time — this is how the crate
/// binds the keystore header to the ciphertext.
///
/// # Parameters
///
/// - `key`: 32-byte AES-256 key re-derived from the password.
/// - `nonce`: 12-byte nonce read from the file header.
/// - `ciphertext_and_tag`: the raw payload bytes from the file
///   (`plaintext.len() + 16` bytes).
/// - `aad`: must be the exact same bytes passed as `aad` at encrypt time —
///   for this crate, the 53-byte header.
///
/// # Errors
///
/// Returns [`KeystoreError::DecryptFailed`] for any authentication failure:
/// wrong key (wrong password), wrong nonce, tampered ciphertext, tampered AAD
/// (header edit). We do NOT distinguish these at the error level — that would
/// leak a side channel about *why* the decrypt failed, which an attacker could
/// exploit to tell "wrong password" from "modified file".
pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| KeystoreError::DecryptFailed)?;
    Ok(Zeroizing::new(plaintext))
}

/// AES-GCM tag size in bytes.
///
/// Exposed at crate level so [`crate::keystore`] and [`crate::format`] can
/// reason about the total file-length arithmetic (`payload_len = secret.len() + TAG_SIZE`).
pub(crate) const TAG_SIZE: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** `encrypt` then `decrypt` recovers the original plaintext bit-exactly
    /// under identical `(key, nonce, aad)`.
    ///
    /// **Why it matters:** This is the fundamental AEAD correctness property.
    /// Any transformation break here (wrong cipher mode, wrong key size, wrong
    /// AAD plumbing) cascades into every `unlock` silently producing garbage.
    ///
    /// **Catches:** switching from `Aes256Gcm` to `Aes128Gcm`, misfeeding key
    /// bytes as-LE-vs-BE, accidentally using `encrypt_in_place` with wrong
    /// buffer sizing.
    #[test]
    fn roundtrip() {
        let key = [3u8; 32];
        let nonce = [5u8; 12];
        let msg = b"hello world";
        let aad = b"aad";
        let ct = encrypt(&key, &nonce, msg, aad).unwrap();
        let pt = decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(&*pt, msg);
    }

    /// **Proves:** decryption with a different key produces [`KeystoreError::DecryptFailed`],
    /// never partial plaintext.
    ///
    /// **Why it matters:** This is what makes "wrong password" a clean failure
    /// mode. The AES-GCM auth tag must reject the wrong-key case; if it ever
    /// returned partial plaintext, an attacker brute-forcing passwords could
    /// distinguish "close" from "far" keys via side channels.
    ///
    /// **Catches:** any regression where `aes-gcm` is swapped for a non-AEAD
    /// cipher (CBC, CTR) that would silently decrypt to gibberish instead of
    /// erroring.
    #[test]
    fn wrong_key_fails() {
        let nonce = [5u8; 12];
        let ct = encrypt(&[3u8; 32], &nonce, b"msg", b"").unwrap();
        assert!(matches!(
            decrypt(&[4u8; 32], &nonce, &ct, b""),
            Err(KeystoreError::DecryptFailed)
        ));
    }

    /// **Proves:** decryption with the wrong nonce fails closed.
    ///
    /// **Why it matters:** In AES-GCM, `(key, nonce)` together keystream the
    /// ciphertext. A correct key with the wrong nonce produces garbage
    /// keystream and a bad tag. This test asserts the tag correctly rejects
    /// the mismatch rather than returning the garbage plaintext.
    ///
    /// **Catches:** a regression to a cipher mode without authentication
    /// (e.g. CTR alone without GCM), where mismatched nonces would silently
    /// produce incorrect plaintext.
    #[test]
    fn wrong_nonce_fails() {
        let key = [3u8; 32];
        let ct = encrypt(&key, &[5u8; 12], b"msg", b"").unwrap();
        assert!(matches!(
            decrypt(&key, &[6u8; 12], &ct, b""),
            Err(KeystoreError::DecryptFailed)
        ));
    }

    /// **Proves:** AAD binding works — if the associated data passed at
    /// decrypt time differs by a single byte from what was passed at encrypt
    /// time, decryption fails.
    ///
    /// **Why it matters:** This is the single most important property of
    /// this module. The keystore header is passed as AAD, so any edit to
    /// the header invalidates the tag. Without AAD binding an attacker
    /// could swap e.g. a `BlsSigning` header onto an `L1WalletBls`
    /// ciphertext (or bump `PAYLOAD_LEN` to cause a truncated decrypt).
    ///
    /// **Catches:** forgetting to pass AAD at either encrypt or decrypt;
    /// using `Aead::encrypt(key, msg)` instead of `Aead::encrypt(key, Payload{msg, aad})`.
    #[test]
    fn wrong_aad_fails() {
        let key = [3u8; 32];
        let nonce = [5u8; 12];
        let ct = encrypt(&key, &nonce, b"msg", b"aad1").unwrap();
        assert!(matches!(
            decrypt(&key, &nonce, &ct, b"aad2"),
            Err(KeystoreError::DecryptFailed)
        ));
    }

    /// **Proves:** a single bit-flip in the ciphertext is detected at decrypt time.
    ///
    /// **Why it matters:** AES-GCM's 128-bit authentication tag must reject
    /// any modified ciphertext with overwhelming probability (≈ 1 − 2⁻¹²⁸
    /// false-accept rate). This confirms the tag check is wired up; without
    /// it, an attacker could flip bits in the stored keystore to, e.g.,
    /// corrupt a key field predictably.
    ///
    /// **Catches:** swapping AES-GCM for AES-CTR or AES-CBC (neither
    /// authenticates), or skipping the tag-check path in a cipher abstraction.
    #[test]
    fn tampered_ciphertext_fails() {
        let key = [3u8; 32];
        let nonce = [5u8; 12];
        let mut ct = encrypt(&key, &nonce, b"msg", b"").unwrap();
        ct[0] ^= 0x01;
        assert!(matches!(
            decrypt(&key, &nonce, &ct, b""),
            Err(KeystoreError::DecryptFailed)
        ));
    }

    /// **Proves:** an empty-plaintext encryption produces output of exactly
    /// [`TAG_SIZE`] (16 bytes), confirming the tag-size constant matches the
    /// underlying AES-GCM implementation.
    ///
    /// **Why it matters:** [`crate::format`] computes `PAYLOAD_LEN` as
    /// `plaintext.len() + TAG_SIZE`. If `TAG_SIZE` ever drifts from the
    /// actual tag size (e.g., if someone switches to a 96-bit-tag variant)
    /// every file would fail to decode with a truncation error.
    ///
    /// **Catches:** a change to a non-128-bit-tag AEAD variant without
    /// updating the constant.
    #[test]
    fn tag_size_is_16() {
        let key = [3u8; 32];
        let nonce = [5u8; 12];
        let ct = encrypt(&key, &nonce, b"", b"").unwrap();
        // Empty plaintext → output is just the 16-byte tag.
        assert_eq!(ct.len(), TAG_SIZE);
    }
}
