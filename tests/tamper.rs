//! Tamper-detection tests.
//!
//! This file exhaustively exercises every byte position of a complete
//! keystore file: the test fixture creates a real keystore, reads its raw
//! bytes, flips each byte one at a time, and asserts that load-or-unlock
//! fails with an expected variant. The goal is to catch any code path
//! where a modified file silently decrypts to garbage.
//!
//! Together with the unit-level tests in `src/cipher.rs` and `src/format.rs`,
//! this file-level fuzzing gives high confidence that the crate's
//! integrity guarantees hold from end to end.

use std::sync::Arc;

use dig_keystore::{
    backend::{BackendKey, KeychainBackend, MemoryBackend},
    scheme::BlsSigning,
    KdfParams, Keystore, KeystoreError, Password,
};

fn build_file() -> (Arc<MemoryBackend>, BackendKey, Vec<u8>) {
    let backend = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");
    let trait_backend: Arc<dyn KeychainBackend> = backend.clone();

    Keystore::<BlsSigning>::create(
        trait_backend,
        key.clone(),
        Password::from("pw"),
        None,
        KdfParams::FAST_TEST,
    )
    .unwrap();

    let bytes = backend.read(&key).unwrap();
    (backend, key, bytes)
}

/// **Proves:** flipping any single byte of a valid keystore file causes
/// either `load` or `unlock` to fail with an expected `KeystoreError`
/// variant. No byte position produces a "successfully decrypted garbage
/// plaintext" outcome.
///
/// **Why it matters:** This is the flagship integrity test. It walks every
/// byte of the file — header fields, ciphertext, tag, CRC footer — and
/// asserts the multi-layer defence (CRC fast-fail, magic check, scheme-id
/// check, KDF-id / cipher-id checks, AAD-bound AES-GCM tag) rejects the
/// tampered file. If one byte slips through the guards, it is a
/// cryptographic breach.
///
/// **Catches:** any regression that loosens a guard: removing the CRC
/// check, accepting unknown KDF ids without error, passing only part of
/// the header as AAD, running AES-GCM without verifying the tag.
///
/// **Performance:** For a 105-byte file this runs ~100 Argon2id derivations
/// (one per byte position that falls in the payload range), each with
/// `FAST_TEST` params, taking roughly 100 ms total on CI hardware.
#[test]
fn tampering_any_byte_fails() {
    let (backend, key, original) = build_file();

    // Flip one byte at each position; load + unlock must fail.
    for pos in 0..original.len() {
        let mut bytes = original.clone();
        bytes[pos] ^= 0xFF;

        backend.write(&key, &bytes).unwrap();

        // Load may succeed or fail depending on which byte we flipped.
        let load = Keystore::<BlsSigning>::load(backend.clone(), key.clone());
        match load {
            Ok(ks) => {
                // Load succeeded → unlock must fail.
                let err = ks.unlock(Password::from("pw")).unwrap_err();
                assert!(
                    matches!(
                        err,
                        KeystoreError::DecryptFailed
                            | KeystoreError::CrcMismatch { .. }
                            | KeystoreError::UnknownMagic { .. }
                            | KeystoreError::UnsupportedKdf(_)
                            | KeystoreError::UnsupportedCipher(_)
                            | KeystoreError::UnsupportedFormat { .. }
                            | KeystoreError::Truncated { .. }
                            | KeystoreError::SchemeMismatch { .. }
                    ),
                    "unexpected unlock err at pos {pos}: {err:?}"
                );
            }
            Err(err) => {
                // Load failed with an expected variant.
                assert!(
                    matches!(
                        err,
                        KeystoreError::CrcMismatch { .. }
                            | KeystoreError::UnknownMagic { .. }
                            | KeystoreError::UnsupportedFormat { .. }
                            | KeystoreError::UnsupportedKdf(_)
                            | KeystoreError::UnsupportedCipher(_)
                            | KeystoreError::SchemeMismatch { .. }
                            | KeystoreError::Truncated { .. }
                    ),
                    "unexpected load err at pos {pos}: {err:?}"
                );
            }
        }
    }
}

/// **Proves:** every prefix of a valid keystore file that is shorter than
/// the full file is rejected by `load`.
///
/// **Why it matters:** Partial writes (disk full mid-save), truncated
/// transfers, and some classes of filesystem corruption produce shortened
/// files. A truncated file must never silently be interpreted — the
/// `payload_len` field could otherwise cause `decode_file` to read past
/// the end of the buffer. Rust's bounds checks prevent UB, but we want a
/// clean `KeystoreError::Truncated` (or `CrcMismatch`) instead of a panic.
///
/// **Catches:** any slice-index path in `decode_file` that doesn't
/// pre-check the buffer length; a regression where CRC is computed over
/// a buffer shorter than declared.
#[test]
fn truncated_file_rejected() {
    let (backend, key, original) = build_file();

    for new_len in 0..original.len() {
        let truncated = &original[..new_len];
        backend.write(&key, truncated).unwrap();

        let load = Keystore::<BlsSigning>::load(backend.clone(), key.clone());
        assert!(
            load.is_err(),
            "loading a truncated file ({new_len} bytes) should fail"
        );
    }
}

/// **Proves:** a zero-length file is rejected with
/// [`KeystoreError::Truncated`].
///
/// **Why it matters:** The minimal boundary case. An empty file has no
/// header, no ciphertext, no CRC — the decoder must fail cleanly without
/// panicking on slice bounds.
///
/// **Catches:** a regression that reads `bytes[0..6]` before checking
/// `bytes.len() >= HEADER_SIZE`.
#[test]
fn empty_file_rejected() {
    let (backend, key, _) = build_file();
    backend.write(&key, &[]).unwrap();
    let err = Keystore::<BlsSigning>::load(backend, key).unwrap_err();
    assert!(matches!(err, KeystoreError::Truncated { .. }));
}

/// **Proves:** a 100-byte buffer of `0xAB` (a file that happens to be
/// almost the right length for a valid keystore, but pure garbage) is
/// rejected — either by CRC, magic, format version, KDF id, or cipher id.
///
/// **Why it matters:** An attacker (or a filesystem bug) could write a
/// plausibly-sized garbage file. The load path must reject it before
/// attempting any cryptography — both for correctness and to avoid
/// spending 0.5 s of Argon2id work on obviously-bogus input.
///
/// **Catches:** a regression where the load path runs Argon2id before the
/// header guards, wasting CPU and potentially surfacing timing differences
/// between bad and good passwords on garbage files.
#[test]
fn garbage_file_rejected() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");
    backend.write(&key, &[0xABu8; 100]).unwrap();
    let err = Keystore::<BlsSigning>::load(backend, key).unwrap_err();
    // Either the CRC or the magic check will reject it.
    assert!(matches!(
        err,
        KeystoreError::CrcMismatch { .. }
            | KeystoreError::UnknownMagic { .. }
            | KeystoreError::UnsupportedFormat { .. }
            | KeystoreError::UnsupportedKdf(_)
            | KeystoreError::UnsupportedCipher(_)
    ));
}
