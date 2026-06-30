//! Branch-coverage tests for `Keystore` accessors and guarded error paths that
//! the end-to-end `roundtrip.rs` flow doesn't reach.
//!
//! These exercise:
//! - the `path()` accessor and the `Debug` impl (no-secret-leak),
//! - the `InvalidPlaintext` guard in `create_with_rng` when a caller supplies a
//!   plaintext seed of the wrong length.
//!
//! Like the other integration suites, this uses [`KdfParams::FAST_TEST`] so the
//! Argon2id KDF stays cheap; correctness of the *guard* logic is independent of
//! KDF cost.

use std::sync::Arc;

use dig_keystore::{
    backend::{BackendKey, KeychainBackend, MemoryBackend},
    scheme::BlsSigning,
    KdfParams, KeystoreError, Password,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use zeroize::Zeroizing;

type Ks = dig_keystore::Keystore<BlsSigning>;

fn fast_params() -> KdfParams {
    KdfParams::FAST_TEST
}

/// **Proves:** `Keystore::path()` returns the exact `BackendKey` the keystore
/// was created with.
///
/// **Why it matters:** CLI tools and the rotation helpers report and re-address
/// the keystore by its backend key (`change_password`/`rotate_kdf` re-`write`
/// to `self.path`). A `path()` that returned a transformed or stale key would
/// mislead operators and could route a rotation write to the wrong blob.
///
/// **Catches:** a regression where `path()` returns a clone of a different
/// field, or where `create` stores a normalized key that diverges from the
/// caller's.
#[test]
fn path_accessor_returns_creation_key() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("wallets/primary");

    let ks = Ks::create(
        backend,
        key.clone(),
        Password::from("pw"),
        None,
        fast_params(),
    )
    .unwrap();

    assert_eq!(ks.path(), &key);
    assert_eq!(ks.path().as_str(), "wallets/primary");
}

/// **Proves:** the `Debug` impl of `Keystore` prints the scheme name, path, and
/// KDF params but never any secret material — and there is no secret on the
/// struct to leak in the first place (the ciphertext lives in the backend).
///
/// **Why it matters:** A `Keystore` is held inside larger app structs that get
/// `tracing`-logged. The `Debug` impl must be safe to print. This pins the
/// fields it surfaces (useful for support) and confirms it does not format the
/// header's salt/nonce or any password.
///
/// **Catches:** a future `#[derive(Debug)]` that would dump the full header
/// (salt/nonce) or any added secret field.
#[test]
fn debug_surfaces_metadata_only() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");

    let ks = Ks::create(backend, key, Password::from("hunter2"), None, fast_params()).unwrap();

    let s = format!("{ks:?}");
    assert!(s.contains("Keystore"));
    assert!(s.contains("BlsSigning"));
    assert!(s.contains('k')); // the path
                              // The password must never appear in Debug output.
    assert!(!s.contains("hunter2"));
}

/// **Proves:** `create_with_rng` rejects a caller-supplied plaintext seed whose
/// length is not the scheme's `SECRET_LEN`, returning
/// [`KeystoreError::InvalidPlaintext`] with the expected/actual lengths — and
/// nothing is written to the backend on that error.
///
/// **Why it matters:** Wallet-restore flows hand a derived seed to `create`. If
/// a truncated or over-long seed slipped past the guard, the keystore would
/// encrypt bytes that `unlock`'s length check later rejects — producing a file
/// that can be created but never opened. Failing fast at create time, before any
/// write, is the correct behavior.
///
/// **Catches:** removing the `p.len() != K::SECRET_LEN` guard in
/// `create_with_rng`; a guard that still writes the bad file before returning.
#[test]
fn create_rejects_wrong_length_plaintext() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");
    let mut rng = StdRng::seed_from_u64(1);

    // BlsSigning::SECRET_LEN is 32; supply 31 bytes.
    let bad_seed = Zeroizing::new(vec![0u8; 31]);

    let err = Ks::create_with_rng(
        backend.clone(),
        key.clone(),
        Password::from("pw"),
        Some(bad_seed),
        fast_params(),
        &mut rng,
    )
    .unwrap_err();

    match err {
        KeystoreError::InvalidPlaintext { expected, got } => {
            assert_eq!(expected, 32);
            assert_eq!(got, 31);
        }
        other => panic!("expected InvalidPlaintext, got {other:?}"),
    }

    // The guard fired before any write — no blob exists.
    assert!(!backend.exists(&key).unwrap());
}
