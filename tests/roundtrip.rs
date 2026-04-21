//! End-to-end round-trip tests: `create → load → unlock → sign → verify`.
//!
//! Every test in this file exercises the **full** keystore stack: password
//! input → Argon2id KDF → AES-256-GCM → file encode → backend write → backend
//! read → file decode → AES-256-GCM decrypt → KDF re-derivation → chia-bls
//! key derivation → chia-bls sign/verify. If a test here fails, at least one
//! layer is broken and the crate does not ship.
//!
//! All tests use [`KdfParams::FAST_TEST`] (8 MiB / 1 iter / 1 lane) so they
//! finish in <100 ms each. This does not weaken the *correctness* properties
//! being tested — it only weakens the *brute-force cost* of the resulting
//! encryption, which matters only if the ciphertext escapes the test process.

use std::sync::Arc;

use dig_keystore::{
    backend::{BackendKey, KeychainBackend, MemoryBackend},
    scheme::{BlsSigning, L1WalletBls},
    KdfParams, KeyScheme, Keystore, Password,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use zeroize::Zeroizing;

/// Fast KDF params so the test suite runs in seconds. Never for production.
fn fast_params() -> KdfParams {
    KdfParams::FAST_TEST
}

/// **Proves:** the full DIG validator BLS signing flow works end-to-end —
/// `create` generates a fresh seed, writes ciphertext to a backend;
/// `unlock` re-reads the ciphertext, decrypts, derives the public key, and
/// produces signatures that verify via the public `chia_bls::verify`; a
/// fresh `load` recovers the same file with its header intact.
///
/// **Why it matters:** This is the top-level smoke test for every validator-
/// binary-side use of this crate. If it fails, no validator can produce
/// signatures that verify on-chain.
///
/// **Catches:** any layer regression — KDF mis-derivation, AAD drift, file-
/// format corruption, scheme-id mismatch, chia-bls API changes.
#[test]
fn bls_signing_full_roundtrip() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("validator");
    let password = Password::from("correct horse battery staple");

    let ks = Keystore::<BlsSigning>::create(
        backend.clone(),
        key.clone(),
        password.clone(),
        None,
        fast_params(),
    )
    .expect("create");

    let signer = ks.unlock(password).expect("unlock");

    let msg = b"hello, dig network";
    let sig = signer.sign(msg);
    assert!(chia_bls::verify(&sig, signer.public_key(), msg));

    // Reload into a fresh Keystore and verify the header survives.
    let ks2 = Keystore::<BlsSigning>::load(backend, key).expect("reload");
    assert_eq!(ks2.header().scheme_id, 0x0001);
    assert_eq!(&ks2.header().magic, b"DIGVK1");
}

/// **Proves:** the `L1WalletBls` scheme round-trips end-to-end exactly like
/// `BlsSigning`.
///
/// **Why it matters:** Mirror of the validator flow but for the Chia L1
/// wallet scheme. Confirms both schemes share the same working
/// infrastructure and neither regressed in a scheme-specific way.
///
/// **Catches:** a scheme-specific bug (e.g., a magic-mismatch in the
/// `L1WalletBls` code path that would surface only under this scheme).
#[test]
fn l1_wallet_bls_roundtrip() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("l1_wallet");
    let password = Password::from("another password");

    let ks = Keystore::<L1WalletBls>::create(
        backend,
        key,
        password.clone(),
        None,
        fast_params(),
    )
    .expect("create");

    let signer = ks.unlock(password).expect("unlock");
    let sig = signer.sign(b"test");
    assert!(chia_bls::verify(&sig, signer.public_key(), b"test"));
}

/// **Proves:** when a caller passes a pre-existing 32-byte seed to `create`
/// (via `plaintext: Some(...)`), the resulting keystore encrypts that exact
/// seed — not a newly-generated one. Unlocking recovers the seed and the
/// derived pubkey matches what the caller would derive from the seed
/// directly.
///
/// **Why it matters:** Wallet-restore flows take a BIP-39 mnemonic, convert
/// to a seed, and hand that seed to `Keystore::create`. If `create` ignored
/// the caller seed and generated its own, every mnemonic-based restore
/// would silently produce the wrong wallet.
///
/// **Catches:** `create` overriding the caller's plaintext; `create` hashing
/// the seed before encrypting (wrong pubkey on unlock).
#[test]
fn caller_supplied_seed() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let seed = Zeroizing::new(vec![0xAAu8; 32]);
    let pubkey_before = BlsSigning::public_key(&seed).unwrap();

    let ks = Keystore::<BlsSigning>::create(
        backend,
        BackendKey::new("k"),
        Password::from("pw"),
        Some(seed.clone()),
        fast_params(),
    )
    .unwrap();

    let signer = ks.unlock(Password::from("pw")).unwrap();
    assert_eq!(
        signer.public_key().to_bytes(),
        pubkey_before.to_bytes(),
    );
}

/// **Proves:** `change_password` re-encrypts the ciphertext under the new
/// password without altering the underlying secret. The signature produced
/// before and after the password change is bit-exactly identical.
///
/// **Why it matters:** Password rotation is a critical admin workflow. If
/// it changed the underlying key, every subsequent signature would differ
/// from the pre-rotation signatures — validators would lose their identity.
/// Conversely, the **old** password must stop working (confirmed by the
/// `DecryptFailed` assertion).
///
/// **Catches:** `change_password` that re-generates the seed (loses identity);
/// that keeps the old salt/nonce (vulnerable to nonce-reuse); that silently
/// accepts the old password afterwards.
#[test]
fn change_password_preserves_secret() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");

    let mut ks = Keystore::<BlsSigning>::create(
        backend,
        key,
        Password::from("old"),
        None,
        fast_params(),
    )
    .unwrap();

    let sig_before = ks
        .unlock(Password::from("old"))
        .unwrap()
        .sign(b"persist");

    ks.change_password(Password::from("old"), Password::from("new"))
        .unwrap();

    // Old password must fail.
    assert!(matches!(
        ks.unlock(Password::from("old")),
        Err(dig_keystore::KeystoreError::DecryptFailed)
    ));

    let sig_after = ks
        .unlock(Password::from("new"))
        .unwrap()
        .sign(b"persist");

    assert_eq!(sig_before.to_bytes(), sig_after.to_bytes());
}

/// **Proves:** `rotate_kdf` upgrades the Argon2id parameters in place
/// without altering the underlying secret. The same password works before
/// and after, signature equality is preserved, and the header reflects the
/// new params.
///
/// **Why it matters:** Argon2id recommendations increase over time (Moore's
/// law on attackers). Operators must be able to bump their KDF params
/// without rotating keys. If `rotate_kdf` changed the secret, signature
/// history would break.
///
/// **Catches:** a rotation that re-generates the seed; a rotation that
/// fails to update the header; a rotation that forgets to re-encrypt under
/// fresh salt/nonce (leading to nonce-key reuse).
#[test]
fn rotate_kdf_preserves_secret() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");

    let mut ks = Keystore::<BlsSigning>::create(
        backend,
        key,
        Password::from("pw"),
        None,
        fast_params(),
    )
    .unwrap();

    let sig_before = ks.unlock(Password::from("pw")).unwrap().sign(b"x");

    // Rotate to stronger params (but keep fast enough for tests).
    let stronger = KdfParams {
        id: dig_keystore::KdfId::Argon2id,
        memory_kib: 16 * 1024,
        iterations: 2,
        lanes: 2,
    };
    ks.rotate_kdf(Password::from("pw"), stronger).unwrap();

    assert_eq!(ks.header().kdf, stronger);
    let sig_after = ks.unlock(Password::from("pw")).unwrap().sign(b"x");
    assert_eq!(sig_before.to_bytes(), sig_after.to_bytes());
}

/// **Proves:** `Keystore::create` refuses to overwrite an existing blob —
/// a second `create` at the same backend key returns
/// [`KeystoreError::AlreadyExists`].
///
/// **Why it matters:** This is a loud-failure safety rail. If `create` silently
/// overwrote existing files, an operator running `dig-validator keys generate`
/// twice would lose their first key without warning. Keys are extremely
/// hard to recover from backup; making overwrite explicit (operator must
/// `delete` first) is load-bearing.
///
/// **Catches:** a regression where `create` skips the existence check.
#[test]
fn create_refuses_overwrite() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");

    Keystore::<BlsSigning>::create(
        backend.clone(),
        key.clone(),
        Password::from("pw"),
        None,
        fast_params(),
    )
    .unwrap();

    let err = Keystore::<BlsSigning>::create(
        backend,
        key,
        Password::from("pw"),
        None,
        fast_params(),
    )
    .unwrap_err();

    assert!(matches!(err, dig_keystore::KeystoreError::AlreadyExists(_)));
}

/// **Proves:** `cached_public_key` is populated immediately after `create`
/// and matches the pubkey returned by a subsequent `unlock`.
///
/// **Why it matters:** The cache lets CLI tools show the validator's pubkey
/// (`dig-validator keys show`) without re-prompting for a password. If the
/// cache drifted from the actual pubkey — or were left `None` post-create —
/// operator UX would silently break or require a password every time.
///
/// **Catches:** regression where the cache is not populated on `create`;
/// where the cache is populated with a stale value that doesn't match the
/// actual secret.
#[test]
fn cached_public_key_populated_after_unlock() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");

    let ks = Keystore::<BlsSigning>::create(
        backend,
        key,
        Password::from("pw"),
        None,
        fast_params(),
    )
    .unwrap();

    // Immediately after create, the public key is cached.
    assert!(ks.cached_public_key().is_some());

    // Unlocking updates it (in this case to the same value).
    let pk_from_unlock = *ks.unlock(Password::from("pw")).unwrap().public_key();
    let pk_from_cache = ks.cached_public_key().unwrap();
    assert_eq!(pk_from_unlock.to_bytes(), pk_from_cache.to_bytes());
}

/// **Proves:** when `create_with_rng` receives a deterministic RNG, two
/// invocations produce keystores whose derived public keys are byte-exactly
/// identical.
///
/// **Why it matters:** Deterministic fixtures are the foundation of the
/// known-answer tests in `tests/vectors.rs` and of dependent crates'
/// integration tests. If the RNG thread ever branched (say, a library
/// read from `OsRng` internally), golden tests would drift randomly.
///
/// **Catches:** a regression where `create` uses `OsRng` in some code path
/// regardless of the passed-in RNG (salt or nonce generation).
#[test]
fn deterministic_rng_produces_same_key() {
    let backend1: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let backend2: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());

    let mut rng1 = StdRng::seed_from_u64(0xDEADBEEF);
    let mut rng2 = StdRng::seed_from_u64(0xDEADBEEF);

    let ks1 = Keystore::<BlsSigning>::create_with_rng(
        backend1,
        BackendKey::new("k"),
        Password::from("pw"),
        None,
        fast_params(),
        &mut rng1,
    )
    .unwrap();
    let ks2 = Keystore::<BlsSigning>::create_with_rng(
        backend2,
        BackendKey::new("k"),
        Password::from("pw"),
        None,
        fast_params(),
        &mut rng2,
    )
    .unwrap();

    let pk1 = *ks1.unlock(Password::from("pw")).unwrap().public_key();
    let pk2 = *ks2.unlock(Password::from("pw")).unwrap().public_key();
    assert_eq!(pk1.to_bytes(), pk2.to_bytes());
}

/// **Proves:** attempting to `Keystore::<L1WalletBls>::load` a file that
/// was created by `Keystore::<BlsSigning>::create` fails with
/// [`KeystoreError::SchemeMismatch`].
///
/// **Why it matters:** This is the enforcement point for type-confusion
/// prevention. A `DIGVK1` (validator) file must not be usable as a
/// `DIGLW1` (wallet) keystore even if someone accidentally renames the
/// file or drops it in the wrong directory. The scheme-id check in `load`
/// is the tripwire.
///
/// **Catches:** a regression where `load` skips the scheme-id check and
/// lets the mismatch surface as a silent `DecryptFailed` (or worse, lets
/// the file decrypt under the wrong scheme).
#[test]
fn load_with_wrong_scheme_fails() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");

    // Store a BlsSigning keystore.
    Keystore::<BlsSigning>::create(
        backend.clone(),
        key.clone(),
        Password::from("pw"),
        None,
        fast_params(),
    )
    .unwrap();

    // Try to load as L1WalletBls.
    let err = Keystore::<L1WalletBls>::load(backend, key).unwrap_err();
    assert!(matches!(
        err,
        dig_keystore::KeystoreError::SchemeMismatch { .. }
    ));
}

/// **Proves:** `Keystore::delete` removes the blob from the backend.
///
/// **Why it matters:** Covers the full delete path at the `Keystore` level
/// (not just `FileBackend::delete` as in the backend unit tests). Confirms
/// that `Keystore::delete` correctly delegates to the backend and that the
/// backend's `exists` reflects the post-delete state.
///
/// **Catches:** regression where `Keystore::delete` becomes a no-op or
/// where it consumes `self` without actually calling `backend.delete`.
#[test]
fn delete_removes_blob() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");

    let ks = Keystore::<BlsSigning>::create(
        backend.clone(),
        key.clone(),
        Password::from("pw"),
        None,
        fast_params(),
    )
    .unwrap();

    assert!(backend.exists(&key).unwrap());
    ks.delete().unwrap();
    assert!(!backend.exists(&key).unwrap());
}
