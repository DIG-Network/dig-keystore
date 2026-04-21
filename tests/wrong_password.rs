//! Wrong-password / missing-password / exotic-password tests.
//!
//! These tests stress the authentication layer: every invalid password must
//! fail with the clean [`KeystoreError::DecryptFailed`] variant — never a
//! panic, never garbage plaintext, never a side-channel leak that
//! distinguishes "close" passwords from "far" ones.
//!
//! Together these tests pin the crate's user-facing error-handling contract:
//! the only way to get a `SignerHandle` is with the exact password used at
//! `create` time.

use std::sync::Arc;

use dig_keystore::{
    backend::{BackendKey, KeychainBackend, MemoryBackend},
    scheme::BlsSigning,
    KdfParams, Keystore, KeystoreError, Password,
};

/// Shared fixture: create a keystore with password `"correct"` and return
/// the backend + key so tests can try loading/unlocking with other passwords.
fn setup() -> (Arc<dyn KeychainBackend>, BackendKey) {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("validator");
    Keystore::<BlsSigning>::create(
        backend.clone(),
        key.clone(),
        Password::from("correct"),
        None,
        KdfParams::FAST_TEST,
    )
    .unwrap();
    (backend, key)
}

/// **Proves:** unlocking with a clearly-wrong password produces
/// [`KeystoreError::DecryptFailed`] and nothing else — no panic, no leak,
/// no partial plaintext.
///
/// **Why it matters:** The baseline "password is wrong" path is what
/// operators hit every time they mistype. It must fail deterministically
/// and cleanly so CLI tools can display "wrong password" without further
/// logic.
///
/// **Catches:** a regression where `unlock` panics on the bad-tag case
/// (would crash the fullnode / validator CLI) or surfaces the `aes-gcm`
/// error verbatim (leaking internal cipher details to operators).
#[test]
fn wrong_password_fails_cleanly() {
    let (backend, key) = setup();
    let ks = Keystore::<BlsSigning>::load(backend, key).unwrap();
    let err = ks.unlock(Password::from("wrong")).unwrap_err();
    assert!(matches!(err, KeystoreError::DecryptFailed));
}

/// **Proves:** unlocking with an empty password produces
/// [`KeystoreError::DecryptFailed`] when the file was created with a
/// non-empty password.
///
/// **Why it matters:** Guards against a subtle regression where the unlock
/// path silently "helps" by mapping an empty password to some default.
/// The KDF must see the empty bytes verbatim and derive a key that cannot
/// decrypt the stored ciphertext.
///
/// **Catches:** a regression where `Password::new(b"")` is treated
/// specially (e.g., replaced with a fixed test password, or short-circuited
/// before KDF).
#[test]
fn empty_password_fails() {
    let (backend, key) = setup();
    let ks = Keystore::<BlsSigning>::load(backend, key).unwrap();
    let err = ks.unlock(Password::from("")).unwrap_err();
    assert!(matches!(err, KeystoreError::DecryptFailed));
}

/// **Proves:** small password perturbations — one character shorter, one
/// character longer, case variations — all fail with
/// [`KeystoreError::DecryptFailed`].
///
/// **Why it matters:** Passwords have no "close enough" behaviour. The
/// Argon2id output for any perturbed input is uniformly random — the AES
/// key will be completely different, and the GCM tag will reject. Pinning
/// this ensures no accidental case-folding, whitespace trimming, or
/// Levenshtein-style tolerance sneaks in.
///
/// **Catches:** a regression where `Password` accidentally normalises via
/// `to_lowercase` / `trim` / NFC; or where Argon2id is replaced with a
/// weaker hash that happens to be collision-prone under small changes.
#[test]
fn password_length_variations() {
    let (backend, key) = setup();
    let ks = Keystore::<BlsSigning>::load(backend, key).unwrap();

    for wrong in &["correc", "correctX", "CORRECT", "correcti", "Correct"] {
        let err = ks.unlock(Password::from(*wrong)).unwrap_err();
        assert!(
            matches!(err, KeystoreError::DecryptFailed),
            "expected DecryptFailed for {wrong:?}"
        );
    }
}

/// **Proves:** a password containing non-ASCII UTF-8 (Cyrillic, emoji, CJK)
/// round-trips without corruption.
///
/// **Why it matters:** Operators in different locales use non-ASCII
/// passwords. Argon2id hashes raw bytes, so this should "just work" — but
/// only if we never touch the bytes between `Password::new` and
/// `hash_password_into`. This test pins the transparency property.
///
/// **Catches:** any layer that assumes ASCII and, e.g., calls
/// `str::to_ascii_lowercase()` or fails on non-ASCII bytes.
#[test]
fn unicode_password_works() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");
    let password = Password::from("пароль🔐中文");

    Keystore::<BlsSigning>::create(
        backend.clone(),
        key.clone(),
        password.clone(),
        None,
        KdfParams::FAST_TEST,
    )
    .unwrap();

    let ks = Keystore::<BlsSigning>::load(backend, key).unwrap();
    ks.unlock(password).expect("unicode password round-trips");
}

/// **Proves:** a 4 KiB password round-trips without truncation or
/// allocation errors.
///
/// **Why it matters:** No spec-enforced password length limit. Password
/// managers sometimes generate very long "passwords" (really random byte
/// strings). 4 KiB is deliberate overkill — well beyond realistic inputs —
/// to surface any buffer-size assumption.
///
/// **Catches:** a hidden length limit (e.g., Argon2id binding that
/// silently truncates); a `Vec<u8>` with a static capacity; an ASCII
/// assumption that fails on high entropy inputs.
#[test]
fn very_long_password_works() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");
    let pw_str = "a".repeat(4096);
    let password = Password::from(pw_str.as_bytes());

    Keystore::<BlsSigning>::create(
        backend.clone(),
        key.clone(),
        password.clone(),
        None,
        KdfParams::FAST_TEST,
    )
    .unwrap();

    let ks = Keystore::<BlsSigning>::load(backend, key).unwrap();
    ks.unlock(password).expect("long password round-trips");
}

/// **Proves:** `change_password` with the wrong `old` password fails with
/// [`KeystoreError::DecryptFailed`] **and** leaves the keystore intact —
/// the original password still works afterwards.
///
/// **Why it matters:** A failed password change must not partially corrupt
/// the keystore. Either the full re-encryption succeeds or the file is
/// unchanged. If a regression wrote a half-updated file (e.g., new header
/// but old ciphertext), the original password would stop working too — a
/// catastrophic failure.
///
/// **Catches:** a regression where `change_password` writes to the backend
/// before verifying the old password succeeds; where the wrong-old error
/// is silently swallowed and the new password is accepted.
#[test]
fn change_password_with_wrong_old_fails() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let key = BackendKey::new("k");

    let mut ks = Keystore::<BlsSigning>::create(
        backend,
        key,
        Password::from("old"),
        None,
        KdfParams::FAST_TEST,
    )
    .unwrap();

    let err = ks
        .change_password(Password::from("WRONG"), Password::from("new"))
        .unwrap_err();
    assert!(matches!(err, KeystoreError::DecryptFailed));

    // Secret stays intact under the original password.
    ks.unlock(Password::from("old"))
        .expect("original password still works");
}
