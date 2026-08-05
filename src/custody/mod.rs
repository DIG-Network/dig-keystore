//! User-custody API — typed keystores, key schemes, and unlocked signer handles.
//!
//! Everything in this module deals with a *user's* long-lived key material: the
//! typed [`Keystore<K>`](keystore::Keystore) container, the
//! [`KeyScheme`](scheme::KeyScheme) implementations that pin each scheme's
//! secret length and public-key derivation, and the
//! [`SignerHandle<K>`](signer::SignerHandle) returned by unlocking one.
//!
//! # Why this is a separate module
//!
//! The crate's *core* — [`crate::opaque`] sealing, [`crate::backend`],
//! [`crate::format`], [`crate::cipher`], [`crate::kdf`] — is machine-key
//! plumbing: seal these bytes under this password, store them, read them back.
//! It has no notion of whose key it is. The custody API is the opposite: it
//! models a user's identity key and hands out a signer for it.
//!
//! The module boundary is a hard one: nothing under `custody/` is referenced by
//! the core modules. That is what keeps a future extraction into its own crate
//! a file move rather than a redesign.

pub(crate) mod keystore;
pub mod scheme;
pub(crate) mod signer;

#[cfg(test)]
mod tests {
    use crate::backend::{BackendKey, KeychainBackend, MemoryBackend};
    use crate::custody::scheme::BlsSigning;
    use crate::opaque::open;
    use crate::{KdfParams, KeystoreError, Password};
    use std::sync::Arc;

    /// **Proves:** a blob written by the typed `Keystore<BlsSigning>` path is
    /// rejected by [`crate::opaque::open`] with `SchemeMismatch`, even though
    /// the outer format (header, CRC, AES-GCM framing) is byte-compatible and
    /// the password is correct — so decryption itself would succeed.
    ///
    /// **Why it matters:** the two containers share a format but not a
    /// meaning. Without the magic/scheme-id assertion, a caller could open a
    /// validator's typed signing key through the untyped opaque path (or vice
    /// versa), defeating the type-confusion protection the rest of the crate
    /// relies on.
    ///
    /// **Catches:** a decode path that validates the format generically but
    /// forgets to assert `MAGIC`/`SCHEME_ID` before returning the plaintext.
    ///
    /// Lives here rather than in `opaque.rs` because it is the one test that
    /// spans both sides of the custody boundary: `opaque` (core) must not
    /// reference `custody` types, so the test belongs on the custody side.
    #[test]
    fn typed_keystore_blob_is_rejected_as_opaque() {
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let password = Password::from("kat-password");
        crate::Keystore::<BlsSigning>::create(
            backend.clone(),
            BackendKey::new("k"),
            password.clone(),
            None,
            KdfParams::FAST_TEST,
        )
        .unwrap();
        let raw = backend.read(&BackendKey::new("k")).unwrap();

        let err = open(&password, &raw).unwrap_err();
        assert!(matches!(err, KeystoreError::SchemeMismatch { .. }));
    }
}
