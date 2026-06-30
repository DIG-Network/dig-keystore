//! Storage backend abstraction.
//!
//! A `KeychainBackend` is any byte-blob KV store. The shipped `FileBackend`
//! persists to the local filesystem with atomic (tmp + rename) writes. Planned
//! future backends: `OsKeyringBackend` (macOS Keychain / Windows Credential
//! Store / Secret Service), and hardware-signer backends (`LedgerBackend`,
//! `YubiHsmBackend`) that proxy `sign` to an external device.

use crate::error::Result;

#[cfg(feature = "file-backend")]
mod file;
mod memory;

#[cfg(feature = "file-backend")]
pub use file::FileBackend;
/// In-memory backend — always available. Originally feature-gated, now
/// unconditional because production adapters (e.g., `dig-l1-wallet`'s
/// encrypt/decrypt-bytes helpers) wrap it in scratch backends to reuse the
/// full keystore format without touching the filesystem.
pub use memory::MemoryBackend;

/// An opaque key identifying a single encrypted blob within a backend.
///
/// For `FileBackend`, the key maps to `<root>/<key>.dks`; for an OS-keyring
/// backend it maps to a service / account pair; for a hardware signer it maps
/// to a slot identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BackendKey(pub String);

impl BackendKey {
    /// Construct from any string-like value.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Borrow as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<T: Into<String>> From<T> for BackendKey {
    fn from(v: T) -> Self {
        Self(v.into())
    }
}

impl std::fmt::Display for BackendKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Storage backend trait. Implementations must be `Send + Sync + 'static` so
/// they can be held behind `Arc<dyn KeychainBackend>`.
pub trait KeychainBackend: Send + Sync + 'static {
    /// Read the full contents of the blob at `key`.
    ///
    /// Returns a backend I/O error if the blob does not exist.
    fn read(&self, key: &BackendKey) -> Result<Vec<u8>>;

    /// Write `data` to `key`. Implementations should be atomic — a reader
    /// seeing the key after this call must see either the old bytes or the
    /// new bytes in full, never a torn mix.
    fn write(&self, key: &BackendKey, data: &[u8]) -> Result<()>;

    /// Remove the blob at `key`. Implementations should best-effort overwrite
    /// the storage before removing so residual disk sectors do not retain the
    /// ciphertext.
    fn delete(&self, key: &BackendKey) -> Result<()>;

    /// List keys that start with `prefix`. Order is unspecified.
    fn list(&self, prefix: &str) -> Result<Vec<BackendKey>>;

    /// Whether a blob exists at `key`. Default impl delegates to `read`;
    /// backends with cheaper existence checks should override.
    fn exists(&self, key: &BackendKey) -> Result<bool> {
        match self.read(key) {
            Ok(_) => Ok(true),
            Err(crate::error::KeystoreError::Backend(e))
                if e.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KeystoreError;
    use std::io;

    /// A minimal backend that does **not** override `exists`, so it exercises
    /// the [`KeychainBackend::exists`] *default* implementation. The shipped
    /// backends (`FileBackend`, `MemoryBackend`) both override `exists` with a
    /// cheaper check, leaving the default's three branches (present →
    /// `Ok(true)`, `NotFound` → `Ok(false)`, other error → propagate) otherwise
    /// unexercised. This stub is the only way to test that contract.
    #[derive(Default)]
    struct ProbeBackend {
        /// When set, every `read` returns this io error kind instead of data.
        fail_kind: Option<io::ErrorKind>,
        present: bool,
    }

    impl KeychainBackend for ProbeBackend {
        fn read(&self, _key: &BackendKey) -> Result<Vec<u8>> {
            if let Some(kind) = self.fail_kind {
                return Err(KeystoreError::from(io::Error::new(kind, "probe")));
            }
            if self.present {
                Ok(vec![1, 2, 3])
            } else {
                Err(KeystoreError::from(io::Error::new(
                    io::ErrorKind::NotFound,
                    "absent",
                )))
            }
        }
        fn write(&self, _key: &BackendKey, _data: &[u8]) -> Result<()> {
            Ok(())
        }
        fn delete(&self, _key: &BackendKey) -> Result<()> {
            Ok(())
        }
        fn list(&self, _prefix: &str) -> Result<Vec<BackendKey>> {
            Ok(vec![])
        }
        // Deliberately NO `exists` override.
    }

    /// **Proves:** `BackendKey` round-trips through every constructor + accessor
    /// — `new`, the blanket `From<T: Into<String>>`, `as_str`, and the
    /// `Display` impl all agree on the same underlying string.
    ///
    /// **Why it matters:** `BackendKey` is the address every backend keys off
    /// (`FileBackend` maps it to `<root>/<key>.dks`). A `Display`/`as_str`
    /// disagreement, or a `From` that mangled the input, would route reads and
    /// writes to different paths — a silent data-loss bug.
    ///
    /// **Catches:** an `as_str` that returns a transformed copy; a `Display`
    /// impl that adds quotes/prefixes; a `From` that drops or alters the value.
    #[test]
    fn backend_key_constructors_and_accessors_agree() {
        let from_new = BackendKey::new("validator");
        let from_into: BackendKey = "validator".into();
        let from_string: BackendKey = BackendKey::from(String::from("validator"));

        assert_eq!(from_new.as_str(), "validator");
        assert_eq!(from_new, from_into);
        assert_eq!(from_new, from_string);
        assert_eq!(format!("{from_new}"), "validator");
        // Eq / Hash derive sanity: distinct values are not equal.
        assert_ne!(from_new, BackendKey::new("other"));
    }

    /// **Proves:** the default [`KeychainBackend::exists`] returns `Ok(true)`
    /// when the blob reads back successfully.
    ///
    /// **Why it matters:** This is the happy-path branch of the default impl
    /// that backends inherit unless they override it. `Keystore::create` calls
    /// `exists` to refuse overwrites; if the default returned `false` for a
    /// present key, `create` would clobber existing keys.
    ///
    /// **Catches:** an inverted truth value in the `Ok(_) => Ok(true)` arm.
    #[test]
    fn default_exists_true_when_present() {
        let be = ProbeBackend {
            present: true,
            ..Default::default()
        };
        assert!(be.exists(&BackendKey::new("k")).unwrap());
    }

    /// **Proves:** the default `exists` maps a `NotFound` read error to
    /// `Ok(false)` rather than propagating it.
    ///
    /// **Why it matters:** A missing key is the normal "not yet created" state,
    /// not an error. `Keystore::create` relies on `exists(..) == Ok(false)` to
    /// proceed with a first-time write. If `NotFound` propagated as `Err`,
    /// creating any new keystore would fail outright.
    ///
    /// **Catches:** removing the `NotFound` guard so absence surfaces as an
    /// error.
    #[test]
    fn default_exists_false_when_not_found() {
        let be = ProbeBackend::default(); // present=false → NotFound
        assert!(!be.exists(&BackendKey::new("k")).unwrap());
    }

    /// **Proves:** the default `exists` propagates non-`NotFound` I/O errors
    /// (e.g. a permission error) instead of swallowing them as `false`.
    ///
    /// **Why it matters:** Treating a `PermissionDenied` as "does not exist"
    /// would let `create` attempt to overwrite a file it merely cannot read —
    /// masking a real environment problem behind a confusing later failure.
    /// The default must distinguish "absent" from "inaccessible".
    ///
    /// **Catches:** a too-broad error arm that maps every error to `Ok(false)`.
    #[test]
    fn default_exists_propagates_other_errors() {
        let be = ProbeBackend {
            fail_kind: Some(io::ErrorKind::PermissionDenied),
            ..Default::default()
        };
        let err = be.exists(&BackendKey::new("k")).unwrap_err();
        assert!(matches!(err, KeystoreError::Backend(_)));
    }
}
