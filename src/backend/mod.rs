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
#[cfg(feature = "testing")]
mod memory;

#[cfg(feature = "file-backend")]
pub use file::FileBackend;
#[cfg(feature = "testing")]
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
