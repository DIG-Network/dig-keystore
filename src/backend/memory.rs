//! In-memory backend.
//!
//! Originally feature-gated behind `testing`. As of v0.1.2 it is compiled
//! unconditionally because production adapters in other crates (notably
//! `dig-l1-wallet`'s `encryption.rs`) use it as a scratch backend to reuse
//! the full keystore file format without touching the filesystem. The
//! `testing` module still re-exports it for discoverability in dependent
//! crates' dev-dependencies.
//!
//! Stores blobs in a `parking_lot::Mutex<HashMap>`. Legitimate production
//! uses: encrypt-to-bytes / decrypt-from-bytes helpers; unit tests; doc
//! examples.

use std::collections::HashMap;

use parking_lot::Mutex;

use crate::backend::{BackendKey, KeychainBackend};
use crate::error::{KeystoreError, Result};

/// A keychain backend that lives entirely in process memory.
///
/// Legitimate uses:
/// - **Scratch backend** for bytes-in / bytes-out adapters (e.g.
///   `dig-l1-wallet::keystore::encryption::encrypt_secret_key`).
/// - **Tests and doc examples** where touching the filesystem is overhead.
///
/// Do **not** use this as the storage medium for a long-lived keystore —
/// process exit drops all state.
#[derive(Default)]
pub struct MemoryBackend {
    inner: Mutex<HashMap<BackendKey, Vec<u8>>>,
}

impl MemoryBackend {
    /// Construct an empty backend.
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeychainBackend for MemoryBackend {
    fn read(&self, key: &BackendKey) -> Result<Vec<u8>> {
        self.inner.lock().get(key).cloned().ok_or_else(|| {
            KeystoreError::from(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("key not found: {key}"),
            ))
        })
    }

    fn write(&self, key: &BackendKey, data: &[u8]) -> Result<()> {
        self.inner.lock().insert(key.clone(), data.to_vec());
        Ok(())
    }

    fn delete(&self, key: &BackendKey) -> Result<()> {
        self.inner.lock().remove(key);
        Ok(())
    }

    fn list(&self, prefix: &str) -> Result<Vec<BackendKey>> {
        Ok(self
            .inner
            .lock()
            .keys()
            .filter(|k| k.as_str().starts_with(prefix))
            .cloned()
            .collect())
    }

    fn exists(&self, key: &BackendKey) -> Result<bool> {
        Ok(self.inner.lock().contains_key(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** `MemoryBackend` satisfies the [`KeychainBackend`]
    /// contract end-to-end — write then read recovers the blob; `exists`
    /// returns `true` for written keys and `false` for deleted ones.
    ///
    /// **Why it matters:** Dependent crates (`apps/validator`,
    /// `dig-l1-wallet`) build their tests on `MemoryBackend`. If the
    /// in-memory backend drifted from the `FileBackend` semantics (e.g.,
    /// `exists` stayed `true` after delete, or `read` returned stale bytes
    /// after overwrite), those tests would pass in CI and fail in
    /// production.
    ///
    /// **Catches:** a regression in `delete` that leaks the key in the
    /// internal `HashMap`, or an `exists` override that short-circuits
    /// without consulting the map.
    #[test]
    fn roundtrip() {
        let be = MemoryBackend::new();
        let k = BackendKey::new("x");
        be.write(&k, b"data").unwrap();
        assert_eq!(be.read(&k).unwrap(), b"data");
        assert!(be.exists(&k).unwrap());
        be.delete(&k).unwrap();
        assert!(!be.exists(&k).unwrap());
    }
}
