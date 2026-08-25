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

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use parking_lot::Mutex;

use crate::backend::{BackendKey, Exclusivity, KeychainBackend};
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

    /// Establish `key` only if vacant, decided under the map's own lock.
    ///
    /// The `Entry` API is what makes this exclusive rather than best-effort:
    /// the vacancy check and the insert happen in one critical section, so two
    /// threads cannot both observe absence and both write.
    fn write_new(&self, key: &BackendKey, data: &[u8]) -> Result<()> {
        match self.inner.lock().entry(key.clone()) {
            Entry::Occupied(_) => Err(KeystoreError::AlreadyExists(key.as_str().to_string())),
            Entry::Vacant(slot) => {
                slot.insert(data.to_vec());
                Ok(())
            }
        }
    }

    fn write_new_exclusivity(&self) -> Exclusivity {
        Exclusivity::Atomic
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

    /// **Proves:** `MemoryBackend::write_new` establishes a vacant key, refuses
    /// an occupied one with `AlreadyExists`, and leaves the occupant's bytes
    /// untouched — while `write` beside it still replaces.
    ///
    /// **Why it matters:** `MemoryBackend` is the scratch backend production
    /// adapters reach for, and it claims `Exclusivity::Atomic`. A `write_new`
    /// that replaced would break the claim silently.
    ///
    /// **Catches:** an `insert`-based implementation (which replaces), and an
    /// inverted occupied/vacant branch.
    #[test]
    fn write_new_establishes_once_and_then_refuses() {
        let be = MemoryBackend::new();
        let key = BackendKey::new("coupled");

        be.write_new(&key, b"established").unwrap();
        let err = be.write_new(&key, b"usurper").unwrap_err();

        assert!(
            matches!(err, KeystoreError::AlreadyExists(ref k) if k == "coupled"),
            "the collision must be adoptable: {err:?}"
        );
        assert_eq!(be.read(&key).unwrap(), b"established");

        be.write(&key, b"replaced").unwrap();
        assert_eq!(be.read(&key).unwrap(), b"replaced");
    }

    /// **Proves:** exactly one of many concurrent `write_new` calls wins.
    ///
    /// **Why it matters:** this is the mechanism behind the `Atomic` claim.
    /// The sequential test above is satisfied identically by a check-then-write,
    /// so on its own it pins a coincidence rather than the property a consumer
    /// with coupled records actually relies on.
    ///
    /// **Catches:** a `write_new` that takes the lock twice — once to check and
    /// once to insert — instead of deciding inside one critical section.
    #[test]
    fn only_one_concurrent_write_new_can_win() {
        use std::sync::{Arc, Barrier};

        const RACERS: usize = 16;
        let be = Arc::new(MemoryBackend::new());
        let key = BackendKey::new("contended");
        let gate = Arc::new(Barrier::new(RACERS));

        let winners = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..RACERS)
                .map(|i| {
                    let (be, gate, key) = (Arc::clone(&be), Arc::clone(&gate), key.clone());
                    scope.spawn(move || {
                        gate.wait();
                        be.write_new(&key, &[i as u8; 8]).is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|won| *won)
                .count()
        });

        assert_eq!(winners, 1, "exactly one racer may establish; {winners} did");
    }

    /// **Proves:** `MemoryBackend` claims atomic exclusivity.
    ///
    /// **Why it matters:** the claim is what a consumer reads before relying on
    /// `write_new`; the test above is what makes the claim true. Both are
    /// asserted so the claim cannot outlive the mechanism.
    #[test]
    fn memory_backend_claims_exclusive_creation() {
        assert_eq!(
            MemoryBackend::new().write_new_exclusivity(),
            Exclusivity::Atomic
        );
    }

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

    /// **Proves:** reading a key that was never written returns a
    /// [`KeystoreError::Backend`] whose inner `io::Error` is
    /// [`ErrorKind::NotFound`].
    ///
    /// **Why it matters:** The exact error *kind* is load-bearing — the default
    /// [`KeychainBackend::exists`] and `Keystore::create`'s overwrite guard both
    /// branch on `NotFound` specifically. If `MemoryBackend::read` reported a
    /// missing key as some other error kind, callers that wrap it (e.g.
    /// `dig-l1-wallet`'s scratch-backend decrypt path) would treat "absent" as a
    /// hard failure.
    ///
    /// **Catches:** a regression that returns a generic/`Other` error, or that
    /// returns `Ok(empty)` for a missing key.
    #[test]
    fn read_missing_key_is_not_found() {
        let be = MemoryBackend::new();
        let err = be.read(&BackendKey::new("absent")).unwrap_err();
        match err {
            KeystoreError::Backend(io) => {
                assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Backend(NotFound), got {other:?}"),
        }
    }

    /// **Proves:** `write` to an existing key overwrites in place — a later
    /// `read` sees the new bytes, never a concatenation or the stale value.
    ///
    /// **Why it matters:** Password rotation and KDF rotation re-`write` the
    /// same backend key with fresh ciphertext. If `MemoryBackend` appended or
    /// kept the old value, an `unlock` after rotation would decrypt stale
    /// ciphertext with the new key and fail.
    ///
    /// **Catches:** a `write` that uses `entry().or_insert` (ignoring updates)
    /// or otherwise fails to replace the prior blob.
    #[test]
    fn write_overwrites_in_place() {
        let be = MemoryBackend::new();
        let k = BackendKey::new("k");
        be.write(&k, b"first").unwrap();
        be.write(&k, b"second").unwrap();
        assert_eq!(be.read(&k).unwrap(), b"second");
    }

    /// **Proves:** `list` returns exactly the keys whose name starts with the
    /// given prefix, and an empty prefix lists everything.
    ///
    /// **Why it matters:** Callers enumerate keystores by prefix (e.g. listing
    /// all `validator/` keys). A prefix filter that matched substrings anywhere,
    /// or ignored the prefix entirely, would surface unrelated keys to the
    /// operator.
    ///
    /// **Catches:** using `contains` instead of `starts_with`; returning all
    /// keys regardless of prefix.
    #[test]
    fn list_filters_by_prefix() {
        let be = MemoryBackend::new();
        be.write(&BackendKey::new("validator/a"), b"1").unwrap();
        be.write(&BackendKey::new("validator/b"), b"2").unwrap();
        be.write(&BackendKey::new("wallet/c"), b"3").unwrap();

        let mut matched: Vec<String> = be
            .list("validator/")
            .unwrap()
            .into_iter()
            .map(|k| k.as_str().to_string())
            .collect();
        matched.sort();
        assert_eq!(matched, vec!["validator/a", "validator/b"]);

        // An empty prefix matches every key.
        assert_eq!(be.list("").unwrap().len(), 3);
        // A non-matching prefix yields nothing.
        assert!(be.list("none/").unwrap().is_empty());
    }

    /// **Proves:** `MemoryBackend::default()` produces an empty backend
    /// equivalent to `new()`.
    ///
    /// **Why it matters:** Production adapters construct the scratch backend via
    /// `MemoryBackend::default()` (it derives `Default`). An accidental
    /// non-empty or mis-initialised `Default` would leak state between
    /// independent encrypt/decrypt operations.
    ///
    /// **Catches:** a hand-written `Default` that pre-populates the map.
    #[test]
    fn default_is_empty() {
        let be = MemoryBackend::default();
        assert!(be.list("").unwrap().is_empty());
        assert!(!be.exists(&BackendKey::new("anything")).unwrap());
    }
}
