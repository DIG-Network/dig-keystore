//! OS-native credential-store backend.
//!
//! [`OsKeychainBackend`] persists each encrypted blob in the host operating
//! system's credential store — **Windows Credential Manager** or **macOS
//! Keychain** — through the cross-platform [`keyring`] crate. It absorbs the
//! proven `OsCredentialStore` shape that shipped in dig-app so the ecosystem
//! keeps exactly one keystore implementation.
//!
//! # Status — no current consumers; NOT for a machine service
//!
//! No crate in the ecosystem uses this backend today. The OS credential store
//! is released by the **login session**, so a machine/system service — a
//! dig-node running as SYSTEM or under a non-interactive account — has no
//! session to release it and **MUST NOT** use this backend; the
//! passphrase-sealed [`FileBackend`](crate::backend::FileBackend) is the
//! backend for that case. It is retained for the user-application case (a
//! desktop app whose secrets live and die with a logged-in user) and to
//! migrate an existing dig-app account off the retired machine-password model.
//!
//! # What this backend is, and is not
//!
//! It is a **storage location, not an access-control primitive**. The
//! keystore's own Argon2id + AES-256-GCM sealing (`SPEC.md` §3–§5) remains the
//! primary access control for everything filed here; the credential store is
//! defence-in-depth only.
//!
//! The access boundary is **not the same on both platforms**:
//!
//! - **macOS** — the Keychain applies a genuine per-application ACL.
//! - **Windows** — a generic Credential Manager entry is protected by DPAPI
//!   under the logged-in user's key and is readable by **any process running
//!   as that user**. That is a **per-user** boundary. Never assume a
//!   per-application one here.
//!
//! Because of that, [`write`](KeychainBackend::write) rejects any payload that
//! does not begin with a recognised DIG container magic (`DIGVK1`, `DIGLW1`,
//! `DIGOP1`, or the `DIGHW1` hardware envelope).
//! The guard binds callers of this crate; it cannot stop other software
//! writing plaintext to the same OS store.
//! [`read`](KeychainBackend::read) is unrestricted: any blob a previous
//! version persisted must still open (`SPEC.md` §5.1).
//!
//! # Platform gating (HARD)
//!
//! The [`keyring`] dependency is compiled **only** on `target_os = "windows"`
//! or `target_os = "macos"`. On every other target — Linux and `wasm32`
//! included — `keyring` is never pulled (no dbus/libsecret system-library tax,
//! no wasm break) and [`OsKeychainBackend::open`] returns `None`. The crate
//! performs **no** fallback of any kind: selecting another backend is entirely
//! the caller's decision.
//!
//! **Linux is deliberately excluded as a custody primary.** The kernel
//! keyutils session keyring is readable by any same-UID process in the session
//! and is non-persistent across reboot/logout, so it is unsafe as a custody
//! primary and would lose the identity on logout. On Linux the
//! passphrase-sealed file is the correct primary instead.
//!
//! # Enumeration
//!
//! OS credential stores expose no native key enumeration. `OsKeychainBackend`
//! keeps a best-effort **index entry** (a reserved account) holding the set of
//! live keys; [`list`](KeychainBackend::list) filters it. `read`/`write`/
//! `delete`/`exists` consult the credential store directly and are the source
//! of truth — the index only powers `list`, so index/store drift can never
//! corrupt a read or a write, only stale a listing.

use crate::backend::{BackendKey, KeychainBackend};
use crate::error::{KeystoreError, Result};

use parking_lot::Mutex;
use zeroize::Zeroizing;

/// Reserved account under which the enumeration index is stored. Chosen to be
/// distinct from any real [`BackendKey`] a caller would use (which are simple
/// identifiers like `validator_bls`).
const INDEX_ACCOUNT: &str = "__dig_keystore_index__";

/// Length of every DIG container magic (`SPEC.md` §3: a 6-byte prefix).
const MAGIC_LEN: usize = 6;

/// Low-level `(account) -> secret` store abstraction over one credential-store
/// namespace (service). Extracted so the enumeration/round-trip logic is
/// testable without touching a real OS store: the real implementation is
/// [`KeyringStore`]; tests inject an in-memory double.
trait RawStore: Send + Sync + 'static {
    /// Fetch the secret stored under `account`, or `None` if no entry exists.
    /// A backend that exists but cannot be read is an `Err`, distinct from
    /// "absent".
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>>;

    /// Store `secret` under `account`, overwriting any existing entry.
    fn set(&self, account: &str, secret: &[u8]) -> Result<()>;

    /// Delete the entry under `account`. Deleting an absent entry is a no-op.
    fn remove(&self, account: &str) -> Result<()>;
}

/// A [`KeychainBackend`] backed by the host OS credential store.
///
/// Construct with [`OsKeychainBackend::open`], which returns `None` when no
/// usable OS store exists on this host. The crate performs no fallback; the
/// caller selects an alternative backend, as the example below does.
///
/// A storage location, not an access-control primitive: the seal is the
/// primary access control and `write` accepts sealed DIG containers only.
/// See the module docs for the per-platform access boundary and for why a
/// machine/system service must not use this backend.
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use dig_keystore::backend::{KeychainBackend, OsKeychainBackend, FileBackend, BackendKey};
///
/// // Prefer the OS credential store; fall back to a file backend elsewhere.
/// let backend: Arc<dyn KeychainBackend> = match OsKeychainBackend::open("dig-app") {
///     Some(os) => Arc::new(os),
///     None => Arc::new(FileBackend::new("/var/lib/dig/keys")),
/// };
/// backend.write(&BackendKey::new("identity"), b"...").unwrap();
/// ```
pub struct OsKeychainBackend {
    /// The underlying credential store (real keyring, or a test double).
    store: Box<dyn RawStore>,
    /// Serializes read-modify-write of the enumeration index within this
    /// process. Cross-process index races are tolerated (best-effort `list`).
    index_lock: Mutex<()>,
}

impl OsKeychainBackend {
    /// Construct from an arbitrary [`RawStore`] — the seam every path shares.
    ///
    /// `open` uses it on Windows/macOS with a real keyring store; tests use it
    /// with an in-memory double. Not compiled where it would be unused (a
    /// non-test Linux/wasm build, where [`open`](Self::open) always returns
    /// `None`).
    #[cfg(any(test, target_os = "windows", target_os = "macos"))]
    fn with_store(store: Box<dyn RawStore>) -> Self {
        Self {
            store,
            index_lock: Mutex::new(()),
        }
    }

    /// Load the enumeration index for `list` (the set of live keys). A
    /// missing or unreadable index yields an empty set — `list` is
    /// best-effort per the module docs. Insert/remove use
    /// [`load_index_for_update`](Self::load_index_for_update) instead, which
    /// keeps a hard read error distinct from "no index yet" so a
    /// read-modify-write never clobbers a previously-persisted index.
    fn load_index(&self) -> Vec<String> {
        self.load_index_for_update().unwrap_or_default()
    }

    /// Load the enumeration index for a read-modify-write, distinguishing a
    /// genuinely empty index (`Ok(None)` — fresh keystore, nothing indexed
    /// yet) from a hard/transient store error (`Err`).
    ///
    /// This distinction matters: `index_insert`/`index_remove` must NOT
    /// treat a transient read failure as "empty" and then persist that empty
    /// index, which would silently drop every other already-indexed key
    /// name from future `list()` calls.
    fn load_index_for_update(&self) -> Result<Vec<String>> {
        match self.store.get(INDEX_ACCOUNT) {
            Ok(Some(bytes)) => {
                let raw = Zeroizing::new(bytes);
                Ok(String::from_utf8_lossy(&raw)
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(str::to_owned)
                    .collect())
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Persist the enumeration index. Best-effort — a failure to write the
    /// index never fails the caller's `write`/`delete`, it only risks a stale
    /// `list` (the credential store itself already holds the authoritative
    /// entry).
    fn store_index(&self, keys: &[String]) {
        let joined = Zeroizing::new(keys.join("\n").into_bytes());
        let _ = self.store.set(INDEX_ACCOUNT, &joined);
    }

    /// Add `key` to the index if absent.
    ///
    /// Skips the update entirely on a hard/transient index-read error rather
    /// than persisting an empty index in its place — see
    /// [`load_index_for_update`](Self::load_index_for_update).
    fn index_insert(&self, key: &str) {
        let _guard = self.index_lock.lock();
        let Ok(mut keys) = self.load_index_for_update() else {
            return;
        };
        if !keys.iter().any(|k| k == key) {
            keys.push(key.to_owned());
            self.store_index(&keys);
        }
    }

    /// Remove `key` from the index if present.
    ///
    /// Skips the update entirely on a hard/transient index-read error, for
    /// the same reason as [`index_insert`](Self::index_insert).
    fn index_remove(&self, key: &str) {
        let _guard = self.index_lock.lock();
        let Ok(mut keys) = self.load_index_for_update() else {
            return;
        };
        let before = keys.len();
        keys.retain(|k| k != key);
        if keys.len() != before {
            self.store_index(&keys);
        }
    }
}

/// Reject a key name that cannot safely be stored: one equal to the
/// reserved [`INDEX_ACCOUNT`] sentinel (which would shadow the enumeration
/// index itself) or containing a newline (which would poison the
/// newline-joined index format persisted by [`store_index`]).
fn validate_key_name(name: &str) -> Result<()> {
    if name == INDEX_ACCOUNT || name.contains('\n') {
        return Err(KeystoreError::from(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid key name (reserved or contains newline): {name:?}"),
        )));
    }
    Ok(())
}

/// Whether `bytes` begin with a DIG container magic this crate recognises —
/// a sealed §3 keystore/opaque blob, or a §17 hardware envelope wrapping one.
///
/// The answer is DELEGATED to the two predicates that already own the
/// question ([`crate::format::is_known_magic`] and
/// [`crate::hardware::envelope::is_envelope`]) rather than re-listing the
/// magic literals here. That delegation is the point: a new container magic
/// registered in `format.rs` becomes writable to the OS credential store on
/// the same commit, instead of silently failing until someone remembers this
/// second list exists.
///
/// A payload too short to carry a magic is not a container.
fn is_dig_container(bytes: &[u8]) -> bool {
    let Some(prefix) = bytes.get(..MAGIC_LEN) else {
        return false;
    };
    match <[u8; MAGIC_LEN]>::try_from(prefix) {
        Ok(magic) => {
            crate::format::is_known_magic(&magic) || crate::hardware::envelope::is_envelope(bytes)
        }
        Err(_) => false,
    }
}

/// Reject a payload that is not a sealed DIG container (`SPEC.md` §10.5).
///
/// The OS credential store is a storage location, not an access-control
/// primitive: on Windows a generic Credential Manager entry is DPAPI-protected
/// under the logged-in user's key and readable by ANY process running as that
/// user. Refusing plaintext keeps the crate's Argon2id + AES-256-GCM seal the
/// primary access control for everything filed here. The guard binds callers
/// of this crate only — it cannot stop other software writing to the same OS
/// store.
fn validate_sealed_payload(data: &[u8]) -> Result<()> {
    if !is_dig_container(data) {
        return Err(KeystoreError::from(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to store an unsealed payload in the OS credential store: \
             expected a DIG container (see SPEC.md §10.5)",
        )));
    }
    Ok(())
}

/// Redacted `Debug` — never prints service, account, or secret material.
impl std::fmt::Debug for OsKeychainBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsKeychainBackend")
            .field("store", &"<redacted>")
            .finish()
    }
}

impl KeychainBackend for OsKeychainBackend {
    fn read(&self, key: &BackendKey) -> Result<Vec<u8>> {
        match self.store.get(key.as_str())? {
            Some(bytes) => Ok(bytes),
            None => Err(KeystoreError::from(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("key not found: {key}"),
            ))),
        }
    }

    fn write(&self, key: &BackendKey, data: &[u8]) -> Result<()> {
        validate_key_name(key.as_str())?;
        validate_sealed_payload(data)?;
        self.store.set(key.as_str(), data)?;
        // Authoritative entry is written; index is a best-effort convenience.
        self.index_insert(key.as_str());
        Ok(())
    }

    fn delete(&self, key: &BackendKey) -> Result<()> {
        self.store.remove(key.as_str())?;
        self.index_remove(key.as_str());
        Ok(())
    }

    fn list(&self, prefix: &str) -> Result<Vec<BackendKey>> {
        Ok(self
            .load_index()
            .into_iter()
            .filter(|k| k.starts_with(prefix))
            .map(BackendKey::new)
            .collect())
    }

    fn exists(&self, key: &BackendKey) -> Result<bool> {
        // Consult the store directly — the index is not authoritative.
        Ok(self.store.get(key.as_str())?.is_some())
    }
}

// ---------------------------------------------------------------------------
// Real keyring-backed store — Windows Credential Manager / macOS Keychain only.
// ---------------------------------------------------------------------------

/// The real [`RawStore`], backed by the OS credential store via [`keyring`].
///
/// One instance owns a single `service` namespace; each account is a
/// [`BackendKey`] string. Secrets are stored through `keyring`'s binary API so
/// no textual re-encoding is applied to the ciphertext.
#[cfg(any(target_os = "windows", target_os = "macos"))]
struct KeyringStore {
    /// The credential-store service (namespace) all entries are filed under.
    service: String,
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
impl KeyringStore {
    fn entry(&self, account: &str) -> keyring::Result<keyring::Entry> {
        keyring::Entry::new(&self.service, account)
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn keyring_err(e: keyring::Error) -> KeystoreError {
    // Never embed SECRET material in the message. `{e}` is only the error
    // class in the common case, but the pathological `keyring::Error::Ambiguous`
    // variant may include a non-secret account/service identifier pulled from
    // the platform backend (e.g. which of several matching credential-store
    // entries it found) — that identifier is not sensitive on its own, unlike
    // the secret bytes this function never has access to.
    KeystoreError::from(std::io::Error::other(format!("OS credential store: {e}")))
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
impl RawStore for KeyringStore {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>> {
        match self.entry(account).and_then(|e| e.get_secret()) {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(keyring_err(e)),
        }
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<()> {
        self.entry(account)
            .and_then(|e| e.set_secret(secret))
            .map_err(keyring_err)
    }

    fn remove(&self, account: &str) -> Result<()> {
        match self.entry(account).and_then(|e| e.delete_credential()) {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(keyring_err(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// `open` — platform-specific construction with fail-to-fallback semantics.
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "windows", target_os = "macos"))]
impl OsKeychainBackend {
    /// Open the OS credential store for `service`, probing the backend once.
    ///
    /// Returns `None` when no usable OS store exists on this host (a locked
    /// keychain, an unreachable Credential Manager). The crate performs no
    /// fallback — a `None` is the caller's cue to select another backend. The
    /// probe looks up a throwaway account: a `NoEntry` result proves the store is reachable; only
    /// a hard backend error returns `None`. This makes "is the OS store
    /// usable?" a single decision taken once, not a failure surfacing
    /// mid-`unlock`.
    pub fn open(service: impl Into<String>) -> Option<Self> {
        let store = KeyringStore {
            service: service.into(),
        };
        let probe = format!("__dig_keystore_probe__{}", std::process::id());
        match store.get(&probe) {
            Ok(_) => Some(Self::with_store(Box::new(store))),
            Err(_) => None,
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
impl OsKeychainBackend {
    /// No OS credential store is used on this target (Linux / wasm) — always
    /// returns `None`. The crate performs no fallback; choosing another
    /// backend is the caller's responsibility. See the module docs for why
    /// Linux is excluded as a custody primary.
    pub fn open(_service: impl Into<String>) -> Option<Self> {
        None
    }
}

/// In-memory doubles shared by this module's unit tests and the hardware
/// composition tests (`crate::hardware::tests`), which need to stand a real
/// [`OsKeychainBackend`] up as the inner store of a
/// [`HardwareBoundBackend`](crate::hardware::HardwareBoundBackend) without a
/// live OS credential store.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::HashMap;

    /// An in-memory [`RawStore`] double — stands in for the OS credential store
    /// so the backend's round-trip, index, and error logic run identically on
    /// every platform (Linux CI included).
    #[derive(Default)]
    pub(crate) struct FakeStore {
        pub(crate) map: Mutex<HashMap<String, Vec<u8>>>,
        /// When set, every `get` fails — models an unreachable backend.
        pub(crate) fail: bool,
    }

    impl RawStore for FakeStore {
        fn get(&self, account: &str) -> Result<Option<Vec<u8>>> {
            if self.fail {
                return Err(KeystoreError::from(std::io::Error::other("unreachable")));
            }
            Ok(self.map.lock().get(account).cloned())
        }
        fn set(&self, account: &str, secret: &[u8]) -> Result<()> {
            self.map.lock().insert(account.to_owned(), secret.to_vec());
            Ok(())
        }
        fn remove(&self, account: &str) -> Result<()> {
            self.map.lock().remove(account);
            Ok(())
        }
    }

    /// An [`OsKeychainBackend`] over a fresh empty [`FakeStore`].
    pub(crate) fn fake_backend() -> OsKeychainBackend {
        OsKeychainBackend::with_store(Box::<FakeStore>::default())
    }

    /// An [`OsKeychainBackend`] over a [`FakeStore`] pre-seeded with `entries`,
    /// bypassing `write` entirely — the only way to model bytes an EARLIER
    /// crate version (before the §10.5 write guard) already persisted.
    pub(crate) fn fake_backend_seeded(entries: &[(&str, &[u8])]) -> OsKeychainBackend {
        let store = FakeStore::default();
        for (account, secret) in entries {
            store
                .map
                .lock()
                .insert((*account).to_owned(), secret.to_vec());
        }
        OsKeychainBackend::with_store(Box::new(store))
    }

    /// A payload carrying the `DIGOP1` container magic — the shape a caller is
    /// permitted to store (`SPEC.md` §10.5). Only the prefix is load-bearing
    /// for the write guard; the tail stands in for sealed ciphertext.
    pub(crate) fn sealed(seed: u8) -> Vec<u8> {
        let mut blob = b"DIGOP1".to_vec();
        blob.extend_from_slice(&[seed; 16]);
        blob
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{fake_backend as backend, fake_backend_seeded, sealed, FakeStore};
    use super::*;
    use std::collections::HashMap;

    /// **Proves:** a blob written through `OsKeychainBackend` reads back
    /// byte-identical.
    ///
    /// **Why it matters:** This is the custody round-trip — a stored sealed
    /// identity blob must return exactly the bytes stored, or every later
    /// `unlock` decrypts garbage. Exercises the store `set`/`get` path plus the
    /// binary (non-re-encoded) secret contract.
    ///
    /// **Catches:** any encoding/truncation regression in the store round-trip.
    #[test]
    fn write_then_read_roundtrip() {
        let be = backend();
        let key = BackendKey::new("identity");
        let blob = sealed(0xDE);
        be.write(&key, &blob).unwrap();
        assert_eq!(be.read(&key).unwrap(), blob);
    }

    /// **Proves:** reading an absent key returns `Backend(NotFound)`, the exact
    /// error shape the default `exists` and `Keystore::create` overwrite guard
    /// branch on.
    ///
    /// **Why it matters:** If a missing key surfaced as a different error kind,
    /// `Keystore::create` would refuse to create a first-time keystore.
    ///
    /// **Catches:** a `read` that maps "absent" to a generic error or `Ok`.
    #[test]
    fn read_absent_is_not_found() {
        let be = backend();
        let err = be.read(&BackendKey::new("missing")).unwrap_err();
        match err {
            KeystoreError::Backend(io) => {
                assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Backend(NotFound), got {other:?}"),
        }
    }

    /// **Proves:** `write` to an existing key overwrites in place.
    ///
    /// **Why it matters:** Password/KDF rotation re-`write`s the same key with
    /// fresh ciphertext; a stale or appended value would fail the next unlock.
    ///
    /// **Catches:** a `set` that refuses to replace an existing entry.
    #[test]
    fn write_overwrites_in_place() {
        let be = backend();
        let key = BackendKey::new("k");
        be.write(&key, &sealed(1)).unwrap();
        be.write(&key, &sealed(2)).unwrap();
        assert_eq!(be.read(&key).unwrap(), sealed(2));
    }

    /// **Proves:** `delete` removes the entry and is idempotent (a second
    /// delete on the now-absent key still succeeds).
    ///
    /// **Why it matters:** Profile removal and rotation call `delete` without
    /// pre-checking existence; a non-idempotent delete would error on a
    /// concurrent double-remove.
    ///
    /// **Catches:** a `delete` that errors on a missing entry, or an `exists`
    /// that reports a deleted key as present.
    #[test]
    fn delete_removes_and_is_idempotent() {
        let be = backend();
        let key = BackendKey::new("gone");
        be.write(&key, &sealed(3)).unwrap();
        assert!(be.exists(&key).unwrap());
        be.delete(&key).unwrap();
        assert!(!be.exists(&key).unwrap());
        be.delete(&key).unwrap(); // idempotent
    }

    /// **Proves:** `list(prefix)` returns exactly the live keys whose name
    /// starts with `prefix`, and the reserved index account never leaks into a
    /// listing.
    ///
    /// **Why it matters:** `list` is what enumerates keystores for a caller;
    /// substring matching, or exposing the internal index account, would
    /// surface wrong or bogus keys.
    ///
    /// **Catches:** `contains` instead of `starts_with`; the `INDEX_ACCOUNT`
    /// bookkeeping entry appearing as a real key.
    #[test]
    fn list_filters_by_prefix_and_hides_index() {
        let be = backend();
        be.write(&BackendKey::new("validator/a"), &sealed(1))
            .unwrap();
        be.write(&BackendKey::new("validator/b"), &sealed(2))
            .unwrap();
        be.write(&BackendKey::new("wallet/c"), &sealed(3)).unwrap();

        let mut matched: Vec<String> = be
            .list("validator/")
            .unwrap()
            .into_iter()
            .map(|k| k.as_str().to_owned())
            .collect();
        matched.sort();
        assert_eq!(matched, vec!["validator/a", "validator/b"]);

        // Empty prefix lists every real key — and only real keys.
        let all: Vec<String> = be.list("").unwrap().into_iter().map(|k| k.0).collect();
        assert_eq!(all.len(), 3);
        assert!(!all.iter().any(|k| k == INDEX_ACCOUNT));
    }

    /// **Proves:** after deleting a key, it disappears from `list` — the index
    /// tracks removals, not just insertions.
    ///
    /// **Why it matters:** A `list` that kept showing deleted keys would report
    /// keystores that no longer exist.
    ///
    /// **Catches:** an `index_remove` that fails to persist the shrunk index.
    #[test]
    fn delete_drops_key_from_list() {
        let be = backend();
        be.write(&BackendKey::new("a"), &sealed(1)).unwrap();
        be.write(&BackendKey::new("b"), &sealed(2)).unwrap();
        be.delete(&BackendKey::new("a")).unwrap();
        let remaining: Vec<String> = be.list("").unwrap().into_iter().map(|k| k.0).collect();
        assert_eq!(remaining, vec!["b".to_owned()]);
    }

    /// **Proves:** `read`/`exists` surface a hard backend error rather than
    /// masking it as "absent" when the store itself is unreachable.
    ///
    /// **Why it matters:** Treating an unreachable store as "no such key" would
    /// let `Keystore::create` clobber a keystore it merely could not read. The
    /// `open` probe is what avoids ever constructing a backend on an
    /// unreachable store, but the read path must still fail closed.
    ///
    /// **Catches:** an over-broad error arm mapping every store error to
    /// `NotFound`/`false`.
    #[test]
    fn store_error_is_propagated_not_swallowed() {
        let be = OsKeychainBackend::with_store(Box::new(FakeStore {
            fail: true,
            ..Default::default()
        }));
        assert!(be.read(&BackendKey::new("x")).is_err());
        assert!(be.exists(&BackendKey::new("x")).is_err());
    }

    /// **Proves:** `write` rejects a key name equal to the reserved
    /// [`INDEX_ACCOUNT`] sentinel or containing a newline, while a normal
    /// name still succeeds.
    ///
    /// **Why it matters:** A newline in a key name would poison the
    /// newline-joined index format (`store_index`/`load_index` split on
    /// `\n`), corrupting `list()` for every other key. A name equal to
    /// `INDEX_ACCOUNT` would let a caller's `write` silently overwrite the
    /// enumeration index itself.
    ///
    /// **Catches:** a `write` that stores the raw name without validating it
    /// first.
    #[test]
    fn write_rejects_reserved_name_and_newline() {
        let be = backend();

        let err = be
            .write(&BackendKey::new(INDEX_ACCOUNT), &sealed(9))
            .unwrap_err();
        assert!(matches!(err, KeystoreError::Backend(_)));

        let err = be
            .write(&BackendKey::new("evil\nname"), &sealed(9))
            .unwrap_err();
        assert!(matches!(err, KeystoreError::Backend(_)));

        // A normal name is unaffected.
        be.write(&BackendKey::new("validator_bls"), &sealed(4))
            .unwrap();
        assert_eq!(
            be.read(&BackendKey::new("validator_bls")).unwrap(),
            sealed(4)
        );
    }

    /// **Proves:** a transient/hard error reading the index during a `write`
    /// does NOT clobber the index — previously-indexed key names survive and
    /// still appear in a later `list()` once the store's index read recovers.
    ///
    /// **Why it matters:** `load_index` used to collapse "index read failed"
    /// and "index is empty" into the same `Vec::new()`, so `index_insert`
    /// would persist a fresh index containing only the just-written key,
    /// silently dropping every other already-indexed name from future
    /// `list()` calls.
    ///
    /// **Catches:** a `load_index_for_update`/`index_insert` that treats a
    /// hard read error as "start empty" instead of "skip the update".
    #[test]
    fn transient_index_read_error_does_not_drop_existing_names() {
        // A `RawStore` double whose index read can be toggled to fail
        // independently of every other account — models a transient
        // keyring hiccup on just the enumeration entry, not "no index yet".
        // The fail flag is shared via `Arc` so the test can flip it after
        // constructing the backend (which takes ownership of the store).
        struct FlakyIndexStore {
            map: Mutex<HashMap<String, Vec<u8>>>,
            fail_index_read: std::sync::Arc<Mutex<bool>>,
        }

        impl RawStore for FlakyIndexStore {
            fn get(&self, account: &str) -> Result<Option<Vec<u8>>> {
                if account == INDEX_ACCOUNT && *self.fail_index_read.lock() {
                    return Err(KeystoreError::from(std::io::Error::other(
                        "transient keyring read failure",
                    )));
                }
                Ok(self.map.lock().get(account).cloned())
            }
            fn set(&self, account: &str, secret: &[u8]) -> Result<()> {
                self.map.lock().insert(account.to_owned(), secret.to_vec());
                Ok(())
            }
            fn remove(&self, account: &str) -> Result<()> {
                self.map.lock().remove(account);
                Ok(())
            }
        }

        let fail_index_read = std::sync::Arc::new(Mutex::new(true));
        let store = FlakyIndexStore {
            map: Mutex::new(HashMap::from([
                ("a".to_owned(), b"1".to_vec()),
                ("b".to_owned(), b"2".to_vec()),
                (INDEX_ACCOUNT.to_owned(), b"a\nb".to_vec()),
            ])),
            fail_index_read: fail_index_read.clone(),
        };
        let be = OsKeychainBackend::with_store(Box::new(store));

        // `write` still succeeds — the authoritative store entry is written
        // even though the index read underneath it is currently failing.
        be.write(&BackendKey::new("c"), &sealed(3)).unwrap();
        assert!(be.exists(&BackendKey::new("c")).unwrap());

        // `list` is best-effort and reports empty while the index is
        // unreadable.
        assert!(be.list("").unwrap().is_empty());

        // Recover the index read and confirm "a" and "b" are STILL indexed
        // — the earlier write must not have persisted an empty/partial
        // index while the read was failing. ("c", written during the
        // outage, is legitimately absent — its insert was skipped, not
        // silently lost data; a fresh `write` after recovery would index it.)
        *fail_index_read.lock() = false;
        let mut names: Vec<String> = be.list("").unwrap().into_iter().map(|k| k.0).collect();
        names.sort();
        assert_eq!(names, vec!["a".to_owned(), "b".to_owned()]);
    }

    /// **Proves:** the `Debug` impl redacts — no secret/service material.
    ///
    /// **Why it matters:** A backend accidentally logged (via `{:?}`) must not
    /// spill key material or the credential-store namespace.
    ///
    /// **Catches:** a derived `Debug` that prints the inner store/service.
    #[test]
    fn debug_is_redacted() {
        let rendered = format!("{:?}", backend());
        assert!(rendered.contains("<redacted>"));
    }

    // -----------------------------------------------------------------------
    // §10.5 write guard — the OS credential store takes sealed containers only.
    // -----------------------------------------------------------------------

    /// Assert `err` is the `Backend(InvalidInput)` shape §10.5 mandates —
    /// the same shape `validate_key_name` already returns, so no new error
    /// variant enters the §11 catalog.
    fn assert_invalid_input(err: KeystoreError) {
        match err {
            KeystoreError::Backend(io) => {
                assert_eq!(io.kind(), std::io::ErrorKind::InvalidInput);
            }
            other => panic!("expected Backend(InvalidInput), got {other:?}"),
        }
    }

    /// **Proves:** `write` refuses a plaintext payload carrying no DIG
    /// container magic.
    ///
    /// **Why it matters:** The OS credential store is defence-in-depth, not the
    /// access-control primitive (§10.5) — on Windows it is a per-USER boundary,
    /// readable by any process running as that user. A caller stashing an
    /// unlock password or a raw mnemonic here would be relying on a boundary
    /// that does not exist.
    ///
    /// **Catches:** a guard that is absent, or a no-op that returns `Ok` for
    /// everything.
    #[test]
    fn write_rejects_unsealed_payload() {
        let be = backend();
        let err = be
            .write(&BackendKey::new("identity"), b"hunter2")
            .unwrap_err();
        assert_invalid_input(err);
        // And nothing was persisted behind the rejection.
        assert!(!be.exists(&BackendKey::new("identity")).unwrap());
    }

    /// **Proves:** every container magic the crate can produce is accepted —
    /// the two shipped scheme magics, the opaque container, and the `DIGHW1`
    /// hardware envelope.
    ///
    /// **Why it matters:** An over-narrow allowlist is the guard's most likely
    /// wrong shape, and the omission with teeth is `DIGHW1`: a
    /// `HardwareBoundBackend` over this backend writes envelope bytes on every
    /// single write, so dropping it breaks a shipped composition outright.
    ///
    /// **Catches:** an allowlist listing only the scheme magics, or only what
    /// `format.rs` knows.
    #[test]
    fn write_accepts_every_known_container_magic() {
        for magic in [
            &b"DIGVK1"[..],
            &b"DIGLW1"[..],
            &b"DIGOP1"[..],
            &b"DIGHW1"[..],
        ] {
            let be = backend();
            let mut blob = magic.to_vec();
            blob.extend_from_slice(&[0xAB; 16]);
            let key = BackendKey::new("identity");
            be.write(&key, &blob)
                .unwrap_or_else(|e| panic!("magic {magic:?} must be accepted, got {e:?}"));
            assert_eq!(be.read(&key).unwrap(), blob);
        }
    }

    /// **Proves:** a payload SHORTER than a magic is rejected, not a panic.
    ///
    /// **Why it matters:** The guard reads a prefix. An unchecked `bytes[..6]`
    /// slice would panic — inside a custody write, on caller-supplied data.
    ///
    /// **Catches:** an unbounded slice or a `try_into().unwrap()`.
    #[test]
    fn write_rejects_payload_shorter_than_magic() {
        let be = backend();
        for short in [&b""[..], b"D", b"DIG", b"DIGHW"] {
            let err = be.write(&BackendKey::new("identity"), short).unwrap_err();
            assert_invalid_input(err);
        }
    }

    /// **Proves:** the guard's accept-set is exactly `format::is_known_magic`
    /// plus the hardware envelope — checked by comparing the guard's answer to
    /// those predicates' answer over a wide prefix corpus, rather than against
    /// a second hand-written list.
    ///
    /// **Why it matters:** The failure this pins is DRIFT: a new container
    /// magic added to `format.rs` alone would be silently unwritable to the OS
    /// store. Re-listing the literals here would reproduce exactly the
    /// duplication that lets that happen, so the oracle is the predicates
    /// themselves.
    ///
    /// **Catches:** a guard that re-lists magic literals instead of delegating.
    #[test]
    fn guard_agrees_with_format_is_known_magic() {
        let corpus: [&[u8]; 10] = [
            b"DIGVK1", b"DIGLW1", b"DIGOP1", b"DIGHW1", b"DIGWX1", b"DIGXX9", b"NOTDIG", b"DIG",
            b"", b"digvk1",
        ];
        for prefix in corpus {
            let mut blob = prefix.to_vec();
            blob.extend_from_slice(&[0x11; 16]);

            let expected = <[u8; 6]>::try_from(&blob[..6]).is_ok_and(|m| {
                crate::format::is_known_magic(&m) || crate::hardware::envelope::is_envelope(&blob)
            });
            assert_eq!(
                is_dig_container(&blob),
                expected,
                "guard disagrees with the format predicates on prefix {prefix:?}"
            );
        }
    }

    /// **Proves:** `read` returns a pre-existing UNSEALED blob byte-identically
    /// — the write guard narrows writes only.
    ///
    /// **Why it matters:** §5.1 is a HARD rule: every blob any prior version
    /// wrote must still read. A guard mistakenly applied to `read` would strand
    /// bytes an earlier dig-keystore already persisted into a user's credential
    /// store. The fixture is seeded through the raw store, not `write`, because
    /// `write` can no longer produce such bytes.
    ///
    /// **Catches:** the guard placed on the read path, or applied symmetrically
    /// in a shared helper.
    #[test]
    fn read_returns_preexisting_unsealed_blob_byte_identically() {
        let legacy = b"hunter2-written-by-v0.6.1".to_vec();
        let be = fake_backend_seeded(&[("identity", &legacy)]);
        assert_eq!(be.read(&BackendKey::new("identity")).unwrap(), legacy);
        assert!(be.exists(&BackendKey::new("identity")).unwrap());
    }

    /// **Proves:** the enumeration index still round-trips with the guard in
    /// place — two sealed writes are both listed.
    ///
    /// **Why it matters:** `store_index` writes newline-joined key NAMES (never
    /// a container) through the private `RawStore`. A guard placed in
    /// `RawStore::set` instead of `KeychainBackend::write` would reject the
    /// index write and silently break `list`; a name-based exemption added to
    /// "fix" that would be a bypass where none is needed.
    ///
    /// **Catches:** a guard at the wrong layer, and any `INDEX_ACCOUNT`
    /// exemption inside `write`.
    #[test]
    fn enumeration_index_survives_the_guard() {
        let be = backend();
        be.write(&BackendKey::new("validator_bls"), &sealed(1))
            .unwrap();
        be.write(&BackendKey::new("wallet"), &sealed(2)).unwrap();

        let mut names: Vec<String> = be.list("").unwrap().into_iter().map(|k| k.0).collect();
        names.sort();
        assert_eq!(names, vec!["validator_bls".to_owned(), "wallet".to_owned()]);
    }
}

// ---------------------------------------------------------------------------
// Real OS-store integration test — self-skips where no backend is available.
// ---------------------------------------------------------------------------

#[cfg(all(test, any(target_os = "windows", target_os = "macos")))]
mod os_integration {
    use super::*;

    /// Exercise the REAL OS credential store end-to-end where a backend exists
    /// (Windows Credential Manager · macOS Keychain). Self-skips on a host with
    /// no usable backend so it is never flaky; the [`FakeStore`](super::tests)
    /// unit tests cover the logic on every platform. The service is namespaced
    /// per-process and every entry is cleaned up so it cannot pollute a
    /// developer's real store.
    #[test]
    fn real_os_store_round_trips_where_available() {
        let service = format!("dig-keystore-test:{}", std::process::id());
        let Some(be) = OsKeychainBackend::open(&service) else {
            eprintln!(
                "no OS credential store on this host — skipping (FakeStore covers the logic)"
            );
            return;
        };

        let key = BackendKey::new("identity");
        assert!(!be.exists(&key).unwrap());

        let blob = super::test_support::sealed(0x01);
        be.write(&key, &blob).unwrap();
        assert!(be.exists(&key).unwrap());
        assert_eq!(be.read(&key).unwrap(), blob);

        // Overwrite replaces the value.
        let v2 = super::test_support::sealed(0x02);
        be.write(&key, &v2).unwrap();
        assert_eq!(be.read(&key).unwrap(), v2);

        // list reflects the live key.
        assert!(be
            .list("")
            .unwrap()
            .iter()
            .any(|k| k.as_str() == "identity"));

        be.delete(&key).unwrap();
        assert!(!be.exists(&key).unwrap());
        be.delete(&key).unwrap(); // idempotent

        // Clean up the index bookkeeping entry too.
        let _ = be.store.remove(INDEX_ACCOUNT);
    }
}
