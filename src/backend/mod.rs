//! Storage backend abstraction.
//!
//! # Coupled records
//!
//! `write` is **replace-semantics**: it settles the new bytes over whatever was
//! there. That is the right shape for updating one record, and the wrong shape
//! for *establishing* one — so [`write_new`](KeychainBackend::write_new) exists
//! alongside it, and the difference matters most for **coupled** records.
//!
//! Two records are coupled when neither is useful without the other: a wrapped
//! blob and the device key that opens it, a sealed secret and its salt, a
//! payload and its integrity sidecar. Written with `write`, two concurrent
//! starts can settle **device key `D_B` beside blob `B_A`** — a key that does
//! not open the blob next to it. A well-behaved consumer also refuses to
//! re-mint an identity it already has, and those two individually-correct
//! decisions compose into a state that **can never self-heal**: the consumer is
//! permanently unable to open its own data, and restarting does nothing.
//!
//! The known-good remedy is structural rather than a lock. Establish the shared
//! record with `write_new` and **adopt on
//! [`AlreadyExists`](crate::error::KeystoreError::AlreadyExists)**, so exactly
//! one racer creates it and every other seals under the record that won. The
//! mismatch becomes unreachable instead of unlikely. Check
//! [`write_new_exclusivity`](KeychainBackend::write_new_exclusivity) first: on a
//! [`BestEffort`](Exclusivity::BestEffort) backend the reasoning does not hold.
//!
//! Preventing the state matters more than reporting it, because the resulting
//! error **structurally cannot name its own cause**. Once hardware binding is in
//! play a mismatch surfaces as `HardwareUnwrapFailed`, which `SPEC.md` §17.5b
//! establishes cannot distinguish a blob copied to another machine from a device
//! whose key was wiped. No inspection of the bytes recovers the difference.
//!
//! A `KeychainBackend` is any byte-blob KV store. Three ship today:
//! `MemoryBackend` (always available), `FileBackend` (feature `file-backend`,
//! atomic tmp + rename writes to the local filesystem), and
//! `OsKeychainBackend` (feature `os-keychain`, the host OS credential store on
//! Windows/macOS — see its module docs for the access boundary it does and
//! does not provide, and for why a machine service must not use it). Planned
//! future backends: hardware-signer backends (`LedgerBackend`, `YubiHsmBackend`)
//! that proxy `sign` to an external device.

use crate::error::Result;

#[cfg(feature = "file-backend")]
mod file;
mod memory;
// `pub(crate)` (not private) so `crate::hardware::tests` can reach the
// in-memory `test_support` doubles and compose a real `OsKeychainBackend`
// under a `HardwareBoundBackend` without a live OS credential store.
#[cfg(feature = "os-keychain")]
pub(crate) mod os_keychain;

#[cfg(feature = "file-backend")]
pub use file::FileBackend;
/// In-memory backend — always available. Originally feature-gated, now
/// unconditional because production adapters (e.g., `dig-l1-wallet`'s
/// encrypt/decrypt-bytes helpers) wrap it in scratch backends to reuse the
/// full keystore format without touching the filesystem.
pub use memory::MemoryBackend;
#[cfg(feature = "os-keychain")]
pub use os_keychain::OsKeychainBackend;

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

/// Whether a backend's [`write_new`](KeychainBackend::write_new) is exclusive
/// by construction, or only by a check the backend performs itself.
///
/// A consumer reaches for `write_new` to make a coupled-record mismatch
/// **unreachable** rather than merely unlikely, and that reasoning is only
/// valid against a backend whose store offers a create-if-absent primitive.
/// So the claim is exposed rather than assumed.
///
/// The default is [`BestEffort`](Self::BestEffort): a backend that says nothing
/// **understates** its guarantee. Overstating it hands a consumer back exactly
/// the race the method exists to remove, which is the more expensive direction
/// to be wrong in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exclusivity {
    /// The underlying store creates-if-absent in one indivisible step, so two
    /// concurrent `write_new` calls cannot both succeed. Exactly one racer
    /// establishes the record and every other receives
    /// [`KeystoreError::AlreadyExists`](crate::error::KeystoreError::AlreadyExists).
    Atomic,

    /// The backend checks for the key and then writes. Correct when uncontended,
    /// but two concurrent calls can both observe absence and both write, so a
    /// consumer MUST NOT rely on this to make a coupled mismatch unreachable.
    ///
    /// The store offers no create-if-absent primitive — not a defect in the
    /// backend, and the reason this is reported rather than hidden.
    BestEffort,
}

impl std::fmt::Display for Exclusivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Atomic => "atomic create-if-absent",
            Self::BestEffort => "best-effort (check then write)",
        })
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

    /// Write `data` to `key` **only if nothing is stored there**, returning
    /// [`KeystoreError::AlreadyExists`](crate::error::KeystoreError::AlreadyExists)
    /// otherwise.
    ///
    /// This is the *establish*, not *update*, entry point. Use it whenever the
    /// write is meant to happen exactly once — see the crate-level
    /// [coupled-records](self#coupled-records) note for why that distinction
    /// is load-bearing and not a convenience.
    ///
    /// Consult [`write_new_exclusivity`](Self::write_new_exclusivity) before
    /// relying on it to make a coupled mismatch *unreachable*: not every store
    /// can offer create-if-absent as one indivisible step.
    ///
    /// There is deliberately **no default implementation**. A default composed
    /// of `exists` then `write` would look like this contract while quietly
    /// providing none of it, and every backend that forgot to override it
    /// would inherit the race silently.
    fn write_new(&self, key: &BackendKey, data: &[u8]) -> Result<()>;

    /// How strong [`write_new`](Self::write_new)'s exclusivity is on this
    /// backend.
    ///
    /// Defaults to [`Exclusivity::BestEffort`] so that a backend which has not
    /// considered the question **understates** rather than overstates what a
    /// consumer may rely on.
    fn write_new_exclusivity(&self) -> Exclusivity {
        Exclusivity::BestEffort
    }

    /// Remove the blob at `key`. Implementations should best-effort overwrite
    /// the storage before removing so residual disk sectors do not retain the
    /// ciphertext.
    fn delete(&self, key: &BackendKey) -> Result<()>;

    /// List keys that start with `prefix`. Order is unspecified.
    fn list(&self, prefix: &str) -> Result<Vec<BackendKey>>;

    /// Whether a blob exists at `key`.
    ///
    /// **Three-valued, and it must stay that way.** `Ok(true)` is present,
    /// `Ok(false)` is *confidently* absent, and `Err` is **could not
    /// determine** — an unreadable parent, a failing mount, an I/O fault. An
    /// implementation MUST NOT collapse the third answer into the second.
    ///
    /// The reason is what callers do with it: this answer decides whether to
    /// **mint**. Since `write` replaces, a spurious `false` does not produce a
    /// harmless duplicate beside the original — it overwrites the original, and
    /// once that blob is hardware-wrapped (`SPEC.md` §17) the overwrite is
    /// unrecoverable. Refusing on an unanswerable read is therefore the
    /// fail-closed choice, and the only safe one.
    ///
    /// The default impl delegates to `read`. Backends with a cheaper existence
    /// check may override, but the override inherits this contract — note that
    /// `Path::exists()` does **not** satisfy it, because it maps every error to
    /// `false`.
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
        fn write_new(&self, _key: &BackendKey, _data: &[u8]) -> Result<()> {
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

    /// **Proves:** a backend that implements only the required trait items
    /// reports [`Exclusivity::BestEffort`].
    ///
    /// **Why it matters:** the direction of this default is a safety property,
    /// not a style choice. A consumer reads it to decide whether `write_new`
    /// makes a coupled-record mismatch *unreachable* (§10.2a). An implementor
    /// who has not considered the question must therefore **understate** the
    /// guarantee; a default of `Atomic` would let silence hand back exactly the
    /// race the method exists to remove, and nothing would flag it.
    ///
    /// **Catches:** flipping the default to `Atomic` — which nothing else in
    /// the suite would notice, because all three shipped backends override it.
    #[test]
    fn a_backend_that_says_nothing_claims_only_best_effort() {
        let be = ProbeBackend::default();
        assert_eq!(be.write_new_exclusivity(), Exclusivity::BestEffort);
    }

    /// **Proves:** the two [`Exclusivity`] variants render as distinct,
    /// non-empty strings that say which is which.
    ///
    /// **Why it matters:** this value is reported into operator-facing logs and
    /// diagnostics to explain *why* a consumer must place a coupled record on
    /// one backend rather than another. Two variants that printed the same
    /// text, or an empty one, would make the distinction the type exists to
    /// carry invisible at exactly the point someone is reading for it.
    ///
    /// **Catches:** a copy-paste in the `Display` arms.
    #[test]
    fn exclusivity_renders_distinguishably() {
        let atomic = Exclusivity::Atomic.to_string();
        let best = Exclusivity::BestEffort.to_string();
        assert!(atomic.contains("atomic"), "{atomic}");
        assert!(best.contains("best-effort"), "{best}");
        assert_ne!(atomic, best);
    }
}
