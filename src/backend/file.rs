//! Filesystem backend.
//!
//! # What this does
//!
//! Stores each [`BackendKey`] as a `<root>/<key>.dks` file (`.dks` = "DIG
//! keystore"). Writes are atomic (tmp file + rename). Deletes best-effort
//! overwrite the file with zeros before unlinking.
//!
//! # Atomicity
//!
//! On **POSIX**: `rename(2)` is atomic within a filesystem. We write to
//! `<key>.dks.tmp.<random>`, `fsync` the file handle, then `rename` onto the
//! final name. If the process crashes between the open and the rename, the
//! tmp file is orphaned but the original `<key>.dks` (if any) is intact.
//!
//! On **Windows**: Rust's `std::fs::rename` wraps `MoveFileExW` with the
//! `MOVEFILE_REPLACE_EXISTING` flag, which is atomic enough for our purposes
//! (Windows does not provide a fully-atomic rename-across-replace on all
//! filesystems but the behaviour is "either old or new contents — never a
//! torn write").
//!
//! # Permissions
//!
//! On Unix, the keystore root directory (on creation) and every written file
//! are restricted to mode `0700` / `0600` — reachable only by the owning user
//! — and that restriction is **verified after the fact**, not merely
//! requested. A path that is still group- or other-accessible fails the write
//! with [`KeystoreError::InsecurePermissions`] rather than succeeding quietly,
//! because a `chmod` on a filesystem without POSIX modes reports success and
//! changes nothing. See [`is_owner_only`].
//!
//! **On Windows there is no equivalent floor.** Standard NTFS ACL inheritance
//! applies and this crate does not narrow it, so a blob inherits whatever its
//! parent directory grants. Restricting it would mean an explicit owner-only
//! DACL, which requires Win32 FFI, and this package pins `unsafe_code =
//! "forbid"` as a spec property (`SPEC.md` §12/§13.2, conformance C-15) — so
//! that enforcement cannot live here. It belongs beside the platform hardware
//! providers in a separate workspace member (dig_ecosystem #1693). Until then,
//! operators on a shared user account should not rely on this crate for access
//! control on Windows.
//!
//! Either way this is defence in depth. The blob is already sealed with
//! AES-256-GCM under an Argon2id-hardened key (`SPEC.md` §3–§5); permissions
//! decide who may *attempt* an offline attack on it, not whether one succeeds.
//!
//! # Secure delete
//!
//! On modern SSDs, a single-pass overwrite cannot guarantee the sectors are
//! unrecoverable — the SSD's flash translation layer may have copied them
//! elsewhere. This crate does a single zero pass as a best-effort. For
//! high-value keys on untrusted hardware, use full-disk encryption (LUKS,
//! BitLocker) which zero-keys the entire volume on wipe.
//!
//! # References
//!
//! - [POSIX `rename(2)`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/rename.html)
//! - [Windows `MoveFileExW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
//! - [DJB on secure-delete on SSDs](https://cr.yp.to/bib/2009/coker.pdf)

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::backend::{BackendKey, KeychainBackend};
use crate::error::{KeystoreError, Result};

/// File extension for keystore blobs. Stands for "DIG KeyStore".
const EXT: &str = "dks";

/// Every group and other permission bit — the set that must be clear on any
/// path holding sealed key material.
const GROUP_AND_OTHER_BITS: u32 = 0o077;

/// Whether `mode` grants access to nobody but the owner.
///
/// This is the property the backend actually promises. It is deliberately
/// phrased over the *observed* bits rather than over "did `chmod` return
/// `Ok`", because the two are not the same thing: on a filesystem with no
/// POSIX mode support a `chmod` succeeds and changes nothing, so a successful
/// call is no evidence at all that the file is protected.
///
/// Only the low nine permission bits are considered; file-type and setuid
/// bits carried in the same word are irrelevant to who may read the blob.
///
/// Compiled on every platform even though only Unix calls it, so that its
/// behaviour is testable on any build host. A `#[cfg(unix)]` predicate is
/// unfalsifiable on a Windows developer machine, which is where most of this
/// crate's consumers are written.
#[cfg_attr(not(unix), allow(dead_code))]
fn is_owner_only(mode: u32) -> bool {
    mode & GROUP_AND_OTHER_BITS == 0
}

/// Request owner-only permissions on `path`, then verify they took effect.
///
/// `requested` is the mode to ask for (`0o700` for the root directory,
/// `0o600` for a blob). The request's own error is intentionally ignored: it
/// is the verification below, not the call's return value, that decides
/// whether the path is safe to hold key material.
///
/// On non-Unix hosts this is a no-op — see the module docs for what does and
/// does not protect a blob on Windows.
#[allow(unused_variables)]
fn enforce_owner_only(path: &Path, requested: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let _ = fs::set_permissions(path, fs::Permissions::from_mode(requested));

        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if !is_owner_only(mode) {
            return Err(KeystoreError::InsecurePermissions {
                path: path.display().to_string(),
                mode,
            });
        }
    }
    Ok(())
}

/// Filesystem-backed keychain.
///
/// Thread-safe — `KeychainBackend` is `Send + Sync`, and all operations use
/// OS-level atomic primitives (rename, unlink). Multiple `FileBackend`
/// instances pointing at the same root directory coexist without mutual
/// serialization; the tmp-file names include a random suffix so concurrent
/// writes to the same `BackendKey` do not step on each other's tmp files.
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use dig_keystore::{
///     backend::{FileBackend, BackendKey, KeychainBackend},
/// };
///
/// let backend: Arc<dyn KeychainBackend> = Arc::new(
///     FileBackend::new("/var/lib/dig/keys")
/// );
/// backend.write(&BackendKey::new("v1"), b"...").unwrap();
/// # drop(backend);
/// ```
pub struct FileBackend {
    /// Directory that contains all `<key>.dks` files owned by this backend.
    root: PathBuf,
}

impl FileBackend {
    /// Create a new file backend rooted at `root`.
    ///
    /// The directory is **not** created immediately — it is lazily created on
    /// the first `write` call (with mode `0700` on Unix). This lets callers
    /// construct a `FileBackend` in tests without side effects; no files are
    /// written until the first `write`.
    ///
    /// # Example
    ///
    /// ```
    /// use dig_keystore::backend::FileBackend;
    /// let be = FileBackend::new("/var/lib/dig/keys");
    /// let _ = be;  // directory not created yet
    /// ```
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The root directory this backend writes to.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Build the full path for a `BackendKey`.
    fn path_for(&self, key: &BackendKey) -> PathBuf {
        let mut p = self.root.clone();
        p.push(format!("{}.{}", key.as_str(), EXT));
        p
    }

    /// Create the root directory if it does not already exist, and hold it to
    /// the owner-only floor whether or not this call created it.
    ///
    /// Called from `write` to support the "lazy directory creation" behaviour.
    /// On Unix the directory is restricted to mode `0700` — so only the owning
    /// user can list or enter it — and that is verified, not assumed.
    ///
    /// **The check runs on every write, not only on the creation path.** An
    /// earlier shape returned early when the root already existed, which left
    /// the floor unreachable for exactly the roots that need it most: one
    /// created by a version that requested `0700` without checking the result,
    /// on a filesystem where that request does nothing, stays unverified
    /// forever.
    ///
    /// The exposure that closes is the root's **write** bits rather than its
    /// read bits — blobs carry their own verified `0600`, so a permissive root
    /// does not expose sealed bytes, but group- or world-writable grants
    /// `unlink` and `create` inside it. That is blob substitution (rolling a
    /// victim back to an older sealed seed) and deletion, on the directory
    /// holding an account master seed.
    fn ensure_root(&self) -> Result<()> {
        if !self.root.exists() {
            fs::create_dir_all(&self.root)?;
        }
        enforce_owner_only(&self.root, 0o700)
    }
}

impl KeychainBackend for FileBackend {
    /// Read the entire file at `<root>/<key>.dks`.
    ///
    /// Returns `KeystoreError::Backend` wrapping an `io::Error` with
    /// `ErrorKind::NotFound` if the file does not exist.
    fn read(&self, key: &BackendKey) -> Result<Vec<u8>> {
        let path = self.path_for(key);
        let mut f = fs::File::open(&path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Atomically write `data` to `<root>/<key>.dks`.
    ///
    /// Steps:
    /// 1. Ensure `root` exists.
    /// 2. Create sibling `<key>.dks.tmp.<random>` file and restrict it to mode
    ///    `0600` on Unix, verifying the result before any bytes are written —
    ///    so a root that cannot hold key material safely yields
    ///    [`KeystoreError::InsecurePermissions`] and an empty, removed tmp
    ///    file rather than an exposed blob.
    /// 3. Write `data`, `fsync` the file handle.
    /// 4. `rename` the tmp file onto the final name.
    /// 5. On Unix, `fsync` the containing directory so the rename is durable.
    /// 6. On error in step 4, best-effort unlink the tmp file.
    ///
    /// The random suffix in step 2 is **not** cryptographic — it exists only
    /// to disambiguate two concurrent writes to the same key from the same
    /// process. Uses a hash of `(nanoseconds_since_epoch, pid)`.
    fn write(&self, key: &BackendKey, data: &[u8]) -> Result<()> {
        self.ensure_root()?;
        let final_path = self.path_for(key);
        let mut tmp_path = final_path.clone();
        let rand_suffix: u64 = fastrand_suffix();
        tmp_path.set_extension(format!("{EXT}.tmp.{rand_suffix:016x}"));

        // Stage the bytes into the tmp file. Written as a closure so the file
        // handle is dropped by leaving scope — and so EVERY failure in here,
        // not just a rename failure, gets the same cleanup below. An earlier
        // shape orphaned the tmp file whenever `write_all` or `sync_all`
        // failed.
        let staged = (|| -> Result<()> {
            let mut f = fs::File::create(&tmp_path)?;
            // Restrict the file BEFORE any ciphertext reaches it. A keystore
            // that cannot protect its own blobs must write nothing at all,
            // rather than report success over a world-readable seed.
            enforce_owner_only(&tmp_path, 0o600)?;
            f.write_all(data)?;
            // fsync the file so the bytes hit durable storage before rename.
            // Without this, a crash between write() and rename() would leave
            // a zero-length tmp file and no keystore data at all.
            f.sync_all()?;
            Ok(())
        })();

        if let Err(e) = staged {
            // The handle is already closed, so this also succeeds on Windows,
            // where an open file cannot be unlinked.
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        // Atomic rename. On POSIX this is truly atomic within a filesystem;
        // on Windows it's "effectively atomic" via MoveFileExW.
        fs::rename(&tmp_path, &final_path).map_err(|e| {
            // Best-effort cleanup of the tmp file on rename failure.
            let _ = fs::remove_file(&tmp_path);
            KeystoreError::from(e)
        })?;

        // fsync the containing directory on Unix so the rename is durable
        // across a crash. No-op on Windows (directory fsync isn't a concept).
        #[cfg(unix)]
        {
            if let Ok(dir) = fs::File::open(&self.root) {
                let _ = dir.sync_all();
            }
        }

        Ok(())
    }

    /// Best-effort secure delete, then unlink.
    ///
    /// Steps:
    /// 1. No-op if file does not exist (idempotent).
    /// 2. Open the file for writing; overwrite with zeros in 4 KiB chunks.
    /// 3. `fsync` the overwritten file so zeros hit storage.
    /// 4. `unlink` the file.
    ///
    /// Step 2 is best-effort. On SSDs with flash translation layer or on
    /// copy-on-write filesystems (btrfs, ZFS), the zero pass may not reach
    /// the sectors that held the ciphertext. Use full-disk encryption for
    /// stronger guarantees.
    fn delete(&self, key: &BackendKey) -> Result<()> {
        let path = self.path_for(key);
        if !path.exists() {
            return Ok(());
        }

        if let Ok(metadata) = fs::metadata(&path) {
            let len = metadata.len();
            if let Ok(mut f) = fs::OpenOptions::new().write(true).open(&path) {
                let zeros = vec![0u8; 4096];
                let mut remaining = len as usize;
                while remaining > 0 {
                    let n = remaining.min(zeros.len());
                    if f.write_all(&zeros[..n]).is_err() {
                        break;
                    }
                    remaining -= n;
                }
                let _ = f.sync_all();
            }
        }

        fs::remove_file(&path)?;
        Ok(())
    }

    /// Enumerate keys whose names start with `prefix`.
    ///
    /// Scans the root directory; skips any file that:
    /// - does not end in `.dks`
    /// - has a non-UTF-8 name
    /// - does not start with `prefix`
    ///
    /// Returns an empty vec if the root directory does not exist.
    fn list(&self, prefix: &str) -> Result<Vec<BackendKey>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = match name.to_str() {
                Some(s) => s,
                None => continue,
            };
            let Some(stem) = name.strip_suffix(&format!(".{EXT}")) else {
                continue;
            };
            if stem.starts_with(prefix) {
                out.push(BackendKey::new(stem.to_string()));
            }
        }
        Ok(out)
    }

    /// Cheap override — `Path::exists` stats without opening the file.
    fn exists(&self, key: &BackendKey) -> Result<bool> {
        Ok(self.path_for(key).exists())
    }
}

/// Quick, non-cryptographic random suffix for tmp filenames.
///
/// We do NOT use this for anything security-sensitive — it only disambiguates
/// concurrent tmp files. Uses `(nanoseconds_since_epoch * golden_ratio_prime) + pid`
/// for a spread uniform enough to avoid collisions across processes on the same host.
///
/// If two tmp files happen to collide, the loser will fail the final
/// `fs::rename` with `AlreadyExists` (on Windows) or succeed but overwrite
/// the other tmp (on Unix); either way the actual final `.dks` file is
/// unaffected.
fn fastrand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    // 0x9E37_79B9_7F4A_7C15 = 2^64 / golden ratio — gives uniform spread.
    ns.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// **Proves:** `FileBackend::write` followed by `FileBackend::read`
    /// recovers the same bytes.
    ///
    /// **Why it matters:** The basic "file actually persists" check. This
    /// exercises the full tmp-file + rename path including directory
    /// creation, mode setting, `fsync`, and `rename`.
    ///
    /// **Catches:** a regression where `write` skips the rename step (file
    /// left in `<name>.tmp.XXX` form) or `read` opens the wrong path.
    #[test]
    fn write_then_read_roundtrip() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());
        let key = BackendKey::new("test");
        be.write(&key, b"hello").unwrap();
        let out = be.read(&key).unwrap();
        assert_eq!(out, b"hello");
    }

    /// **Proves:** two sequential `write` calls to the same key leave no
    /// `.tmp.` residue in the directory — meaning the tmp-then-rename
    /// dance successfully cleaned up intermediate files.
    ///
    /// **Why it matters:** If tmp files accumulated, `list` would return
    /// them to callers, disk space would leak, and operators would have to
    /// manually clean up. The second `write` also asserts that the newer
    /// content (`"second"`) overwrote the older (`"first"`) — atomicity's
    /// visible behaviour.
    ///
    /// **Catches:** a regression where the rename fails silently and the
    /// tmp file is not deleted; a regression where the final file is not
    /// actually renamed on top of the previous one.
    #[test]
    fn write_is_atomic_on_rename_failure() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());
        let key = BackendKey::new("atomic");
        be.write(&key, b"first").unwrap();
        be.write(&key, b"second").unwrap();
        assert_eq!(be.read(&key).unwrap(), b"second");
        // No .tmp files should linger.
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        for e in entries {
            let name = e.unwrap().file_name();
            let s = name.to_string_lossy().into_owned();
            assert!(!s.contains(".tmp."), "leftover tmp file: {s}");
        }
    }

    /// **Proves:** after `delete`, the file is gone and `exists` returns `false`.
    ///
    /// **Why it matters:** Confirms the delete path actually unlinks the
    /// file. This is the final action in `Keystore::delete`; a regression
    /// here would leave keystore files behind after an operator thought
    /// they had wiped them.
    ///
    /// **Catches:** a regression where `delete` only overwrites (secure
    /// wipe) without unlinking; where `exists` checks a stale cache; or
    /// where `delete` silently errors on the unlink step.
    #[test]
    fn delete_removes_file() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());
        let key = BackendKey::new("delete_me");
        be.write(&key, b"bye").unwrap();
        assert!(be.exists(&key).unwrap());
        be.delete(&key).unwrap();
        assert!(!be.exists(&key).unwrap());
    }

    /// **Proves:** deleting a non-existent key is a no-op success — not an
    /// error.
    ///
    /// **Why it matters:** The [`KeychainBackend`] contract requires
    /// `delete` to be idempotent. Callers (e.g., `dig-validator keys remove`)
    /// can call `delete` without first checking existence; a double-call
    /// after a concurrent delete should not fail.
    ///
    /// **Catches:** a regression where `delete` returns `NotFound` for
    /// missing files.
    #[test]
    fn delete_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());
        be.delete(&BackendKey::new("never_existed")).unwrap();
    }

    /// **Proves:** `list("alph")` returns exactly `["alpha", "alpha2"]`
    /// when the directory contains `alpha.dks`, `alpha2.dks`, and `beta.dks`.
    ///
    /// **Why it matters:** Prefix-based listing is what enables CLI tools
    /// like `dig-validator keys list` to enumerate all keystores of a given
    /// operator. Strict prefix matching (not substring, not suffix) must
    /// be pinned.
    ///
    /// **Catches:** `starts_with` → `contains` regression (which would
    /// include `beta` if prefix were `"eta"`); failure to strip the `.dks`
    /// extension.
    #[test]
    fn list_with_prefix() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());
        be.write(&BackendKey::new("alpha"), b"a").unwrap();
        be.write(&BackendKey::new("alpha2"), b"a").unwrap();
        be.write(&BackendKey::new("beta"), b"b").unwrap();
        let mut keys = be.list("alph").unwrap();
        keys.sort_by_key(|k| k.0.clone());
        assert_eq!(
            keys,
            vec![BackendKey::new("alpha"), BackendKey::new("alpha2")]
        );
    }

    /// **Proves:** reading a non-existent key returns a `KeystoreError::Backend`
    /// wrapping an `io::Error` with `ErrorKind::NotFound`.
    ///
    /// **Why it matters:** The default [`KeychainBackend::exists`] impl
    /// relies on this specific error shape to distinguish "not present"
    /// from "I/O failed." If `read` returned a generic `InvalidInput` or
    /// similar, `exists` would misclassify missing keys.
    ///
    /// **Catches:** a regression where `read` eats the OS error and
    /// returns a custom `KeystoreError` variant, breaking the default
    /// `exists` implementation.
    #[test]
    fn read_nonexistent_returns_error() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());
        let err = be.read(&BackendKey::new("missing")).unwrap_err();
        let is_not_found = match &err {
            KeystoreError::Backend(io) => io.kind() == std::io::ErrorKind::NotFound,
            _ => false,
        };
        assert!(is_not_found);
    }

    /// **Proves:** `FileBackend::write` lazily creates the root directory
    /// (and intermediate parents) when the first write arrives.
    ///
    /// **Why it matters:** Operators may point the validator at
    /// `~/.dig/keys/` before that directory exists. Requiring them to
    /// `mkdir -p` first is poor UX. This test pins the "lazy mkdir" on
    /// first write behaviour so `FileBackend::new` can remain side-effect-free.
    ///
    /// **Catches:** a regression where `write` assumes the dir exists and
    /// fails with `NotFound` on first call; or where `new` eagerly creates
    /// the dir (unwanted in tests).
    #[test]
    fn creates_root_dir() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("nested/keys");
        let be = FileBackend::new(sub.clone());
        assert!(!sub.exists());
        be.write(&BackendKey::new("k"), b"x").unwrap();
        assert!(sub.exists());
    }

    /// `is_owner_only` accepts exactly those modes that grant nobody but the
    /// owner any access.
    ///
    /// **Why it matters:** this predicate is the whole of the permission
    /// guarantee. Everything else in `enforce_owner_only` is plumbing around
    /// its answer, so a predicate that is merely *nearly* right silently
    /// downgrades the at-rest floor for dig-app's account seed and dig-node's
    /// seed store, which are this backend's production callers.
    ///
    /// **Catches:** each of the plausible near-miss implementations. `0o400`
    /// and `0o000` rule out an equality test against `0o600`; `0o640` rules
    /// out a predicate that only inspects the *other* triad (and any
    /// `mode & 0o077 != 0o077` inversion, which would read group-readable as
    /// safe); `0o604` rules out one that only inspects the *group* triad.
    #[test]
    fn owner_only_predicate_rejects_every_non_owner_bit() {
        // No access for group or other, at varying owner permissions.
        for mode in [0o000, 0o400, 0o600, 0o700] {
            assert!(
                is_owner_only(mode),
                "{mode:04o} grants nobody but the owner"
            );
        }

        // A single group or other bit is enough to fail, in either triad.
        for mode in [0o640, 0o604, 0o644, 0o060, 0o006, 0o660, 0o777] {
            assert!(!is_owner_only(mode), "{mode:04o} reaches beyond the owner");
        }
    }

    /// A written blob, and the root that holds it, really are owner-only on
    /// disk — not merely requested to be.
    ///
    /// **Why it matters:** `SPEC.md` §10.3 / conformance C-14 state mode
    /// `0700` for the root and `0600` for blobs as a normative property. It
    /// was previously requested with the result discarded, so nothing
    /// observed whether it held.
    ///
    /// **Catches:** a regression that drops the `enforce_owner_only` call
    /// from either `ensure_root` or `write`, or that reorders the blob's
    /// restriction after `write_all` so ciphertext lands at the umask default
    /// first.
    ///
    /// Unix-only because Windows has no POSIX mode. That makes it
    /// unfalsifiable on a Windows build host, which is why the predicate above
    /// is tested separately and unconditionally.
    #[cfg(unix)]
    #[test]
    fn written_blob_and_root_are_owner_only_on_disk() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let root = dir.path().join("keys");
        let be = FileBackend::new(root.clone());
        be.write(&BackendKey::new("seed"), b"sealed").unwrap();

        let root_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(root_mode, 0o700, "root dir mode");

        let blob_mode = fs::metadata(root.join("seed.dks"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(blob_mode, 0o600, "blob mode");
    }

    /// An **already-existing** permissive root is brought back to `0700` on the
    /// next write, not left alone.
    ///
    /// **Why it matters:** the floor is worthless if it only applies to roots
    /// this version created. A root created by 0.8.x — which requested `0700`
    /// and discarded the result — is precisely the one at risk, and it exists
    /// before any 0.9.0 write reaches it. The exposure is the root's *write*
    /// bits: blobs carry their own verified `0600`, but a group- or
    /// world-writable root grants `unlink` and `create`, which is blob
    /// substitution (rolling a victim back to an older sealed seed) and
    /// deletion, on the directory holding an account master seed.
    ///
    /// **Catches:** the `if self.root.exists() { return Ok(()); }` early
    /// return. Under it this test sees `0o755` and fails, because
    /// `enforce_owner_only` never runs on the existing-root path.
    /// `written_blob_and_root_are_owner_only_on_disk` above cannot catch it:
    /// its root is a fresh non-existent path, so it only ever exercises the
    /// creation branch.
    ///
    /// **Why this asserts tightening rather than `InsecurePermissions`:** on a
    /// root the process owns, `chmod` succeeds, so the permissive mode is
    /// repaired and there is nothing to refuse. Erroring instead would fail a
    /// host the crate can simply fix. `InsecurePermissions` stays reserved for
    /// the unrepairable case — a filesystem where the `chmod` does nothing —
    /// which is the branch documented as unreachable in a test.
    #[cfg(unix)]
    #[test]
    fn existing_permissive_root_is_tightened_on_write() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let root = dir.path().join("keys");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o755,
            "fixture must start group/other-accessible, or it proves nothing"
        );

        let be = FileBackend::new(root.clone());
        be.write(&BackendKey::new("seed"), b"sealed").unwrap();

        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700,
            "an existing root must be brought to the floor, not skipped"
        );
    }
}
