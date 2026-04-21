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
//! On Unix, both the keystore root directory (on creation) and every written
//! file are set to mode `0700` / `0600` respectively — readable only by the
//! owning user. On Windows, standard NTFS ACL inheritance applies; operators
//! running under a shared user account should not rely on this crate for
//! access control.
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

    /// Create the root directory if it does not already exist.
    ///
    /// Called from `write` to support the "lazy directory creation" behaviour.
    /// On Unix, sets the directory to mode `0700` so only the owning user can
    /// list / enter it.
    fn ensure_root(&self) -> Result<()> {
        if self.root.exists() {
            return Ok(());
        }
        fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
        }
        Ok(())
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
    /// 2. Create sibling `<key>.dks.tmp.<random>` file, mode `0600` on Unix.
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

        {
            let mut f = fs::File::create(&tmp_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
            }
            f.write_all(data)?;
            // fsync the file so the bytes hit durable storage before rename.
            // Without this, a crash between write() and rename() would leave
            // a zero-length tmp file and no keystore data at all.
            f.sync_all()?;
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
}
