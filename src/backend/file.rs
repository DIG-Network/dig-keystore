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
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::backend::{BackendKey, Exclusivity, KeychainBackend};
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

/// Create `path` for writing, born owner-only where the platform allows it.
///
/// `File::create` opens with `0666 & ~umask`, so on a default umask the tmp
/// blob exists at `0644` for the window between the open and the narrowing
/// `chmod`. Requesting the mode in the `open(2)` call itself removes that
/// window: the file never exists under a permissive mode at all. `create_new`
/// additionally refuses to follow a symlink planted on the tmp path.
///
/// One window is *not* closed by this, and is not closable from user space: a
/// process holding a directory fd opened before the root was tightened can
/// still `openat` inside it, and read permission granted at open time survives
/// any later `chmod`. That is why the root is brought to a verified `0700`
/// before any tmp file is created, rather than relying on the blob mode alone.
fn create_owner_only(path: &Path) -> Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    Ok(opts.open(path)?)
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
    ///
    /// **A permissive mode is repaired; a symlinked root is refused.** The two
    /// resolve in opposite directions because they are different kinds of
    /// claim. A mode is a property of the intended directory: the backend can
    /// correct it in one syscall and then *verify* that it did, so refusing
    /// instead would turn any drift — a restore from backup, a `chmod` by the
    /// user — into a permanent brick on master-seed writes, and hand anyone who
    /// can merely widen the mode a denial primitive over a condition the crate
    /// can fix. A symlink is a claim about *which directory the keystore is*,
    /// and no syscall makes an attacker-chosen directory into the intended one;
    /// since `set_permissions` and `metadata` both follow links, "repairing" it
    /// would mean chmodding that directory to `0700` and sealing the seed
    /// inside it. Fail closed where the invariant cannot be established, repair
    /// where it can be established and confirmed.
    fn ensure_root(&self) -> Result<()> {
        // `symlink_metadata` inspects the root itself; `exists()` and
        // `metadata()` both follow links, and so do `set_permissions` and the
        // verification read below. Following a link here would mean chmodding
        // and then seeding a directory chosen by whoever planted it.
        match fs::symlink_metadata(&self.root) {
            Ok(meta) if meta.file_type().is_symlink() => Err(KeystoreError::UnsafeRoot {
                path: self.root.display().to_string(),
                reason: "it is a symbolic link; pass the resolved target if that is intended",
            }),
            Ok(meta) if !meta.is_dir() => Err(KeystoreError::UnsafeRoot {
                path: self.root.display().to_string(),
                reason: "it exists and is not a directory",
            }),
            Ok(_) => enforce_owner_only(&self.root, 0o700),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.root)?;
                enforce_owner_only(&self.root, 0o700)
            }
            Err(e) => Err(KeystoreError::from(e)),
        }
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
    /// 1. Ensure `root` exists, is a directory rather than a symlink, and is
    ///    verified owner-only.
    /// 2. Create sibling `<key>.dks.tmp.<random>` file with mode `0600`
    ///    requested in the `open(2)` call on Unix, then verify the mode that
    ///    actually took effect before any bytes are written —
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
            let mut f = create_owner_only(&tmp_path)?;
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
    /// 1. No-op if the file is **confidently absent** (idempotent); refuses if
    ///    its presence could not be determined, rather than reporting a
    ///    completed erase over a blob that may still be there.
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
        // Three-valued, exactly as `exists` — an absent blob is an idempotent
        // success, but a blob whose presence could not be DETERMINED is a
        // refusal. `Path::exists()` collapses those, so an unreadable parent
        // used to report a completed secure-erase over key material still on
        // disk (`SPEC.md` §10.2).
        match fs::symlink_metadata(&path) {
            // Present. A dangling symlink lands here too, and is unlinked
            // below: something occupies the name, and removing it is what the
            // caller asked for.
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
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
    /// Returns an empty vec if the root directory is **confidently absent**, and
    /// an error if it could not be inspected at all — the same three-valued
    /// contract [`exists`](Self::exists) keeps, for the same reason.
    fn list(&self, prefix: &str) -> Result<Vec<BackendKey>> {
        // An absent root is a legitimate empty result — no keystore has been
        // created yet. A root that could not be INSPECTED is not: reporting it
        // as empty tells a caller enumerating identities that the user has no
        // keys, when the truth is that we could not look (`SPEC.md` §10.2).
        match fs::symlink_metadata(&self.root) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
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

    /// Stat the path without opening it, preserving the trait's three-valued
    /// contract: present, confidently absent, or **could not determine**.
    ///
    /// Uses `symlink_metadata` rather than `Path::exists()` or `try_exists()`.
    /// `Path::exists()` maps every error to `false`, which turns an
    /// inspection failure into a confident negative — and the caller uses that
    /// answer to decide whether to mint over a `write` that replaces.
    ///
    /// `symlink_metadata` is also the stricter of the two honest options: it
    /// does not follow links, so a **dangling symlink** at the key path counts
    /// as present. Something occupies that name; refusing to write over it is
    /// the fail-closed reading, whereas `try_exists()` would report `false` and
    /// invite exactly the overwrite this method exists to prevent.
    fn exists(&self, key: &BackendKey) -> Result<bool> {
        match fs::symlink_metadata(self.path_for(key)) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Establish `<root>/<key>.dks` **only if it does not already exist**.
    ///
    /// Exclusivity comes from the OS: the file is opened with `create_new`, so
    /// exactly one racer creates it and every other gets
    /// [`KeystoreError::AlreadyExists`] — a distinguishable error the loser can
    /// adopt on, rather than a generic I/O failure it can only give up on.
    ///
    /// # Why this does not use tmp + rename
    ///
    /// `rename` always replaces, so it cannot express "only if absent"; the two
    /// guarantees are not simultaneously available without a hard link, which
    /// not every filesystem supports. Exclusivity is the one that matters here,
    /// and the cost is bounded: a crash mid-write leaves a **short file**, which
    /// the format's magic, length and CRC all detect on the next read
    /// (`SPEC.md` §3.2), and which is repaired by deleting it and retrying. The
    /// state this method exists to prevent — a coupled pair that settled
    /// mismatched — is neither detectable nor repairable. A best-effort unlink
    /// removes the partial file on the way out of any failure.
    fn write_new(&self, key: &BackendKey, data: &[u8]) -> Result<()> {
        self.ensure_root()?;
        let path = self.path_for(key);

        // `create_owner_only` is the same exclusive, born-owner-only open the
        // tmp-file path uses: `create_new(true)` plus the requested mode, so
        // the file never exists under a permissive mode and a symlink planted
        // on the path is refused rather than followed.
        let f = match create_owner_only(&path) {
            Ok(f) => f,
            Err(KeystoreError::Backend(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(KeystoreError::AlreadyExists(key.as_str().to_string()))
            }
            Err(e) => return Err(e),
        };

        // Stage the bytes with the handle owned by a closure, so it is closed
        // by leaving scope. An explicit `drop(f)` would say the same thing on
        // every native target and trip `clippy::drop_non_drop` on wasm32, where
        // `std::fs::File` is a stub that does not implement `Drop` — and the
        // close is load-bearing, because Windows cannot unlink an open file.
        // Same shape as `write`, for the same reason.
        let staged = (|mut f: fs::File| -> Result<()> {
            // The mode is verified, not merely requested: a `chmod` on a
            // filesystem without POSIX modes reports success and changes
            // nothing, so the file is removed below rather than filled with key
            // material it cannot protect. Same floor and reasoning as `write`.
            enforce_owner_only(&path, 0o600)?;
            f.write_all(data)?;
            f.sync_all()?;
            Ok(())
        })(f);

        if let Err(e) = staged {
            // Only reachable once THIS call created the file — an
            // `AlreadyExists` returned above, so a losing racer never reaches
            // here and can never unlink the winner's blob.
            let _ = fs::remove_file(&path);
            return Err(e);
        }

        // fsync the containing directory on Unix so the creation is durable
        // across a crash, matching `write`. Not a concept on Windows.
        #[cfg(unix)]
        {
            if let Ok(dir) = fs::File::open(&self.root) {
                let _ = dir.sync_all();
            }
        }

        Ok(())
    }

    /// `create_new(true)` is an atomic create-if-absent at the OS level, so two
    /// concurrent calls cannot both succeed.
    fn write_new_exclusivity(&self) -> Exclusivity {
        Exclusivity::Atomic
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
    use crate::error::KeystoreError;
    use tempfile::TempDir;
    /// A key whose name carries an interior NUL byte. Every OS path API
    /// rejects it with `InvalidInput` — never `NotFound` — so it is a
    /// deterministic, cross-platform way to make a `stat` **fail to answer**
    /// rather than answer "absent".
    ///
    /// It is the vehicle, not the property. The property is that an
    /// undeterminable read refuses; the realistic vehicles (an unreadable
    /// parent directory, a failing mount, an I/O fault) are not portably
    /// constructible in a unit test, and one of them is covered by
    /// `exists_refuses_when_the_parent_cannot_be_read` below.
    fn undeterminable_key() -> BackendKey {
        let mut name = String::from("un");
        name.push('\u{0}');
        name.push_str("determinable");
        BackendKey::new(name)
    }

    /// **Proves:** `FileBackend::exists` returns `Err` — not `Ok(false)` —
    /// when the filesystem could not answer whether the blob is there.
    ///
    /// **Why it matters:** `exists` is a two-valued answer to a three-valued
    /// question, and its one production caller (`Keystore::create_with_rng`,
    /// `src/custody/keystore.rs`) uses it to decide whether to MINT.
    /// `FileBackend::write` is replace-semantics tmp+rename, so a spurious
    /// `false` does not merely mint a duplicate beside the original — it
    /// **overwrites the original**. Once the blob is hardware-wrapped
    /// (`SPEC.md` §17) that overwrite is unrecoverable, and
    /// `HardwareUnwrapFailed` structurally cannot name its own cause
    /// (§17.5b), so the loss is silent as well as permanent.
    ///
    /// **Catches:** exactly the implementation this replaced —
    /// `Ok(self.path_for(key).exists())`. `Path::exists()` maps *every* error
    /// to `false`, so it returns `Ok(false)` for this fixture and this
    /// assertion fails. Also catches any future "cheap override" that maps a
    /// non-`NotFound` error to absent.
    #[test]
    fn exists_refuses_rather_than_reporting_absent_when_it_cannot_tell() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());

        // Control: the same backend answers a *determinable* absence honestly,
        // so the test cannot pass by refusing everything.
        assert!(
            !be.exists(&BackendKey::new("genuinely-absent")).unwrap(),
            "a determinable absence must still be reported as absent"
        );

        let err = be
            .exists(&undeterminable_key())
            .expect_err("an unanswerable stat must not be reported as absent");
        assert!(
            matches!(err, KeystoreError::Backend(_)),
            "the refusal must carry the underlying I/O cause"
        );
    }

    /// **Proves:** the refusal reaches the mint decision — a write is not
    /// attempted, and nothing is half-created, when the read could not answer.
    ///
    /// **Why it matters:** this is the *placement* half. The assertion above
    /// pins the backend's contract; a guard added in `Keystore::create`
    /// instead would leave every other present and future `exists` caller
    /// minting on a false absence. Both the seam and its effect are observed,
    /// so the fix cannot be relocated without a test noticing.
    ///
    /// **Catches:** an `exists` override that answers `Ok(false)` here, which
    /// would let the write proceed.
    #[test]
    fn an_unanswerable_read_does_not_reach_a_write() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());
        let key = undeterminable_key();

        assert!(be.exists(&key).is_err());
        // And the write itself refuses too, rather than half-creating anything.
        assert!(be.write(&key, b"payload").is_err());
        assert!(
            be.list("").unwrap().is_empty(),
            "a refused write must leave no residue"
        );
    }

    /// **Proves:** a parent directory the process cannot read makes `exists`
    /// refuse, rather than report absent.
    ///
    /// **Why it matters:** this is the *realistic* vehicle for the same
    /// property — a keystore root whose permissions changed under a running
    /// service. The NUL-key test above proves the branch; this one proves the
    /// branch is reached by a situation that actually happens.
    ///
    /// **Unix only.** Windows has no equivalent portable construction: mode
    /// bits do not apply, and denying access needs an explicit DACL, which
    /// needs Win32 FFI this crate cannot contain (`unsafe_code = "forbid"`,
    /// §13.2 C-15). On Windows this test is not compiled in and the property
    /// rests on the test above. It is exercised by the Linux and macOS CI legs;
    /// a Windows developer cannot run it locally.
    #[cfg(unix)]
    #[test]
    fn exists_refuses_when_the_parent_cannot_be_read() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let root = dir.path().join("locked");
        fs::create_dir(&root).unwrap();
        let be = FileBackend::new(root.clone());
        let key = BackendKey::new("sealed");
        be.write(&key, b"payload").unwrap();

        fs::set_permissions(&root, fs::Permissions::from_mode(0o000)).unwrap();
        let answer = be.exists(&key);
        // Restore before asserting so a failure cannot leave an unremovable dir.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        // Root defeats permission bits entirely, so the fixture cannot make the
        // stat fail there. Rather than skip — which would print `ok` while
        // asserting nothing, and go unfalsifiable on any root CI runner — each
        // environment asserts the outcome it can actually exhibit. Neither
        // branch is vacuous, and neither is `Ok(false)`, which is the answer
        // this method must never give.
        if running_as_root() {
            assert!(
                answer.unwrap(),
                "root can read the directory, so the blob must be reported present"
            );
        } else {
            assert!(
                answer.is_err(),
                "an unreadable parent must refuse, not report the blob absent"
            );
        }
    }

    /// Whether this process can read a `0o000` directory — i.e. is effectively
    /// root. Probed by observation rather than `libc::geteuid`, because the
    /// crate forbids `unsafe` and the observable is the thing we actually care
    /// about.
    #[cfg(unix)]
    fn running_as_root() -> bool {
        use std::os::unix::fs::PermissionsExt;
        let probe = TempDir::new().unwrap();
        let d = probe.path().join("probe");
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o000)).unwrap();
        let readable = fs::read_dir(&d).is_ok();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        readable
    }

    /// **Proves:** `write_new` refuses an existing key with a distinguishable
    /// `AlreadyExists`, and leaves the stored bytes untouched.
    ///
    /// **Why it matters:** a consumer storing two COUPLED records — a wrapped
    /// blob and the device key that opens it — needs to say "I am
    /// *establishing* this, not updating it" (dig-keystore#16). With only
    /// replace-semantics `write`, two concurrent starts settle key `D_B`
    /// beside blob `B_A`, which never self-heals. `create_new` +
    /// adopt-on-`AlreadyExists` makes that state unreachable rather than
    /// unlikely.
    ///
    /// **Catches:** a `write_new` implemented as `exists()` then `write()`,
    /// which would replace the bytes; and one that reports the collision as a
    /// generic I/O error, which a caller cannot adopt on.
    #[test]
    fn write_new_refuses_an_existing_key_without_touching_it() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());
        let key = BackendKey::new("coupled");

        be.write_new(&key, b"established").unwrap();
        let err = be
            .write_new(&key, b"usurper")
            .expect_err("write_new must refuse an established key");

        assert!(
            matches!(err, KeystoreError::AlreadyExists(ref k) if k == "coupled"),
            "the collision must be adoptable, not a generic I/O error: {err:?}"
        );
        assert_eq!(
            be.read(&key).unwrap(),
            b"established",
            "a refused write_new must not replace the established bytes"
        );
    }

    /// **Proves:** `write_new` on an absent key stores bytes `read` recovers,
    /// and the `write` beside it still replaces.
    ///
    /// **Why it matters:** the control for the test above. A `write_new` that
    /// refused unconditionally would satisfy the refusal assertion perfectly
    /// while being useless, and no other test would notice.
    ///
    /// **Catches:** a `write_new` that never writes, writes to a different
    /// path than `write`/`read` use, or that accidentally makes `write`
    /// exclusive too.
    #[test]
    fn write_new_establishes_an_absent_key() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());
        let key = BackendKey::new("fresh");

        be.write_new(&key, b"payload").unwrap();
        assert_eq!(be.read(&key).unwrap(), b"payload");
        be.write(&key, b"replaced").unwrap();
        assert_eq!(be.read(&key).unwrap(), b"replaced");
    }

    /// **Proves:** `FileBackend` claims exclusive `write_new`.
    ///
    /// **Why it matters:** [`Exclusivity`] is what a consumer reads to decide
    /// whether `write_new` can be *relied on* to make a coupled mismatch
    /// unreachable. A backend that overstates it hands back the exact race the
    /// method exists to remove.
    ///
    /// **Catches:** a `FileBackend` that keeps the `Atomic` claim after being
    /// reimplemented as a check-then-write.
    #[test]
    fn file_backend_claims_exclusive_creation() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());
        assert_eq!(be.write_new_exclusivity(), Exclusivity::Atomic);
    }

    /// **Proves:** under contention, exactly ONE `write_new` establishes the key
    /// and every other racer gets `AlreadyExists` — the mechanism behind the
    /// [`Exclusivity::Atomic`] claim, not merely the claim.
    ///
    /// **Why it matters:** `write_new_refuses_an_existing_key_without_touching_it`
    /// above is satisfied identically by a check-then-write, so on its own it
    /// pins a coincidence. The whole value of `write_new` to a consumer with
    /// coupled records is that two concurrent *starts* cannot both establish;
    /// that is a property of concurrency and nothing sequential can observe it.
    ///
    /// **Catches:** a `write_new` reimplemented as `exists()` then `write()`.
    /// Every thread would pass the vacancy check inside the barrier window and
    /// several would report success.
    ///
    /// **One-directional, deliberately.** A correct implementation can *never*
    /// produce two winners, so this test cannot fail spuriously. A broken one
    /// is caught probabilistically — the barrier maximises the overlap, but a
    /// single unlucky scheduling could still serialise the threads. It is a
    /// sound proof of the negative and a strong-but-not-certain detector of the
    /// positive, which is the right way round.
    #[test]
    fn only_one_concurrent_write_new_can_win() {
        use std::sync::{Arc, Barrier};

        const RACERS: usize = 16;

        let dir = TempDir::new().unwrap();
        // Create the root up front so the race is over the blob, not over
        // `ensure_root`, which would serialise the threads before they reach
        // the interesting call.
        let be = Arc::new(FileBackend::new(dir.path().to_path_buf()));
        be.write(&BackendKey::new("warmup"), b"x").unwrap();

        let key = BackendKey::new("contended");
        let gate = Arc::new(Barrier::new(RACERS));

        let winners: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..RACERS)
                .map(|i| {
                    let (be, gate, key) = (Arc::clone(&be), Arc::clone(&gate), key.clone());
                    scope.spawn(move || {
                        // Each racer writes a distinguishable payload, so the
                        // survivor identifies which one won.
                        let payload = [i as u8; 8];
                        gate.wait();
                        be.write_new(&key, &payload).is_ok()
                    })
                })
                .collect();
            // `join` consumes the handle, so map-then-filter rather than
            // `filter(|h| h.join()..)`. `unwrap` is deliberate: a panicking
            // racer must fail this test, not be counted as a loser.
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|won| *won)
                .count()
        });

        assert_eq!(
            winners, 1,
            "exactly one racer may establish a key; {winners} did"
        );
        // The stored bytes are one racer's payload in full — never a blend of
        // two, which is what a torn concurrent write would leave.
        let stored = be.read(&key).unwrap();
        assert_eq!(stored.len(), 8);
        assert!(
            stored.iter().all(|b| *b == stored[0]),
            "the survivor's payload must be intact, not a mix of two writers"
        );
    }

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

    /// **Proves:** `delete` returns `Err` — not `Ok(())` — when the filesystem
    /// could not answer whether the blob is there.
    ///
    /// **Why it matters:** `delete` is this crate's secure-erase path, so its
    /// `Ok(())` is read as *the key material is gone*. `Path::exists()` maps
    /// every error to `false`, so an unreadable parent or a failing mount made
    /// `delete` take the early "already absent" return and report success over a
    /// blob still sitting on disk. That is a false assurance about residual key
    /// material — a lie about custody rather than a loss of it, which is why
    /// this is the lower-severity half of the same defect class as `exists`
    /// (#18/#19), and still not something this crate is willing to say.
    ///
    /// **Catches:** exactly the implementation this replaced —
    /// `if !path.exists() { return Ok(()); }`. Under it this fixture returns
    /// `Ok(())` and the assertion fails.
    ///
    /// **The control is load-bearing:** a `delete` that simply refused
    /// everything would satisfy the first assertion, and would break the
    /// documented idempotence the second one pins.
    #[test]
    fn delete_refuses_rather_than_reporting_success_when_it_cannot_tell() {
        let dir = TempDir::new().unwrap();
        let be = FileBackend::new(dir.path().to_path_buf());

        // Control: a determinable absence is still an idempotent success.
        be.delete(&BackendKey::new("genuinely-absent"))
            .expect("a determinable absence must still delete Ok");

        let err = be
            .delete(&undeterminable_key())
            .expect_err("an unanswerable stat must not be reported as a completed delete");
        assert!(
            matches!(err, KeystoreError::Backend(_)),
            "the refusal must carry the underlying I/O cause"
        );
    }

    /// **Proves:** `list` distinguishes a root that is genuinely absent (a
    /// legitimate empty result) from a root it could not inspect (an error).
    ///
    /// **Why it matters:** a caller enumerating a user's identities acts on an
    /// empty vec — it offers to create a first keystore, or reports "you have no
    /// keys". `Path::exists()` collapsed "there is no root yet" and "I could not
    /// read the root" into the same answer, so a permissions change under a
    /// running service presented as a user with nothing in it.
    ///
    /// **Catches:** exactly the implementation this replaced —
    /// `if !self.root.exists() { return Ok(Vec::new()); }`. Under it the
    /// undeterminable root returns `Ok(vec![])` and the third assertion fails.
    ///
    /// **Both controls are load-bearing**, and they are different from each
    /// other: an absent root must stay `Ok(vec![])` (the legitimate empty this
    /// fix must not turn into an error), and a present, genuinely empty root
    /// must also stay `Ok(vec![])` (so the fix cannot pass by refusing every
    /// root that holds no keys).
    #[test]
    fn list_separates_an_absent_root_from_an_uninspectable_one() {
        let dir = TempDir::new().unwrap();

        // Control 1: root does not exist yet. A legitimate empty.
        let absent_root = FileBackend::new(dir.path().join("not-created-yet"));
        assert!(
            absent_root.list("").unwrap().is_empty(),
            "a root that is genuinely absent must still list as empty"
        );

        // Control 2: root exists and holds no keys. Also a legitimate empty.
        let empty_root = FileBackend::new(dir.path().to_path_buf());
        assert!(
            empty_root.list("").unwrap().is_empty(),
            "an existing empty root must still list as empty"
        );

        // The property: a root that cannot be inspected is not an empty root.
        let unreadable_root = FileBackend::new(PathBuf::from("un\u{0}determinable"));
        let err = unreadable_root
            .list("")
            .expect_err("an uninspectable root must not be reported as holding no keys");
        assert!(
            matches!(err, KeystoreError::Backend(_)),
            "the refusal must carry the underlying I/O cause"
        );
    }

    /// **Proves:** a root whose parent the process cannot read makes both
    /// `delete` and `list` refuse, rather than report a completed delete and an
    /// empty keystore.
    ///
    /// **Why it matters:** this is the *realistic* vehicle for the property the
    /// two tests above prove with an interior-NUL path — a keystore directory
    /// whose permissions changed under a running service. The parent is locked
    /// rather than the root itself, because a `0o000` root still *stats*
    /// successfully from its readable parent; it is the stat that must be made
    /// to fail, not the directory read.
    ///
    /// **Unix only**, for the same reason as
    /// `exists_refuses_when_the_parent_cannot_be_read`: Windows needs an
    /// explicit DACL, which needs Win32 FFI this crate cannot contain
    /// (`unsafe_code = "forbid"`, §13.2 C-15).
    #[cfg(unix)]
    #[test]
    fn delete_and_list_refuse_when_the_root_cannot_be_stat_ed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("locked-parent");
        fs::create_dir(&parent).unwrap();
        let root = parent.join("keys");
        let be = FileBackend::new(root.clone());
        let key = BackendKey::new("sealed");
        be.write(&key, b"payload").unwrap();

        fs::set_permissions(&parent, fs::Permissions::from_mode(0o000)).unwrap();
        let listed = be.list("");
        let deleted = be.delete(&key);
        // Restore before asserting so a failure cannot leave an unremovable dir.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();

        // Root defeats permission bits entirely, so each environment asserts the
        // outcome it can actually exhibit — neither branch is vacuous, and in
        // neither is the answer the silent success this test exists to forbid.
        if running_as_root() {
            assert_eq!(
                listed.unwrap().len(),
                1,
                "root can read the parent, so the blob must be enumerated"
            );
            deleted.expect("root can read the parent, so the delete must complete");
        } else {
            assert!(
                listed.is_err(),
                "an uninspectable root must refuse, not report an empty keystore"
            );
            assert!(
                deleted.is_err(),
                "an uninspectable blob must refuse, not report a completed delete"
            );
        }
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
    /// the unrepairable case — a filesystem where the `chmod` does nothing, a
    /// foreign-owned root where it returns `EPERM`, an immutable attribute.
    /// The *production call sites* therefore cannot reach the refusal on a
    /// mode-honouring filesystem the process owns; the refusal itself is not
    /// unreachable, and
    /// `enforce_owner_only_refuses_a_mode_it_could_not_bring_to_the_floor`
    /// drives it directly.
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

    /// The verify half of chmod-then-verify actually refuses.
    ///
    /// **Property:** when the mode observed after the request is *not*
    /// owner-only, `enforce_owner_only` returns `InsecurePermissions` carrying
    /// the bits it saw — it does not return `Ok` on the strength of the
    /// `chmod` having succeeded.
    ///
    /// **Why this is the load-bearing assertion of the whole change:** the
    /// thesis of 0.9.0 is "verify the outcome, do not trust the request". The
    /// request's own `Result` is discarded on purpose in `enforce_owner_only`;
    /// the refusal below is the entire reason that is safe. Without this test
    /// the fail-closed block can be deleted with a green suite, returning the
    /// crate to the 0.8.x shape — `set_permissions` called and its result
    /// thrown away with nothing observing the bits.
    ///
    /// **Fixture design.** The refusal cannot be provoked through `write`,
    /// whose call sites always request an owner-only mode on a path the
    /// process owns, so a `write`-level fixture would need a mode-ignoring
    /// mount or a second uid — neither available in a test, which is what
    /// previously left this branch untested. The requested mode is a
    /// *parameter*, so asking for a permissive one drives the same verified
    /// read the production path performs, hermetically: no root, no second
    /// uid, no exotic mount. `0o755` is used rather than `0o777` because it
    /// leaves the owner triad at its production value, so the assertion is
    /// about the group and other bits and nothing else.
    ///
    /// **Catches:** deletion of the fail-closed block in `enforce_owner_only`,
    /// and any narrowing of `is_owner_only` reached through it. Asserting the
    /// observed `mode` — not merely that the call erred — also rules out a
    /// refusal that reports the mode it *asked* for instead of the one on
    /// disk, which would make the diagnostic useless on exactly the mount
    /// classes it exists to diagnose.
    #[cfg(unix)]
    #[test]
    fn enforce_owner_only_refuses_a_mode_it_could_not_bring_to_the_floor() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let root = dir.path().join("permissive");
        fs::create_dir_all(&root).unwrap();

        let err = enforce_owner_only(&root, 0o755)
            .expect_err("a mode granting group and other access must be refused, not accepted");

        match err {
            KeystoreError::InsecurePermissions { path, mode } => {
                assert_eq!(mode, 0o755, "the reported mode must be the one on disk");
                assert_eq!(path, root.display().to_string(), "reported path");
            }
            other => panic!("expected InsecurePermissions, got {other:?}"),
        }

        // The refusal describes the state it found, so the mode really is the
        // permissive one — the fixture is not silently owner-only already.
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o755,
            "fixture must remain group/other-accessible, or it proves nothing"
        );
    }

    /// A symlinked root is refused, not followed.
    ///
    /// **Property:** `write` on a root that is a symbolic link returns
    /// `UnsafeRoot` and touches neither the target's mode nor its contents.
    ///
    /// **Why refuse here when a permissive mode is repaired:** a mode is a
    /// property of the intended directory that the backend can correct and
    /// then verify. A symlink is a claim about *which* directory the keystore
    /// is, and no syscall makes an attacker-chosen directory into the intended
    /// one. Both `set_permissions` and `metadata` follow links, so the
    /// alternative is chmodding a directory of someone else's choosing to
    /// `0700` and sealing an account master seed inside it.
    ///
    /// **Catches:** reverting `symlink_metadata` to `exists()`/`metadata()`.
    ///
    /// **The side effects are asserted before the error, deliberately.** Under
    /// that revert the write returns `Ok`, so an `expect_err` placed first
    /// panics and the two assertions that name the actual damage never run —
    /// the proof would fire on "no error" rather than on the primitive. Ordered
    /// this way, the failure a reverting change sees is the chmod reaching
    /// through the link, which is what is new in this diff. The error
    /// assertion still has to be there: a write that failed for some later,
    /// unrelated reason would leave the victim equally untouched.
    #[cfg(unix)]
    #[test]
    fn symlinked_root_is_refused_and_its_target_is_untouched() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let victim = dir.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();

        let root = dir.path().join("keys");
        std::os::unix::fs::symlink(&victim, &root).unwrap();

        let result = FileBackend::new(root.clone()).write(&BackendKey::new("seed"), b"sealed");

        assert_eq!(
            fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o755,
            "the link's target must not be chmodded through the link"
        );
        assert!(
            !victim.join("seed.dks").exists(),
            "the sealed blob must not land in the link's target"
        );
        assert!(
            matches!(result, Err(KeystoreError::UnsafeRoot { .. })),
            "a symlinked root must be refused, got {result:?}"
        );
    }
}
