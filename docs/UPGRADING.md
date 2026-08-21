# Upgrading

Behaviour changes that need a decision from you on upgrade. `CHANGELOG.md` lists
*what changed*; this file says *what to do about it*.

This file is hand-written. `CHANGELOG.md` is regenerated from Conventional Commits by
git-cliff on every release (`--output CHANGELOG.md`, `release.yml`), so a note added
there by hand is overwritten by the next release; the changelog header links here
instead.

## 0.9.0

### `FileBackend::write` now refuses a root whose permissions it cannot verify

`FileBackend` has always *requested* mode `0700` on its root directory and `0600` on
every blob. Through 0.8.1 it discarded the result of that request, so on a filesystem
that does not implement POSIX modes the `chmod` reported success, changed nothing, and
the write returned `Ok` over sealed key material that was group- and world-readable.

0.9.0 re-reads the mode and fails with `KeystoreError::InsecurePermissions` when any
group or other bit survives — **before any ciphertext is written**, so no blob is left
behind.

**What this costs.** A write that previously succeeded on a mode-ignoring filesystem
now fails. Measured: a root on WSL2 `/mnt/c` (drvfs) reports mode `0777` before and
after the `chmod`, and `write` returns
`InsecurePermissions { mode: 511 }` where 0.8.1 returned `Ok(())`.

The affected mount classes are the ones that do not carry POSIX modes:

- WSL2 `drvfs` (`/mnt/c` and any other Windows drive)
- CIFS/SMB, including a macOS or Linux client mounting an SMB share
- FAT32 / exFAT, including most removable media
- NFS exported without POSIX mode semantics
- Docker and Podman bind mounts backed by a Windows or macOS host filesystem

Unaffected: every native Unix filesystem (ext4, xfs, btrfs, APFS, ZFS), and Windows
hosts, where the enforcement is a documented no-op (`SPEC.md` §10.3).

**What to do.** Place the keystore root on a filesystem that honours POSIX modes. The
error message names this remedy, and the failure is deliberate rather than
conservative: the alternative is a keystore that reports success while leaving an
account master seed readable by every account on the machine. Permissions are defence
in depth here — the blob is sealed with AES-256-GCM under an Argon2id-hardened key —
but a backend whose own documented guarantee is a falsehood is worse than one that
says so loudly.

### `FileBackend::write` now refuses a symlinked root

A root that is a symbolic link, or that exists as something other than a directory,
fails with the new `KeystoreError::UnsafeRoot` instead of being followed. Through
0.8.1 the link was followed for the write; 0.9.0 would additionally have applied
`chmod 0700` to its target, so this is refused rather than repaired — see `SPEC.md`
§10.3 for why a mode is repaired and a symlink is not.

**What to do.** If you intended the link's target as your keystore root, pass the
resolved path, so that choice is explicit at the call site.

### `KeystoreError` has two new variants

`InsecurePermissions` and `UnsafeRoot`. `KeystoreError` is `#[non_exhaustive]`, so an
exhaustive `match` on it already required a wildcard arm and does not break.
