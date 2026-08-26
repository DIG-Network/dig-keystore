# Upgrading

Behaviour changes that need a decision from you on upgrade. `CHANGELOG.md` lists
*what changed*; this file says *what to do about it*.

This file is hand-written. `CHANGELOG.md` is regenerated from Conventional Commits by
git-cliff on every release (`--output CHANGELOG.md`, `release.yml`), so a note added
there by hand is overwritten by the next release; the changelog header links here
instead.

## 0.13.0

### macOS and Linux can now reach the hardware tier — and can now fail closed

`dig-keystore-hardware` 0.2.0 binds the Apple Secure Enclave (on Apple silicon) and the Linux
TPM 2.0. Until now both platforms reported `PlatformUnsupported`, which degrades under every
policy except `Required`, so `bind_strongest` could not fail on them for hardware reasons.

Two consequences to know about:

- **`HardwarePolicy::Required` may now succeed** on those hosts, where it previously always
  refused. That is the point of the change.
- **`HardwarePolicy::Preferred` — the default — may now refuse**, but only where the host
  could not be inspected at all: a TPM that will not answer, that answers unintelligibly, or
  that reports a transient condition such as `TPM_RC_RETRY` or exhausted object memory.
  Nothing is known about such a host, so it fails closed.

  **A host that was inspected and simply has no trusted component this process can use still
  degrades exactly as before**, and that covers every ordinary case: no TPM at all, a TPM
  device node owned by a group this process is not in, an owner hierarchy carrying a password
  this process does not hold (`tpm2_changeauth -c owner`, enterprise imaging, a Windows
  install that took ownership), a TPM in dictionary-attack lockout, and a binary without the
  Secure Enclave entitlement. Those probe `Absent` and open at the software floor.

  The distinction is `SPEC.md` §17.5 / C-46, and it is the difference between a degrade and
  being unable to **load** an existing keystore — the refusal happens when the backend is
  constructed, so it gates opening a keystore, not merely minting one.

**What to do.** Nothing, if you pass `Optional` or accept a degrade. If you rely on
`Preferred` never erroring, handle `HardwareProbeIndeterminate`, or pass `Optional` and read
`backend.tier()` yourself.

An Intel Mac is unchanged: the Secure Enclave binding covers Apple silicon only, because a T2
may or may not be present and nothing in this build can determine which. And the wrap/unwrap
path on both new platforms has been proven by compilation and by the seam tests, **not** on
real silicon — see `SPEC.md` §17.5 for the outstanding evidence.

### `FileBackend::delete` and `::list` now refuse an uninspectable path

Both used `Path::exists()`, which maps **every** error — an unreadable parent, a
failing mount, an I/O fault — to `false`. So `delete` returned `Ok(())` for a blob it
could not stat (a false assurance that key material is gone, from the crate's
secure-erase path), and `list` returned an empty vec for a root it could not read
(indistinguishable, to a caller enumerating identities, from a user who has no keys).

Both now use the same link-preserving stat `exists` has used since 0.11.0: present →
proceed, `NotFound` → the old answer, anything else → `Err`.

**What to do.** If you call either on a path that might be unreadable, handle the new
`Err`. Two behaviours are deliberately unchanged, so most callers need nothing:
`delete` on a genuinely-absent key is still an idempotent `Ok(())`, and `list` on a
root that does not exist yet is still `Ok([])` — a keystore nobody has created is
legitimately empty. Only the *undeterminable* cases changed.

### `Keystore::create` is exclusive under contention on an atomic backend

`create` no longer probes for existence and then writes. It performs a single
`write_new`, so two concurrent mints of the same key on `FileBackend` or
`MemoryBackend` now resolve to exactly one winner, every loser receiving
`AlreadyExists`. Previously both racers observed an absence, both sealed — with an
Argon2id derivation between the check and the write — and the loser's blob replaced
the winner's, leaving the winning caller holding a seed that no longer opens anything.

**What to do.** Nothing, unless you mint concurrently against `OsKeychainBackend`,
whose credential store has no create-if-absent primitive and reports
`Exclusivity::BestEffort`. The residual race there is **not** closed by this change —
`create` still mints, because refusing would make the OS credential store unable to
hold a keystore at all — so serialise the mint yourself. `SPEC.md` §7.1 is normative.

One visible timing change: a mint that collides now pays the Argon2id derivation
before it reports `AlreadyExists`, because the collision is detected by the write
rather than by a pre-check. The error is the same one, at the same call, and this is
the cost of having a single authority on whether the key already existed.

## 0.11.0

### `KeychainBackend` gains a required `write_new`

Any type implementing `KeychainBackend` must now also implement:

```rust
fn write_new(&self, key: &BackendKey, data: &[u8]) -> Result<()>;
```

There is deliberately **no default implementation**. A default composed of `exists`
then `write` would present the create-if-absent contract while providing none of it,
and every backend that forgot to override it would inherit the race silently — which is
exactly the failure this method exists to remove.

**What to do.** If your store offers a create-if-absent primitive, use it and override
`write_new_exclusivity` to return `Exclusivity::Atomic`. If it does not, a vacancy check
followed by a write is a correct implementation; leave `write_new_exclusivity` at its
`BestEffort` default, which is the honest answer. Report a pre-existing record as
`KeystoreError::AlreadyExists(key)` either way, so a losing racer can adopt the winner
rather than only give up.

Every backend shipped by this crate implements it already. No caller of `Keystore`,
`opaque`, or a shipped backend needs any change.

### `FileBackend::exists` now returns `Err` where it used to return `Ok(false)`

Through 0.10.0 the implementation was `Ok(self.path_for(key).exists())`.
`Path::exists()` maps **every** error to `false` — an unreadable parent directory, a
failing mount, an I/O fault — so an inspection failure was reported as a confident
absence.

That answer decides whether to **mint**. `Keystore::create` refuses to overwrite only
because `exists` says the key is there, and `FileBackend::write` replaces, so a spurious
`false` did not create a harmless duplicate beside the original — it **destroyed the
original**. Where the blob is hardware-wrapped (`SPEC.md` §17) the destruction is
unrecoverable, and `HardwareUnwrapFailed` structurally cannot name its own cause
(§17.5b), so the loss is silent as well as permanent.

0.11.0 stats with `symlink_metadata` and preserves the trait's three-valued contract:
present, confidently absent, or **could not determine**.

**What this costs.** Two behaviour changes, both in the fail-closed direction:

- A call that could not determine presence now returns `KeystoreError::Backend` instead
  of `Ok(false)`. A caller that treated `exists` as infallible via `unwrap_or(false)`
  reinstates the old hazard and should be changed to propagate.
- A **dangling symlink** at the key path now counts as **present**. Something occupies
  that name; refusing to write over it is the fail-closed reading. `Path::try_exists()`
  would report it absent, which is why it is not used either.

If you genuinely want the old permissive behaviour for read-only inspection tooling,
call `exists(..).unwrap_or(false)` at that call site explicitly — where it is visible —
rather than having every caller inherit it.

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
