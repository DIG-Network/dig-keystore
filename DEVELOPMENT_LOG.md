# dig-keystore — Development Log

Concise, durable realizations from developing this crate. Context, not a change diary.

## OS credential store (`OsKeychainBackend`, feature `os-keychain`)

- **`keyring` is target-gated to Windows/macOS only — never Linux, never wasm.** It lives in a
  `[target.'cfg(any(target_os = "windows", target_os = "macos"))'.dependencies]` table as an
  `optional` dep, and the `os-keychain` feature activates it via `dep:keyring`. Cargo resolves
  `dep:` against a target-only optional dependency correctly: on Linux/wasm the feature is a no-op
  for that dep (verified — `cargo check --target x86_64-unknown-linux-gnu --features os-keychain`
  resolves features with no keyring in the graph; only a missing C cross-linker for `blst` stops a
  full host cross-build). This keeps CI free of dbus/libsecret and keeps the wasm member building.

- **Linux is deliberately excluded as a custody primary, not an oversight.** The kernel keyutils
  session keyring is readable by any same-UID process (no application separation at all — weaker
  even than Windows Credential Manager, which at least encrypts at rest under DPAPI) and is non-persistent
  across reboot/logout — unsafe for custody and would lose the identity on logout. On Linux the
  passphrase-sealed file backend is the correct primary. This rationale is inherited from dig-app's
  original `OsCredentialStore`, which this backend absorbs so the ecosystem keeps one keystore impl.

- **The SEAL is the access-control primitive; the OS credential store is defence-in-depth under it.**
  This is the inverse of the rationale inherited from dig-app, and the inversion matters: the OS
  boundary is far weaker than that rationale assumed. On **Windows** a generic Credential Manager
  entry is DPAPI-protected under the logged-in *user's* key and is readable by **any process running
  as that user** — a per-USER boundary, with no application separation at all, and not even a
  machine-local one: `keyring` writes with `CRED_PERSIST_ENTERPRISE`, so on a domain-joined host
  the credential roams with the user profile. On **macOS** the
  Keychain does apply a per-application ACL, but it is gated by user consent: a same-user process
  triggers an authorization prompt that can be answered "Always Allow", and the trusted-application
  designation rests on a code signature a same-user process can generally overwrite. So an attacker
  running as the user reaches the stored entry on both platforms and gets only ciphertext — which is
  the whole point. Argon2id + AES-256-GCM is what stands between them and the key; treat the
  credential store as a storage location, never as the thing keeping an attacker out.

- **The backend cannot enforce "sealed payloads only" — that is a CALLER obligation (`SPEC.md` §10.5).**
  A `write` guard rejecting non-container payloads was built and removed: `HardwareBoundBackend`
  must write *unwrapped, non-container* bytes through its inner backend on `unbind` and on a failed
  `bind`'s restore, and that restore is best-effort (`let _ = self.inner.write(..)`). With the guard
  in place, a failed `bind` over a pre-migration blob had its restore silently rejected and left the
  store holding a `DIGHW1` envelope the hardware had just proven it could not reopen — unrecoverable
  custody loss, reported only as a wrap error. "Inner backend constrains payload shape" is
  architecturally incompatible with "hardware backend can unbind"; an exemption hook would be a
  public bypass. The obligation is stated in prose and pinned by
  `unbind_returns_a_non_container_payload_through_the_os_keychain_backend` and
  `a_failed_bind_restores_a_legacy_blob_through_the_os_keychain_backend` (C-25/C-26).

- **OS credential stores have no native enumeration.** `list` is powered by a best-effort index
  entry (a reserved account, `__dig_keystore_index__`) holding the live key set. `read`/`write`/
  `delete`/`exists` hit the store directly and are authoritative — index/store drift can only stale a
  `list`, never corrupt a read or write. The `RawStore` inner trait makes all of this testable with
  an in-memory double on every platform; the real OS path is covered by a self-skipping integration
  test (skips where no backend, so it is never flaky).

- **Use `keyring` v3's binary secret API (`get_secret`/`set_secret`), not `get_password`/`set_password`.**
  Keystore blobs are raw ciphertext (`Vec<u8>`); the binary API avoids any textual re-encoding of the
  bytes. (dig-app used the password API because it stored base64 strings; here the value is binary.)

## Hardware binding (0.5.0) — durable realizations

### `unsafe_code = "forbid"` decides the crate boundary, not taste

Real TPM/Secure Enclave binding needs CNG (`NCrypt*`) or Security Framework calls, and the
`windows` crate's bindings are `unsafe fn`. This package pins "no `unsafe` anywhere" as a
spec property (`SPEC.md` §13.2, conformance C-15), so the FFI physically cannot live here.
That is what forces providers into a `hardware/` workspace member behind the
`HardwareProvider` trait — the same reason `wasm/` was split out. Anyone tempted to "just
add a `windows` dependency and cfg it" is proposing to drop C-15.

### TPM 2.0 cannot wrap AES, so the envelope has to be hybrid

A platform-crypto-provider key is asymmetric (RSA/ECC) and bounded by the modulus; a Secure
Enclave key is a P-256 key that never leaves the chip. Neither can be handed a blob to
symmetrically encrypt. Hence: a random 32-byte content key encrypts the blob with AES-256-GCM
in this crate, and the hardware only ever wraps *that key*. This keeps the provider trait to
two 32-byte operations, so each platform binding is a few dozen lines of FFI rather than a
second envelope format, and every platform shares one audited AEAD path.

### Wrapping OUTSIDE the v1 format, not inside it

Extending the v1 header with hardware fields would put the §5.1 compatibility burden inside
the one format that must never move. Wrapping the v1 blob whole and detecting by *prefix*
instead means the v1 bytes are untouched and an existing blob needs no migration — it is
simply not an envelope, so it passes through. The passthrough rule is deliberately stated over
the whole class of non-`DIGHW1` prefixes rather than a whitelist of today's inner magics,
so a future inner format does not silently become unreadable.

### Put the degrade reason INSIDE the variant

The first shape considered was `tier: Tier` plus `degrade_reason: Option<DegradeReason>`. That
is the omission hazard: every consumer check becomes `if let Some(reason)`, which *skips*
rather than fails when the field is absent, and an absent reason reads as "fine". Making it
`ProtectionTier::Software(DegradeReason)` means a degrade is unrepresentable without its
cause. Same reasoning kept the tier total (no `Option<Tier>`, no `Unknown`): a UI must always
be able to get a real answer to "is this hardware-bound?".

### "No hardware" and "could not tell" are different facts

A two-valued probe converts an inspection failure into a confident negative. The consequence
is concrete: a transient probe failure would silently downgrade a TPM-equipped machine to a
software blob that then opens *anywhere*. So `HardwareProbe` is three-valued and the default
`Preferred` policy fails closed on `Indeterminate` while still degrading on a confident
`Absent`. The `Absent` row is what keeps that test honest — without it the test would also
pass against an implementation that simply rejects everything.

### A probe is a claim; only use is proof

Reading a probe and believing it is not a check — it cannot fail, so it would report
`Hardware` on any host where the probe is optimistic or spoofed. Tier resolution therefore
runs a live wrap/unwrap self-test plus a `NonExportable` custody check before claiming a
hardware tier, and rejects six distinct self-inconsistencies (wrap fails, wrap returns the key
verbatim, unwrap fails, unwrap returns a different key, custody is `ProcessMemory`, declared
kind disagrees with probed kind).

### A false green found by reverting, not by reading

The "envelope declaring no wrapped key must be rejected" test passed with its fix reverted.
Cause: zeroing `WRAPPED_LEN` on a real envelope *also* makes the declared total length
disagree with the byte count, so the length check fired first — and the assertion accepted
either error. The assertion was true of the code, on a fixture that could not exhibit the
property. Fix: re-attribute the wrapped-key bytes to the payload so the envelope stays
length-consistent, and assert the one specific error. Lesson: an assertion that accepts a set
of errors cannot prove which guard ran; revert-in-isolation is what surfaces it.

### Fixture sizing comes from the format

Inner-blob fixtures are 105 bytes — the real size of a v1 blob with a 32-byte secret
(`SPEC.md` §3) — not a short synthetic stub, and the golden fixtures are frozen hex produced
by the crate's own sealing path rather than regenerated per run. A regenerating test only
proves the code agrees with itself and would stay green through a change that made every
previously-written file unreadable.

### Cross-machine binding needs two devices

A test with one device in play cannot see a missed binding — it passes against an
implementation that ignores the wrapping key entirely. The fixture uses two devices differing
in exactly one thing (the device key) and keeps the original as an honest control, so a
failure means "the other machine was refused" rather than "nothing works".

### Line coverage certifies happy-path guards it never tested

Six normative guards in the envelope decoder — declared-length agreement,
`payload_len < TAG_SIZE`, `ENV_VERSION`, `CIPHER_ID`, the in-`decode` magic check, and the
self-test's empty-wrap clause — could each be deleted with the **entire suite green**, at
93.4% line coverage. Those lines all execute on the happy path: they run, and nothing
asserted on them. **Coverage measures execution, not verification — a guard is only tested
by an input that makes it FIRE.** Any guard on a success path is invisible to the metric, so
the metric cannot warn you. The only reliable check is to delete the guard and watch a named
test go red.

### Fixing one false green can move the vacuity rather than remove it

Making the `WRAPPED_LEN == 0` fixture length-consistent stopped the length-agreement guard
from masking the empty-key rule — and left the length rule *itself* with no test that would
fail if it were dropped. The vacuity moved one guard over. When a guard is found to be
masking another, test **both**: the one that was hidden, and the one that was hiding it.

### A fixture vocabulary that cannot express the adversary reports every guard as safe

The self-test's "a wrap that returns nothing" clause was unenforceable by the harness,
because `WrapBehaviour` had no variant that returned an empty wrapped key. Adding a naive
one would not have helped either: a device that returns empty *and then fails to unwrap* is
refuted by the round-trip clause instead, leaving the empty-wrap guard still untested. The
variant had to be `EmptyWrapWithRecall` — emits nothing, but remembers the key internally —
so that **only** the empty-wrap clause is violated. Isolating a clause means building a
double that is honest in every respect except the one under test.

### Host capability is not per-key protection

`tier()` answers "what is this machine capable of"; it is not "is this key protected". On a
hardware-capable host, a keystore written before hardware binding existed is still protected
by the passphrase alone and *does* open on another machine. A UI quoting host capability
would claim copy-resistance the key lacks, possibly leading a user to guard the file less
carefully or pick a weaker passphrase. Hence `blob_tier(key)`, answered from the stored
bytes, and a SPEC sentence that names which of the two a user-facing claim may use. §5.1
forces the legacy passthrough, so the fix is never to reject old blobs — it is to describe
them truthfully.

### `#[non_exhaustive]` is nearly free at a caret-incompatible bump, and expensive later

Six error variants and three growable enums (`HardwareKind` is documented append-only) went
out in a `0.x` MINOR that already forces every consumer to bump. Marking them cost nothing
at that moment; skipping it would have guaranteed a second multi-repo cascade the first time
any of them grew. `ProtectionTier` is deliberately left exhaustive — its whole point is that
exactly two outcomes exist and a consumer must handle both, so permitting a wildcard arm
would let the software case be swept into a catch-all.

### `include` decides which spec the world reads

`Cargo.toml`'s `include` packaged `docs/resources/SPEC.md`, a stale duplicate, and not the
root `SPEC.md`. Every crates.io/docs.rs reader would have received a spec with no §17 while
the rendered module docs cited "SPEC.md §17" as if resolvable. If a repo has two copies of
its spec, the packaged one is the one that ships — check `include` whenever a spec section
is added.

## chia-bls 0.26 -> 0.36.1: the derivation is identical, and that had never been proven

The uplift needed no source change at all — `SecretKey::{from_seed, from_bytes,
to_bytes}`, `PublicKey`, `Signature`, `sign` and `verify` are shape-identical
across the two lines. The whole risk was invisible: if EIP-2333 derivation had
moved, every `DIGVK1` keystore already at rest would have silently started
opening onto a *different* identity. Nothing in the crate would have failed;
the keys would just have been the wrong ones.

Only `DIGVK1` is exposed, and the reason is worth keeping: `BlsSigning` derives
through `SecretKey::from_seed`, which *is* EIP-2333, while `L1WalletBls`
reconstructs through `SecretKey::from_bytes`
(`src/custody/scheme/l1_wallet_bls.rs:81-98`) because its stored secret is
already a derived master key. A derivation change cannot reach a scheme that
does not derive. So the KAT that needed blessing was the one on the exposed
scheme — which is also the one that had never been blessed.

The crate had a test for exactly this — `tests/vectors.rs`
`bls_signing_deterministic_pubkey`, whose own doc comment says it catches
"accidental version bumps in `chia-bls` that change EIP-2333 derivation". It
could not: its expected constant still read `_REGENERATE_ME_ON_FIRST_RUN`, and
the test `return`ed success down that branch. A "regenerate on first run" escape
hatch is a test that passes for any value until someone remembers to close it,
and nobody did across nine releases.

So the sequence that makes an uplift like this safe is:

1. **Bless the golden value on the OLD line first.** A value blessed after the
   bump records whatever the new line does and proves nothing.
2. **Prove the KAT is load-bearing by mutating production** — and check the
   failure fires for the *right reason*. The first attempt here mutated both
   `MAGIC` and the derivation at once, and the KAT failed on `UnknownMagic`
   before it ever reached its value comparison. That looked like a passing
   proof and was not one.
3. **Then bump, and require the same value.**

A second test in the same file, `magic_bytes_are_ascii`, declared its own
private `Magic` trait holding `DIGVK1`/`DIGLW1` and asserted those literals
against themselves — never reading `KeyScheme::MAGIC`. Both sides of an
assertion coming from the same place proves only that `==` works.

## `Path::exists()` cannot implement a presence check that decides whether to mint

`FileBackend::exists` was `Ok(self.path_for(key).exists())` from the first release until
0.11.0. It reads as an obvious optimisation over the trait's default — stat instead of
open — and it is wrong in a way that only shows up under a second condition.

`Path::exists()` maps **every** error to `false`. Not just `NotFound`: an unreadable
parent, a failing mount, an I/O fault, a path the OS rejects. So it converts "I could not
tell" into "there is definitely nothing there" — the same two-valued-answer-to-a-
three-valued-question defect the `hardware` module's `HardwareProbe::Absent` vs
`Indeterminate` split exists to avoid, sitting one directory away and unnoticed.

**The second condition is what makes it expensive.** `Keystore::create` calls `exists` to
decide whether to mint, and `FileBackend::write` is replace-semantics tmp+rename. So a
spurious `false` does not produce a harmless duplicate beside the original — it
**overwrites the original**. Adding at-rest protection then converts that from
recoverable to permanent: a hardware-wrapped blob that is overwritten is gone, and
`HardwareUnwrapFailed` (§17.5b) structurally cannot name its own cause, so nobody can even
diagnose it afterwards.

**The generalisable lesson: adding at-rest protection obliges re-auditing every read that
decides whether to MINT.** The sealing change itself is not where the bug is. Sealing
raises the cost of an *already-existing* misread from "duplicate beside a recoverable
original" to "the only copy is gone", without touching the misread. dig-node PR #342 hit
the same shape from the other direction and fixed it structurally — `create_new` plus
adopt-on-`AlreadyExists`, so the bad state is unreachable rather than unlikely — which is
what `write_new` now offers here.

Two things worth keeping:

- **`Path::try_exists()` is honest about errors but still not the right primitive here.**
  It follows symlinks, so a **dangling symlink** at the key path reports `false` and
  invites the overwrite. `symlink_metadata` counts it as present, which is the fail-closed
  reading: something occupies that name.
- **A sequential "refuses an existing key" test does not prove exclusivity.** Measured on
  this branch: replacing `write_new`'s `create_new` with a check-then-write left
  `write_new_refuses_an_existing_key_without_touching_it` **passing**, while the
  16-thread contention test reported **16 winners**. Exclusivity is a property of
  concurrency, and nothing sequential can observe it.

