# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.5.0] - 2026-07-27

### Features
- **hardware:** bind at-rest key material to the OS hardware trusted component (#1502)

  Adds the `hardware` module: a `HardwareBoundBackend` decorator that wraps an
  already-sealed keystore blob in an outer `DIGHW1` envelope keyed by a
  non-exportable hardware wrapping key, so a sealed blob copied to another machine
  cannot be opened. The AES-256-GCM + Argon2id file envelope remains the FLOOR and
  the v1 format (`SPEC.md` §3) is byte-for-byte unchanged — any blob without the
  envelope prefix is read back untouched, so every existing keystore keeps opening.

  `ProtectionTier` is total and carries its `DegradeReason` inside the `Software`
  variant, so a degrade can never be reported without its cause nor mistaken for a
  hardware tier. `HardwareProbe` separates a confident `Absent` from an
  `Indeterminate` inspection failure, and the default `Preferred` policy fails
  closed on the latter. A hardware tier is claimed only after a live wrap/unwrap
  self-test and a non-exportable custody check.

  Platform providers are injected through the `HardwareProvider` trait and live
  outside this package (`unsafe_code = "forbid"`, conformance C-15); none ships in
  this release, so a caller passing no provider resolves `Software(NotRequested)`.

  The tier is reported **per blob**, not just per host: `tier()` answers what the
  machine is capable of, while `blob_tier(key)` answers what protects one stored
  key, read from its bytes. They can legitimately disagree — a hardware-capable
  host may hold a keystore written before this feature existed, which the
  passphrase alone protects — so anything a user sees must come from `blob_tier`.
  It fails closed on a blob it cannot fully classify.

  A hardware refusal, a malformed envelope, and an unrecognised hardware class are
  three distinct errors, so `HardwareUnwrapFailed` keeps its documented meaning as
  the cross-machine guarantee.

  New: `SPEC.md` §17 (normative, incl. the envelope byte layout and conformance
  C-17..C-24), golden v1 compatibility fixtures under `tests/fixtures/`.

### Changed
- **`KeystoreError` and the growable `hardware` enums are now `#[non_exhaustive]`**
  (`KeystoreError`, `HardwareKind`, `DegradeReason`, `HardwareProbe`,
  `WrapBehaviour`). Downstream `match`es need a wildcard arm. Taken now because
  this release is already caret-incompatible, so the cost is zero today and every
  later addition is a non-event. `ProtectionTier` is deliberately left exhaustive:
  exactly two outcomes exist and a consumer must handle both.
- **The packaged spec is now the root `SPEC.md`**, not the stale
  `docs/resources/SPEC.md` duplicate. crates.io and docs.rs readers of 0.4.x
  received a spec predating several sections — including, for this release, all of
  §17 — while the rendered docs cited it (§4.2). The duplicate's fate is tracked
  as dig_ecosystem #1695.

## [0.4.1] - 2026-07-20

### Chores
- Npm OIDC trusted publisher + dual LICENSE files (v0.4.1) (#7)

## [0.4.0] - 2026-07-20

### Features
- **backend:** OS-native credential-store backend (OsKeychainBackend) #1024 (#6)

## [0.3.1] - 2026-07-12

### CI
- Add flaky-test management (#489) (#5)

## [0.3.0] - 2026-07-10

### Features
- **wasm:** Add sealStrong export for the STRONG Argon2id preset (#4)

## [0.2.1] - 2026-07-07

### CI
- Publish via npm trusted publishing (OIDC), retire NPM_TOKEN (#3)

## [0.2.0] - 2026-07-06

### Features
- Add opaque secret sealing + dig-keystore-wasm wasm-bindgen binding

## [0.1.3] - 2026-07-06

### Bug Fixes
- **l1-wallet-bls:** Stop double-deriving the master key (#1)

### Testing
- Harden coverage on backend, signer, scheme, password, keystore branches

### CI
- Gate test job on >=80% line coverage via cargo-llvm-cov- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Release automation (git-cliff changelog + tag on merge); publish is manual workflow_dispatch (#230)- Re-arm crates.io auto-publish on version tag (token in org secrets; auto-publish-everything #230)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog

## [0.1.2] - 2026-04-21

### Features
- Expose MemoryBackend unconditionally (v0.1.2)

## [0.1.1] - 2026-04-21

### Features
- Add SignerHandle::expose_secret for HD-wallet consumers (v0.1.1)

## [0.1.0] - 2026-04-21

### Features
- Add keystore

### Bug Fixes
- **publish:** Constrain package contents to avoid 10 MiB crates.io limit

### Chores
- Gate integration tests on `testing` feature + fmt


