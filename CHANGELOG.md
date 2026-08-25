# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

Behaviour changes that need action on upgrade are recorded in
[docs/UPGRADING.md](docs/UPGRADING.md).


## [0.11.0] - 2026-08-25

### Features
- **backend:** Make an undeterminable read refuse rather than mint, and offer an exclusive create (#17)

## [0.10.0] - 2026-08-24

### Features
- **deps:** Bring chia-bls to the ecosystem 0.36.1 line, and make the derivation KAT able to fail (#15)

## [0.9.0] - 2026-08-21

### Features
- **file-backend:** Enforce the owner-only at-rest floor and CI the platform-gated code (#14)

## [0.8.1] - 2026-08-20

### Bug Fixes
- **ci:** Name this crate, not the one the workflows were copied from (#13)

## [0.8.0] - 2026-08-08

### Refactor
- **custody:** Gate the user-custody API behind a non-default `custody` feature (#12)

## [0.7.0] - 2026-08-05

### Bug Fixes
- **os-keychain:** State the custody posture, drop the unenforceable write guard (#11)

## [0.6.1] - 2026-08-03

### CI
- **publish-npm:** Skip republish when the wasm version already exists (#1917)

## [0.6.0] - 2026-08-01

### Features
- **hardware:** Make hardware binding reversible so losing a TPM cannot strand a seed (#9)

## [0.5.0] - 2026-07-27

### Features
- **hardware:** Bind at-rest key material to the OS hardware trusted component (#8)

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


