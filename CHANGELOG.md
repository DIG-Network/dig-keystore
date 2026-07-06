# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

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


