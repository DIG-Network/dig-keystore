# Contributing to dig-keystore

Thanks for your interest in improving dig-keystore. This is a security-sensitive
encrypted secret-key storage library for DIG Network binaries — please read this
before opening a PR.

## Prerequisites

- [Rust](https://rustup.rs) **1.70 or later** (MSRV; no pinned toolchain required)
- The crate depends on [`chia-bls`](https://crates.io/crates/chia-bls) for BLS12-381 key operations
- No special build-order prereqs; all dependencies are published crates

## Build & test

```sh
# build the whole workspace
cargo build --workspace

# run the full test suite
cargo test --workspace --all-features
```

The workspace includes the core library, the `dig-keystore-hardware` platform-specific module, and the `dig-keystore-wasm` guest. All are tested together by default.

## The gate (must pass before a PR is merged)

CI runs these on every PR (`.github/workflows/publish.yml`); run them locally first:

```sh
# Check formatting
cargo fmt --all -- --check

# Lint all configurations
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --no-default-features --features file-backend,testing --all-targets -- -D warnings
cargo clippy --no-default-features --features file-backend,testing,custody --all-targets -- -D warnings

# Run tests with coverage (gate ≥80% line coverage)
cargo llvm-cov nextest --all-features --test-threads=1 --fail-under-lines 80

# Platform-specific code (runs on actual Windows/macOS in CI; ubuntu skips these)
cargo clippy -p dig-keystore-hardware --all-targets -- -D warnings
```

The workspace gates multiple feature combinations to prevent bitrot in optional surfaces (custody, OS keychain backends, hardware integration). All configurations must compile and pass lints.

## Commit conventions

- Use clear, imperative commit subjects with Conventional Commits format:
  `type(scope): summary`, where `type` ∈ `feat|fix|docs|style|refactor|perf|test|build|ci|chore`.
- Keep one logical change per commit where practical.
- End every commit with a `Co-Authored-By: Claude <noreply@anthropic.com>` trailer if Claude helped author it.

## Where things live

| Module | Responsibility |
|---|---|
| `src/` (root) | Core opaque sealing, format types, KDF/cipher config, backend trait |
| `src/backend/` | Storage backends (file, memory, OS keychain) |
| `src/scheme/` | Custody key schemes (BLS signing, L1 wallet) |
| `src/opaque/` | Low-level seal/open (arbitrary-length secrets) |
| `dig-keystore-hardware/` | Platform-specific hardware wallet tiers (degrade ladder) |
| `dig-keystore-wasm/` | WebAssembly binding (guest) |
| `docs/resources/SPEC.md` | Normative format spec, error semantics, security properties |

## Security

For anything security-relevant, read `docs/resources/SPEC.md` first — it documents the crypto composition, key derivation parameters, format versioning, and backwards-compatibility guardrails. The repo also tracks the DIG Network security model at https://github.com/DIG-Network/dig_ecosystem — file vulnerability reports privately to the maintainer rather than opening a public issue.

## Pull requests

1. Branch from `main`.
2. Make the gate green locally (all clippy configurations, coverage ≥80%, format check).
3. Bump the version in `Cargo.toml` (patch for docs-only, minor for new capability, major for breaking changes).
4. Open a PR with a clear description of the change and its rationale; reference any related issue. Keep the diff focused.
5. All required checks must pass before merge; no force-pushing to `main`.
