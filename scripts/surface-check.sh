#!/usr/bin/env bash
# Multi-configuration public-surface check for dig-keystore's feature gates.
#
# WHY THIS EXISTS, AND WHY IT IS NOT AN ORDINARY TEST
#
# The `custody` / `hd-derivation` gates are a claim about what a *consumer*
# can NAME. The repo's own test job runs `cargo llvm-cov nextest --all-features`,
# which turns every gate ON — so it structurally cannot observe a broken gate.
# A gate is only proven by compiling a consumer under a configuration where the
# gated item must NOT resolve, and watching that consumer fail.
#
# So this script builds a throwaway probe crate that depends on this repo by
# path, once per feature configuration, and asserts the exact rustc diagnostic:
#
#   - core-only, names one gated symbol   -> MUST fail, E0432 (unresolved import)
#   - core-only, names only core items    -> MUST build   [control]
#   - +custody,  names that same symbol   -> MUST build
#   - +custody,  calls `expose_secret`    -> MUST fail, E0599 (no such method)
#   - +custody,  signs instead            -> MUST build   [control]
#   - +custody,hd-derivation, exposes     -> MUST build
#
# ONE SYMBOL PER PROBE. This is not tidiness, it is the difference between a
# real check and a decorative one. The first draft of this script probed
# `use dig_keystore::{BlsSigning, Keystore};` in a single case. A mutant that
# un-gated ONLY `Keystore` then still produced E0432 — from `BlsSigning`, which
# was still gated — and the case reported PASS while the gate it named was
# broken. A bundled negative fixture can only prove that *at least one* of its
# names is absent, which is not the property. Each gated symbol therefore gets
# its own probe, so removing any single `#[cfg]` turns exactly one case red.
#
# The controls are load-bearing for the mirror-image reason. Without them, a
# typo in the probe, a broken generated manifest, or a missing toolchain would
# make the negative cases "fail" for reasons unrelated to the gate — a false
# kill that looks exactly like a real one. (That is not hypothetical either:
# the control caught an MSYS path bug on the first local run.) Each negative
# case is matched by a positive case differing in ONE thing: the gated name.
#
# Asserting the specific error CODE matters for the same reason. `E0432` means
# the probe compiled far enough to resolve imports and found the name absent;
# any other failure means the probe never reached the property under test.
#
# Requires only a stable toolchain (unlike `cargo public-api`, which needs
# nightly rustdoc JSON that this repo's CI does not install).
#
# Usage: scripts/surface-check.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# On Git Bash / MSYS, `pwd` yields `/c/...`, which cargo resolves against the
# drive root as `C:\c\...` and then cannot find. `cygpath -m` gives the native
# mixed path cargo needs. No-op everywhere else.
if command -v cygpath >/dev/null 2>&1; then
    REPO_ROOT="$(cygpath -m "$REPO_ROOT")"
fi
WORK="$(mktemp -d)"
# One shared target dir across every probe: they share a dependency graph,
# so this turns many cold builds into one.
export CARGO_TARGET_DIR="$WORK/target"
trap 'rm -rf "$WORK"' EXIT

failures=0

# run_case <name> <expect: build|fail> <error-code|-> <features-toml-list> <body> [extra-deps-toml]
run_case() {
    local name="$1" expect="$2" code="$3" features="$4" body="$5" extra_deps="${6:-}"
    local dir="$WORK/probe"
    rm -rf "$dir"
    mkdir -p "$dir/src"

    cat >"$dir/Cargo.toml" <<TOML
[package]
name = "surface-probe"
version = "0.0.0"
edition = "2021"

[workspace]

[dependencies]
dig-keystore = { path = "$REPO_ROOT", default-features = false, features = [$features] }
$extra_deps
TOML
    printf '%s\n' "$body" >"$dir/src/main.rs"

    local out status
    set +e
    out="$(cargo build --manifest-path "$dir/Cargo.toml" 2>&1)"
    status=$?
    set -e

    if [ "$expect" = "build" ]; then
        if [ "$status" -eq 0 ]; then
            echo "PASS  $name (built, as required)"
        else
            echo "FAIL  $name: expected a successful build, got exit $status"
            echo "$out" | sed 's/^/      | /'
            failures=$((failures + 1))
        fi
        return
    fi

    if [ "$status" -eq 0 ]; then
        echo "FAIL  $name: expected compilation to FAIL ($code) but it succeeded."
        echo "      The feature gate is not holding: the item is nameable in this configuration."
        failures=$((failures + 1))
    elif echo "$out" | grep -q "$code"; then
        echo "PASS  $name (failed with $code, as required)"
    else
        # Failed, but not for the reason under test — treat as a broken probe,
        # never as a kill.
        echo "FAIL  $name: compilation failed, but WITHOUT $code."
        echo "      The probe did not reach the property under test."
        echo "$out" | sed 's/^/      | /'
        failures=$((failures + 1))
    fi
}

CORE_ONLY_BODY='fn main() {
    // Core surface only: opaque sealing needs no custody types.
    let pw = dig_keystore::Password::from("pw");
    let blob = dig_keystore::opaque::seal(&pw, b"secret", dig_keystore::KdfParams::default())
        .expect("seal");
    assert!(dig_keystore::opaque::verify_password(&pw, &blob));
}'

# Every symbol the `custody` feature gates at the crate root. Merely importing
# one is enough: an unused import is a warning, so the probe builds iff the name
# resolves. Keep this list in sync with the `#[cfg(feature = "custody")]`
# re-exports in `src/lib.rs` — a symbol missing from here is a symbol whose gate
# nothing checks.
CUSTODY_SYMBOLS="Keystore SignerHandle BlsSigning KeyScheme L1WalletBls scheme"

names_one() {
    printf 'use dig_keystore::%s;
fn main() {}
' "$1"
}

SIGNS_BODY='use dig_keystore::{BlsSigning, SignerHandle};
fn take(h: &SignerHandle<BlsSigning>) {
    let _ = h.sign(b"msg");
}
fn main() {
    let _ = take;
}'

EXPOSES_BODY='use dig_keystore::{BlsSigning, SignerHandle};
fn take(h: &SignerHandle<BlsSigning>) -> usize {
    h.expose_secret().len()
}
fn main() {
    let _ = take;
}'

# ---------------------------------------------------------------------------
# Entropy-source gate (dig_ecosystem #2549)
#
# `opaque::seal` hard-wires the OS CSPRNG. `opaque::seal_with_rng` lets the
# CALLER supply the RNG, and therefore the Argon2id salt and the AES-GCM nonce
# — the Milk Sad / Trust Wallet defect class (CVE-2023-31290, CVE-2022-32969),
# which no test over the OUTPUT can detect because a seeded-ChaCha20 blob is
# indistinguishable from a sound one.
#
# So the defence has to be reachability, and reachability is what these cases
# prove: a consumer on the default surface cannot NAME the RNG-parameterised
# seam. Same one-symbol-per-probe + matched-control discipline as the custody
# cases above.
#
# The bound case is a SECOND, weaker line and is labelled honestly. `R: RngCore
# + CryptoRng` makes `SmallRng` a type error, which is worth pinning because it
# is the shape the rest of the ecosystem copies — but it does NOT reject
# `ChaCha20Rng::seed_from_u64(n)`, which satisfies `CryptoRng` on 64 bits of
# entropy. Seed PROVENANCE is not expressible in the type system. The feature
# gate is what protects production; the bound is what stops an outright
# non-cryptographic generator.
# ---------------------------------------------------------------------------

NAMES_SEAL_WITH_RNG='use dig_keystore::opaque::seal_with_rng;
fn main() {}'

NAMES_SEAL='use dig_keystore::opaque::seal;
fn main() {}'

RAND_DEP='rand = { version = "0.8", features = ["small_rng"] }
rand_core = "0.6"'

# Non-CSPRNG at the seam: must be rejected by `R: RngCore + CryptoRng` (E0277,
# unsatisfied trait bound) — NOT by name resolution, which is why the feature
# is enabled here.
SMALL_RNG_BODY='use dig_keystore::{KdfParams, Password};
use rand::rngs::SmallRng;
use rand::SeedableRng;
fn main() {
    let mut rng = SmallRng::seed_from_u64(1);
    let _ = dig_keystore::opaque::seal_with_rng(&Password::from("pw"), b"s", KdfParams::default(), &mut rng);
}'

# The matched control: identical call shape, CSPRNG source. Without it, a typo
# in the probe above would look exactly like the bound doing its job.
OS_RNG_BODY='use dig_keystore::{KdfParams, Password};
fn main() {
    let _ = dig_keystore::opaque::seal_with_rng(&Password::from("pw"), b"s", KdfParams::default(), &mut rand_core::OsRng);
}'

echo "dig-keystore public-surface check (repo: $REPO_ROOT)"
echo

run_case "core-only control: core surface builds" build - '"file-backend"' "$CORE_ONLY_BODY"

for sym in $CUSTODY_SYMBOLS; do
    body="$(names_one "$sym")"
    run_case "core-only cannot name $sym" fail E0432 '"file-backend"' "$body"
    run_case "custody can name $sym" build - '"file-backend", "custody"' "$body"
done

run_case "custody control: sign() builds" build - '"file-backend", "custody"' "$SIGNS_BODY"
run_case "custody alone cannot call expose_secret" fail E0599 '"file-backend", "custody"' "$EXPOSES_BODY"
run_case "hd-derivation can call expose_secret" build - '"file-backend", "custody", "hd-derivation"' "$EXPOSES_BODY"

echo
echo "-- entropy-source gate (dig_ecosystem #2549) --"

run_case "entropy control: default surface can name opaque::seal" \
    build - '"file-backend"' "$NAMES_SEAL"
run_case "default surface CANNOT name opaque::seal_with_rng" \
    fail E0432 '"file-backend"' "$NAMES_SEAL_WITH_RNG"
run_case "test-vectors CAN name opaque::seal_with_rng" \
    build - '"file-backend", "test-vectors"' "$NAMES_SEAL_WITH_RNG"

run_case "entropy control: OsRng satisfies the seam's RNG bound" \
    build - '"file-backend", "test-vectors"' "$OS_RNG_BODY" "$RAND_DEP"
run_case "non-CryptoRng (SmallRng) is rejected at the seam" \
    fail E0277 '"file-backend", "test-vectors"' "$SMALL_RNG_BODY" "$RAND_DEP"

echo
if [ "$failures" -ne 0 ]; then
    echo "$failures surface check(s) FAILED."
    exit 1
fi
echo "All surface checks passed."
