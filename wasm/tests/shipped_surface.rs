//! Structural guard on the SHIPPED wasm surface (dig_ecosystem #2549).
//!
//! # The defect class this exists for
//!
//! A predictable wallet seed — or a predictable Argon2id salt / AES-GCM nonce
//! sealing one — is the highest-severity defect a wallet can carry, and it is
//! the one defect class that is INVISIBLE to ordinary testing: output from a
//! 64-bit-seeded ChaCha20 is indistinguishable, by inspection or by any
//! assertion over the bytes, from output from the OS CSPRNG. Milk Sad
//! (CVE-2023-31290), Trust Wallet (CVE-2022-32969) and Profanity all shipped
//! green test suites. Only reading the ENTROPY SOURCE proves anything.
//!
//! This crate previously exported `sealWithSeed(password, secret, seed: u64)`
//! — 64-bit-seeded ChaCha20 at the weakest permitted KDF preset — as an
//! ungated `#[wasm_bindgen]` function in the published
//! `@dignetwork/dig-keystore-wasm` package, sitting one autocomplete entry
//! away from the real `seal` on the same module object the Chrome extension's
//! offscreen vault holds to encrypt BIP-39 wallet entropy.
//!
//! # Why this is a source scan and not a `#[test]` over behaviour
//!
//! There is no runtime observation that separates a sound source from a
//! seeded one, so a behavioural test cannot hold this property (see
//! `opaque_wasm.rs::successive_seals_differ_so_the_salt_and_nonce_are_live`
//! for the one thing behaviour CAN show: a stuck source). The reachability
//! property — "no export of this module lets a caller choose the entropy" —
//! is a property of the SOURCE, so the source is what gets asserted.
//!
//! `src/lib.rs` is a good subject for that in a way most files are not: it is
//! ~110 lines, it is the crate's ENTIRE JS-visible surface, and it contains no
//! conditional compilation at all (asserted below, so the scan cannot be
//! evaded by wrapping code in a `#[cfg(test)]` that ships anyway).
//!
//! # The three layers, and what each one alone would miss
//!
//! 1. `EXPECTED_EXPORTS` pins the exact set of `#[wasm_bindgen]` functions.
//!    Catches a NEW weak export under any name — which a token denylist alone
//!    would miss if it were spelled differently.
//! 2. `FORBIDDEN_TOKENS` denies seeded-RNG spellings in that file. Catches a
//!    weak source smuggled into an EXISTING, already-pinned export — which the
//!    name pin alone would miss.
//! 3. The manifest assertions deny `rand_chacha` (and every other
//!    seeded-RNG crate) in `[dependencies]`, and deny the `test-vectors`
//!    feature on the normal `dig-keystore` edge. This is the layer that makes
//!    layers 1 and 2 hard to REGRESS rather than merely detectable: with both
//!    absent, a reintroduced `sealWithSeed` does not compile under
//!    `wasm-pack build --release`, which is the command that produces the npm
//!    artefact.
//!
//! Layer 3 is the load-bearing one. 1 and 2 are the cheap tripwires that turn
//! a manifest edit into a red test rather than a silent re-opening.

// Reads repo files, so it is a NATIVE test. Compiled away under wasm32 so
// `wasm-pack test --node` and `clippy --target wasm32-unknown-unknown
// --all-targets` both stay happy.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeSet;

/// Every `#[wasm_bindgen]`-exported function this crate may ship, by Rust
/// name. Adding a line here is a deliberate act that shows up in review as a
/// change to the wallet-sealing surface — which is the point.
const EXPECTED_EXPORTS: &[&str] = &["init", "seal", "open", "verify_password", "seal_strong"];

/// Spellings that can only appear in `src/lib.rs` if someone put a
/// caller-controllable or deterministic entropy source into the shipped
/// module. `from_seed` covers `SeedableRng::from_seed`; `seed_from_u64` covers
/// the 64-bit form that shipped; the RNG type names cover the crates that
/// provide them.
const FORBIDDEN_TOKENS: &[&str] = &[
    "seed_from_u64",
    "from_seed",
    "SmallRng",
    "StdRng",
    "ChaCha",
    "rand_chacha",
    "seal_with_rng",
];

/// Crates in `[dependencies]` that would make a seeded RNG NAMEABLE in
/// `src/lib.rs`. `rand_core` is deliberately absent from this list: it is the
/// crate that supplies `OsRng` and the `CryptoRng` bound, and it cannot by
/// itself construct a seeded generator.
const FORBIDDEN_RUNTIME_DEPS: &[&str] = &[
    "rand_chacha",
    "rand_xoshiro",
    "rand_pcg",
    "rand_hc",
    "oorandom",
    "fastrand",
    "nanorand",
];

fn lib_rs() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("wasm/src/lib.rs must be readable")
}

fn manifest() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("wasm/Cargo.toml must be readable")
}

/// Return the `pub fn` name on the first function following each
/// `#[wasm_bindgen…]` attribute.
fn exported_fn_names(src: &str) -> BTreeSet<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut found = BTreeSet::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.trim_start().starts_with("#[wasm_bindgen") {
            continue;
        }
        let name = lines[i + 1..]
            .iter()
            .find_map(|l| l.trim_start().strip_prefix("pub fn "))
            .and_then(|rest| rest.split('(').next())
            .unwrap_or_else(|| {
                panic!("a #[wasm_bindgen] attribute on line {} is not followed by a `pub fn`; the export parser below can no longer see the whole surface", i + 1)
            });
        found.insert(name.trim().to_string());
    }
    found
}

/// Declaration lines of `Cargo.toml`'s `[dependencies]` table — the NORMAL
/// dependency edges a `wasm-pack build --release` compiles against. Stops at
/// the next `[section]`, so `[dev-dependencies]` and the `[target…]` table are
/// excluded.
///
/// Comments are dropped. That is not cosmetic: the manifest deliberately
/// EXPLAINS, in prose right there, why `test-vectors` and `rand_chacha` are
/// absent — so a parser that kept comments would read its own warning as a
/// violation and fail on the correct manifest.
fn normal_dependencies_section(toml: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            inside = t == "[dependencies]";
            continue;
        }
        if !inside || t.starts_with('#') {
            continue;
        }
        // Trailing comment. Dependency values in this manifest never contain
        // " #" inside a quoted string, so cutting at the first occurrence is
        // safe here and keeps the parser dependency-free.
        let code = line.split(" #").next().unwrap_or(line);
        out.push_str(code);
        out.push('\n');
    }
    out
}

/// **Proves:** the set of `#[wasm_bindgen]` exports in `src/lib.rs` is exactly
/// `EXPECTED_EXPORTS` — in particular that `seal_with_seed`/`sealWithSeed` is
/// gone and that no replacement has been added under another name.
///
/// **Why it matters:** the export set IS the attack surface. Every function on
/// that module object is reachable from any script running in the extension's
/// offscreen document, and a wallet-sealing function whose entropy a caller
/// chooses must not be one of them.
///
/// **Catches:** a reintroduced deterministic sealer under ANY name; also any
/// unreviewed widening of the JS surface.
#[test]
fn wasm_export_set_is_exactly_the_pinned_surface() {
    let found = exported_fn_names(&lib_rs());
    let expected: BTreeSet<String> = EXPECTED_EXPORTS.iter().map(|s| s.to_string()).collect();

    // Anti-vacuity: a parser that silently matched nothing would make the
    // set-equality below trivially satisfiable by an EMPTY expected list, and
    // would report PASS on a file it never actually read.
    assert!(
        found.len() >= 5,
        "the export parser found only {} exports — it is no longer reading src/lib.rs correctly, \
         so this whole check is vacuous",
        found.len()
    );

    assert_eq!(
        found, expected,
        "the shipped wasm export surface changed.\n  found:    {found:?}\n  expected: {expected:?}\n\
         If this is deliberate, review it as a change to the WALLET SEALING surface and update \
         EXPECTED_EXPORTS. If it added a function that takes a seed, an RNG, or any caller-supplied \
         entropy, it is dig_ecosystem #2549 re-opening — do not update the list."
    );
}

/// **Proves:** `src/lib.rs` — the whole shipped surface — mentions no seeded
/// or deterministic RNG, and no path to the RNG-parameterised sealing seam.
///
/// **Why it matters:** the export-set pin above cannot see a weak source
/// smuggled INTO an already-approved export (e.g. `seal` growing a
/// `ChaCha20Rng::seed_from_u64` internally). This layer can.
///
/// **Catches:** exactly that, plus a `use rand_chacha::…` added in
/// anticipation of one.
#[test]
fn shipped_wasm_source_names_no_seeded_rng() {
    let src = lib_rs();

    // Anti-vacuity control: the file must actually be the one we think it is.
    // Without this, a read that returned an empty string would pass every
    // "does not contain" assertion below.
    assert!(
        src.contains("pub fn seal(") && src.len() > 2000,
        "src/lib.rs does not look like the wasm binding source ({} bytes) — the scan below \
         would be vacuous",
        src.len()
    );

    // The scan treats the file as 100% shipped code. That is only true if the
    // file has no conditional compilation carving out "test-only" regions, so
    // assert it rather than assume it.
    assert!(
        !src.contains("cfg(test)"),
        "src/lib.rs gained a cfg(test) region. This scan assumes every line of this file ships; \
         a test-only carve-out here would be a place to hide a seeded sealer. Move test code to \
         wasm/tests/ instead."
    );

    // `//!` module docs legitimately DISCUSS the removed export and the tokens
    // below, so scan code lines only.
    let code: String = src
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("#!")
        })
        .collect::<Vec<_>>()
        .join("\n");

    for token in FORBIDDEN_TOKENS {
        assert!(
            !code.contains(token),
            "`{token}` appears in the shipped wasm binding's code. A caller-chosen or \
             deterministic entropy source must not exist in this module (dig_ecosystem #2549). \
             Deterministic known-answer vectors belong in wasm/tests/, which reaches \
             dig_keystore::opaque::seal_with_rng through a DEV-dependency."
        );
    }
}

/// **Proves:** no seeded-RNG crate is a NORMAL dependency of this package, and
/// the normal `dig-keystore` edge does not enable `test-vectors`.
///
/// **Why it matters:** this is the layer that makes the defect
/// non-reintroducible rather than merely detectable. `wasm-pack build
/// --release` — the command `publish-npm.yml` runs to produce the npm tarball
/// — does not unify dev-dependency features. With `rand_chacha` dev-only and
/// `test-vectors` off on the normal edge, a `sealWithSeed`-shaped export fails
/// to COMPILE for the shipped artefact: `E0433` for the RNG type, `E0432` for
/// the sealing seam.
///
/// **Catches:** the manifest edit that would have to precede any
/// reintroduction — which is the earliest point at which this is catchable at
/// all.
#[test]
fn shipped_wasm_manifest_cannot_name_a_seeded_rng() {
    let toml = manifest();
    let deps = normal_dependencies_section(&toml);

    // Anti-vacuity control: prove the section parser found the real
    // `[dependencies]` table. If it returned an empty string (a renamed
    // section, a `dependencies.foo` sub-table form), every assertion below
    // would pass while checking nothing.
    assert!(
        deps.contains("dig-keystore") && deps.contains("wasm-bindgen"),
        "could not locate the [dependencies] table in wasm/Cargo.toml — this check is vacuous.\n\
         parsed section was:\n{deps}"
    );

    for dep in FORBIDDEN_RUNTIME_DEPS {
        assert!(
            !deps.contains(dep),
            "`{dep}` is a NORMAL dependency of dig-keystore-wasm. It must be dev-only: as a \
             normal dependency it becomes nameable in src/lib.rs and a seeded sealer can be \
             written into the shipped module again (dig_ecosystem #2549)."
        );
    }

    assert!(
        !deps.contains("test-vectors"),
        "the normal `dig-keystore` dependency enables `test-vectors`, which exposes \
         opaque::seal_with_rng to the SHIPPED cdylib. That feature belongs on the \
         [dev-dependencies] edge only (dig_ecosystem #2549)."
    );

    // The mirror image: the dev edge MUST still carry them, or the
    // native<->wasm known-answer vector in opaque_wasm.rs silently stops
    // compiling and we would lose the byte-compatibility proof while this
    // file happily reported all-clear.
    assert!(
        toml.contains("[dev-dependencies]")
            && toml.contains(r#"features = ["test-vectors"]"#)
            && toml.contains("rand_chacha"),
        "the dev-dependency edge that lets wasm/tests/opaque_wasm.rs pin the native<->wasm KAT \
         vector is missing. Removing it would make the tests above pass for the wrong reason."
    );
}
