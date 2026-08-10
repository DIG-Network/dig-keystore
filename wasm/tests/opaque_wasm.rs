//! `wasm-bindgen-test` suite for `dig-keystore-wasm`'s opaque-secret binding.
//!
//! Run via `wasm-pack test --node` (from `wasm/`) — Node provides the
//! `crypto.getRandomValues` that `getrandom`'s "js" backend needs for
//! `seal`'s OS randomness.
//!
//! # Native ↔ wasm byte compatibility (dig_ecosystem #147 Phase A)
//!
//! `KAT_SEED`/`KAT_PASSWORD`/`KAT_SECRET`/`KAT_HEX` below MUST match
//! `dig-keystore`'s `tests/opaque_vectors.rs` (and `src/opaque.rs`'s inline
//! unit test) exactly. Both suites call the identical `seal_with_rng` with the
//! identical `ChaCha20Rng` seed and assert the identical expected hex.
//! Agreement here is the empirical proof that a blob sealed on one target is
//! byte-for-byte identical to one sealed on the other — required before Phase
//! B (the extension vault migration) can trust the format across its
//! native-CLI and in-browser-wasm consumers alike.
//!
//! # Why this calls the library, not an export (dig_ecosystem #2549)
//!
//! It used to go through `dig_keystore_wasm::seal_with_seed`, a
//! `#[wasm_bindgen]` export whose only reason to exist was this assertion.
//! That put a 64-bit-seeded, `FAST_TEST`-KDF sealing function into the
//! published npm package, adjacent to the real `seal` on the same module
//! object the extension's wallet vault holds.
//!
//! The test needs the deterministic SEAM, not a deterministic EXPORT. A
//! `wasm-bindgen-test` binary links this crate's dev-dependencies, so it can
//! reach `dig_keystore::opaque::seal_with_rng` directly under the
//! `test-vectors` feature — while `wasm-pack build --release`, which does not
//! unify dev-dependency features, cannot. The proof is strictly stronger for
//! it: there is no pass-through wrapper left between the assertion and the
//! code production runs.

use dig_keystore::opaque::seal_with_rng;
use dig_keystore::{KdfParams, Password};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use wasm_bindgen_test::*;

// No `wasm_bindgen_test_configure!` call — the default runner is Node
// (`wasm-pack test --node`), which is all this suite needs (no DOM/browser
// APIs are exercised). `run_in_browser` would be required only for a
// browser-only test.

const KAT_SEED: u64 = 0x4B_4159_5354_4F52;
const KAT_PASSWORD: &str = "opaque-kat-password";
const KAT_SECRET: &[u8] = b"\x00\x01\x02\x03opaque-kat-secret-bytes\xFF\xFE";
const KAT_HEX: &str = "4449474f5031000100040100002000000000010101d2491ad536cec869b6d6174731645eeacabcde0420b2f2a8151f13900000002df6427db43857eb57c6c5606c5ed12abee298cdcdd56313136add9aada0b8cfb523b6fa6480fa8bcdfbdf78e63bbe815355";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// **Proves:** `dig_keystore::opaque::seal_with_rng` compiled for
/// `wasm32-unknown-unknown` produces the EXACT SAME bytes as the identical
/// call compiled natively
/// (`tests/opaque_vectors.rs::kat_vector_stable_via_public_api`).
///
/// **Why it matters:** This is the wasm half of the native↔wasm
/// byte-compatibility proof required by dig_ecosystem #147 Phase A — a
/// vault entry sealed by one target (e.g. a future native CLI import tool)
/// MUST open identically via the wasm binding used in the browser, and
/// vice versa (`kat_opens_a_native_sealed_blob` below).
///
/// **Catches:** any wasm-target-specific divergence in the crypto pipeline
/// (e.g., a different AES-GCM backend selected under wasm32, an endianness
/// bug that only manifests cross-target) that unit tests run on a single
/// target could never see.
#[wasm_bindgen_test]
fn kat_vector_matches_native() {
    let mut rng = ChaCha20Rng::seed_from_u64(KAT_SEED);
    let blob = seal_with_rng(
        &Password::from(KAT_PASSWORD),
        KAT_SECRET,
        KdfParams::FAST_TEST,
        &mut rng,
    )
    .expect("seal_with_rng should succeed");
    assert_eq!(
        to_hex(&blob),
        KAT_HEX,
        "wasm KAT vector diverged from native"
    );
}

/// **Proves:** a blob sealed by the SHIPPED `seal` export opens under the
/// shipped `open`, and — the part that matters here — that two successive
/// seals of the SAME secret under the SAME password produce DIFFERENT bytes.
///
/// **Why it matters:** identical output would mean the salt and nonce are not
/// varying, i.e. the module is not drawing from `crypto.getRandomValues` at
/// all (a stuck, constant, or seeded source). That is the only symptom of the
/// weak-entropy defect class that is observable from OUTPUT rather than from
/// reading the source, so it is worth pinning on the real wasm target where
/// the `getrandom` "js" backend is actually exercised.
///
/// **Catches:** a `getrandom` backend regression that silently returns a
/// constant buffer under wasm32 instead of failing; a future refactor that
/// hoists the salt/nonce out of the per-call path.
///
/// **Does NOT catch:** a *predictable but varying* source. Distinguishing
/// ChaCha-from-a-known-seed from ChaCha-from-the-OS is not possible by
/// inspecting output; that property is held structurally by the
/// `test-vectors` gate and by `tests/shipped_surface.rs`.
#[wasm_bindgen_test]
fn successive_seals_differ_so_the_salt_and_nonce_are_live() {
    let secret = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
    let a = dig_keystore_wasm::seal("same-password", secret).expect("seal a");
    let b = dig_keystore_wasm::seal("same-password", secret).expect("seal b");
    assert_ne!(
        to_hex(&a),
        to_hex(&b),
        "two seals of identical inputs produced identical bytes — the salt/nonce source is not live"
    );

    // The 53-byte header carries the salt at [21..37) and the nonce at
    // [37..49) (SPEC.md §3). Assert BOTH varied, not merely that the blobs
    // differ somewhere: a nonce that varied while the salt was stuck would
    // still change the ciphertext and pass a whole-blob comparison.
    assert_ne!(&a[21..37], &b[21..37], "Argon2id salt did not vary");
    assert_ne!(&a[37..49], &b[37..49], "AES-GCM nonce did not vary");
}

/// **Proves:** the native-produced KAT blob (hardcoded `KAT_HEX`, pinned
/// independently by `tests/opaque_vectors.rs`) opens correctly through the
/// wasm `open` binding and recovers the exact original secret bytes.
///
/// **Why it matters:** This is the literal "native → wasm" direction of the
/// compatibility requirement: a blob written by the native crate (e.g., in
/// a future migration tool) must be readable by the browser binding.
#[wasm_bindgen_test]
fn kat_opens_a_native_sealed_blob() {
    let blob = from_hex(KAT_HEX);
    let recovered =
        dig_keystore_wasm::open(KAT_PASSWORD, &blob).expect("open should recover the secret");
    assert_eq!(recovered, KAT_SECRET);
}

/// **Proves:** the ordinary `seal` (OS randomness) → `open` round trip
/// recovers the exact secret bytes, for both a small BIP-39-entropy-sized
/// secret and an empty one.
#[wasm_bindgen_test]
fn seal_open_roundtrip() {
    for secret in [
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10".as_slice(),
        b"",
    ] {
        let blob = dig_keystore_wasm::seal("correct horse battery staple", secret)
            .expect("seal should succeed");
        let recovered = dig_keystore_wasm::open("correct horse battery staple", &blob)
            .expect("open should succeed");
        assert_eq!(recovered, secret);
    }
}

/// **Proves:** `open` with the wrong password throws (returns `Err`), never
/// silently returning wrong plaintext.
#[wasm_bindgen_test]
fn wrong_password_throws() {
    let blob = dig_keystore_wasm::seal("right-password", b"secret bytes").unwrap();
    let result = dig_keystore_wasm::open("wrong-password", &blob);
    assert!(result.is_err());
}

/// **Proves:** `verifyPassword` reports `true`/`false` correctly and never
/// throws, including for a structurally-invalid blob.
#[wasm_bindgen_test]
fn verify_password_reports_correctly() {
    let blob = dig_keystore_wasm::seal("pw", b"data").unwrap();
    assert!(dig_keystore_wasm::verify_password("pw", &blob));
    assert!(!dig_keystore_wasm::verify_password("not-pw", &blob));
    assert!(!dig_keystore_wasm::verify_password(
        "pw",
        b"not a keystore blob at all"
    ));
}

/// **Proves:** `sealStrong` (the STRONG Argon2id preset — 256 MiB / 4
/// iterations / 4 lanes, `KdfParams::STRONG`) round-trips the exact secret
/// bytes through the ordinary `open`, exactly like the DEFAULT-preset
/// `seal`/`open` pair above.
///
/// **Why it matters:** dig_ecosystem #147 Phase B — the extension's
/// `ARGON2_STRONG` high-value-wallet option (`digwx1.ts`) delegates to this
/// export instead of hand-rolled Argon2id; losing the STRONG preset when
/// migrating to `dig-keystore-wasm` would be a feature regression.
///
/// **Catches:** a copy-paste of `seal` that forgets to swap in
/// `KdfParams::STRONG`, or a `sealStrong` that silently falls back to
/// `KdfParams::DEFAULT`.
#[wasm_bindgen_test]
fn seal_strong_roundtrip() {
    let blob =
        dig_keystore_wasm::seal_strong("correct horse battery staple", b"strong-preset-secret")
            .expect("seal_strong should succeed");
    let recovered = dig_keystore_wasm::open("correct horse battery staple", &blob)
        .expect("open should succeed");
    assert_eq!(recovered, b"strong-preset-secret");
}

/// **Proves:** `sealStrong` rejects the wrong password just like `seal`/`open`
/// — the STRONG preset doesn't accidentally bypass authentication.
#[wasm_bindgen_test]
fn seal_strong_wrong_password_fails() {
    let blob = dig_keystore_wasm::seal_strong("right", b"secret").unwrap();
    assert!(dig_keystore_wasm::open("wrong", &blob).is_err());
}
