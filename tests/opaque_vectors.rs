//! Deterministic known-answer test (KAT) for `dig_keystore::opaque`, and the
//! public-API-level roundtrip proof that complements `src/opaque.rs`'s
//! inline unit tests.
//!
//! # Cross-target byte compatibility (dig_ecosystem #147 Phase A)
//!
//! The KAT constants below (seed, password, secret, expected hex) are
//! duplicated verbatim in `wasm/tests/opaque_wasm.rs` (a `wasm-bindgen-test`
//! that calls the wasm binding's `sealWithSeed` test helper with the same
//! seed). Both suites assert the SAME expected hex string. Since
//! `dig-keystore-wasm`'s `sealWithSeed` is a direct, non-branching call into
//! `dig_keystore::opaque::seal_with_rng` (the identical Rust source compiled
//! for `wasm32-unknown-unknown`), agreement here and there is the empirical
//! proof that a blob sealed on one target opens identically on the other —
//! required before Phase B (the extension vault migration) can trust the
//! format across its native-CLI and in-browser-wasm consumers alike.
//!
//! If you intentionally change the KDF/cipher/header wiring, this test WILL
//! fail — update `KAT_HEX` here AND in `wasm/tests/opaque_wasm.rs` together,
//! or the two targets silently drift apart.

use dig_keystore::opaque::{open, seal_with_rng, verify_password};
use dig_keystore::{KdfParams, Password};
// ChaCha20Rng (not `rand::StdRng`) — MUST match `wasm/src/lib.rs`'s
// `seal_with_seed` test helper exactly; see `src/opaque.rs`'s test module for why.
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// MUST match `wasm/tests/opaque_wasm.rs`'s `KAT_SEED`.
const KAT_SEED: u64 = 0x4B_4159_5354_4F52;
/// MUST match `wasm/tests/opaque_wasm.rs`'s `KAT_PASSWORD`.
const KAT_PASSWORD: &str = "opaque-kat-password";
/// MUST match `wasm/tests/opaque_wasm.rs`'s `KAT_SECRET`.
const KAT_SECRET: &[u8] = b"\x00\x01\x02\x03opaque-kat-secret-bytes\xFF\xFE";
/// MUST match `wasm/tests/opaque_wasm.rs`'s `KAT_HEX` — the native↔wasm pin.
const KAT_HEX: &str = "4449474f5031000100040100002000000000010101d2491ad536cec869b6d6174731645eeacabcde0420b2f2a8151f13900000002df6427db43857eb57c6c5606c5ed12abee298cdcdd56313136add9aada0b8cfb523b6fa6480fa8bcdfbdf78e63bbe815355";

/// **Proves:** `opaque::seal_with_rng(KAT_SEED, KAT_PASSWORD, KAT_SECRET,
/// FAST_TEST)` produces exactly `KAT_HEX`, called through the crate's public
/// API surface (`dig_keystore::opaque::*`, not `pub(crate)` internals) —
/// this is what an external consumer (the wasm binding) actually links
/// against.
///
/// **Why it matters:** `src/opaque.rs`'s inline unit test pins the same
/// vector from inside the crate; this integration test pins it from
/// outside, proving the public re-exports (`opaque::seal_with_rng`,
/// `KdfParams`, `Password`) are wired correctly and that the vector is
/// reachable exactly as `dig-keystore-wasm` will reach it.
///
/// **Catches:** a `pub` visibility regression on `opaque::seal_with_rng` /
/// `opaque::MAGIC` / `opaque::SCHEME_ID`, or a KDF/cipher drift.
#[test]
fn kat_vector_stable_via_public_api() {
    let mut rng = ChaCha20Rng::seed_from_u64(KAT_SEED);
    let blob = seal_with_rng(
        &Password::from(KAT_PASSWORD),
        KAT_SECRET,
        KdfParams::FAST_TEST,
        &mut rng,
    )
    .unwrap();
    assert_eq!(hex::encode(&blob), KAT_HEX);
}

/// **Proves:** the pinned KAT blob opens back to the exact original secret
/// under the KAT password, and `verify_password` agrees.
///
/// **Why it matters:** A byte-stable-but-unopenable blob would be useless —
/// this closes the loop from the golden hex fixture back to plaintext,
/// which is the property Phase B's "old blobs still open" migration path
/// depends on.
#[test]
fn kat_vector_opens_to_original_secret() {
    let blob = hex::decode(KAT_HEX).unwrap();
    let password = Password::from(KAT_PASSWORD);
    let recovered = open(&password, &blob).unwrap();
    assert_eq!(&*recovered, KAT_SECRET);
    assert!(verify_password(&password, &blob));
    assert!(!verify_password(&Password::from("not-it"), &blob));
}
