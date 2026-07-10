//! WebAssembly bindings for `dig-keystore`'s opaque secret sealing.
//!
//! dig_ecosystem #147 Phase A: gives browser callers (the DIG Chrome
//! extension's offscreen vault, Phase B — separate, gated) a canonical
//! seal/open/verify-password surface backed by the SAME audited AES-256-GCM +
//! Argon2id implementation every native DIG binary uses, instead of
//! hand-rolling the primitives in JS.
//!
//! # Surface
//!
//! - [`seal`] / [`open`] / [`verify_password`] — the real API. Each is a
//!   direct, non-branching call into [`dig_keystore::opaque`] (no
//!   wasm-specific crypto logic lives in this crate) — see that module's
//!   docs for the container format and the native↔wasm byte-compatibility
//!   argument.
//! - [`seal_with_seed`] — **test/fixture-only.** Seals with a caller-chosen
//!   deterministic seed instead of OS randomness, so a shared known-answer
//!   vector can be asserted identical on both this wasm target and native
//!   `cargo test` (`wasm/tests/opaque_wasm.rs` / `tests/opaque_vectors.rs`).
//!   Predictable RNG — **never use it to seal a real secret.**
//! - [`init`] — installs the panic-hook (feature `console-panic-hook`,
//!   default on) so a Rust panic surfaces a real message + stack trace in
//!   the browser/Node console instead of an opaque wasm trap. Call once at
//!   startup; safe to omit.
//!
//! # Storage backend
//!
//! There is deliberately no `KeychainBackend`/`FileBackend`/`MemoryBackend`
//! surface here — the file and OS-keychain backends are meaningless in a
//! browser (no filesystem, no OS keyring), and even `MemoryBackend` would
//! just add an unnecessary indirection: `seal`/`open` already are
//! bytes-in/bytes-out, so the JS caller owns storage directly (e.g.
//! `chrome.storage.local`) exactly as it does today for its `DIGWX1` records.
//!
//! # Errors
//!
//! `seal`/`open` return `Result<_, JsValue>`; the `JsValue` is always a
//! `TypeError`-free plain string built from the underlying
//! `KeystoreError`'s `Display` (which is proven, at the native crate level,
//! to never contain secret material or the password). `verify_password`
//! never throws — a malformed blob or wrong password both yield `false`.

use dig_keystore::opaque;
use dig_keystore::{KdfParams, Password};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use wasm_bindgen::prelude::*;

/// Install a panic hook that forwards Rust panics to the JS console with a
/// real message instead of an opaque "unreachable executed" trap. Call once
/// at module load; idempotent (subsequent calls are no-ops).
#[wasm_bindgen]
pub fn init() {
    #[cfg(feature = "console-panic-hook")]
    console_error_panic_hook::set_once();
}

/// Seal `secret` under `password`, returning the encoded container bytes.
///
/// Uses [`KdfParams::DEFAULT`] (64 MiB / 3 iterations / 4 lanes — the same
/// default every native DIG keystore file uses) and OS randomness (via
/// `getrandom`'s "js" backend) for the salt + nonce. `secret` may be any
/// length, including empty (e.g., raw BIP-39 entropy of 16-32 bytes, or any
/// other opaque application secret).
#[wasm_bindgen]
pub fn seal(password: &str, secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    opaque::seal(&Password::from(password), secret, KdfParams::DEFAULT)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Open a blob produced by [`seal`], returning the original secret bytes.
///
/// Fails with a thrown error for a wrong password, a tampered/corrupted
/// blob, or a blob that isn't a `dig-keystore` opaque-secret container
/// (e.g., it's a validator/wallet `DIGVK1`/`DIGLW1` keystore file instead).
#[wasm_bindgen]
pub fn open(password: &str, blob: &[u8]) -> Result<Vec<u8>, JsValue> {
    opaque::open(&Password::from(password), blob)
        .map(|secret| secret.to_vec())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// `true` if `password` opens `blob` without exposing the secret. Never
/// throws — a malformed blob or a wrong password both report `false`.
#[wasm_bindgen(js_name = "verifyPassword")]
pub fn verify_password(password: &str, blob: &[u8]) -> bool {
    opaque::verify_password(&Password::from(password), blob)
}

/// Seal `secret` under `password` using the STRONG Argon2id preset (256 MiB /
/// 4 iterations / 4 lanes — [`KdfParams::STRONG`]) instead of [`seal`]'s
/// [`KdfParams::DEFAULT`], for a caller's high-value-secret option (dig_ecosystem
/// #147 Phase B — the extension's `ARGON2_STRONG` wallet preset). Otherwise
/// identical to [`seal`]: OS randomness, any secret length, opened by the same
/// [`open`] (the preset is recorded in the blob's own self-describing header,
/// not tracked by the caller).
#[wasm_bindgen(js_name = "sealStrong")]
pub fn seal_strong(password: &str, secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    opaque::seal(&Password::from(password), secret, KdfParams::STRONG)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// **Test/fixture-only.** Seals `secret` under `password` using a
/// deterministic RNG seeded from `seed`, so the exact output bytes are
/// reproducible. Used exclusively to prove `wasm/tests/opaque_wasm.rs`'s
/// known-answer vector matches `tests/opaque_vectors.rs`'s native vector
/// byte-for-byte (dig_ecosystem #147 Phase A native↔wasm compatibility
/// proof).
///
/// # ⚠️ Never use this for a real secret
///
/// A seeded RNG is trivially predictable — a caller who knows (or can guess)
/// `seed` can derive the exact salt/nonce used, defeating the encryption.
/// Production callers MUST use [`seal`] (OS randomness) instead.
#[wasm_bindgen(js_name = "sealWithSeed")]
pub fn seal_with_seed(password: &str, secret: &[u8], seed: u64) -> Result<Vec<u8>, JsValue> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    opaque::seal_with_rng(
        &Password::from(password),
        secret,
        KdfParams::FAST_TEST,
        &mut rng,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}
