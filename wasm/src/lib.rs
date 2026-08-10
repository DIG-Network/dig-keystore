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
//! - [`seal`] / [`seal_strong`] / [`open`] / [`verify_password`] — the real
//!   API. Each is a direct, non-branching call into [`dig_keystore::opaque`]
//!   (no wasm-specific crypto logic lives in this crate) — see that module's
//!   docs for the container format and the native↔wasm byte-compatibility
//!   argument.
//! - [`init`] — installs the panic-hook (feature `console-panic-hook`,
//!   default on) so a Rust panic surfaces a real message + stack trace in
//!   the browser/Node console instead of an opaque wasm trap. Call once at
//!   startup; safe to omit.
//!
//! That is the WHOLE export surface, and it is pinned by
//! `wasm/tests/shipped_surface.rs`.
//!
//! # Entropy contract (normative — `SPEC.md` §16.6)
//!
//! Every export above draws its Argon2id salt and AES-GCM nonce inside the
//! wasm module, from `rand_core::OsRng` backed by `getrandom`'s "js" feature
//! (`crypto.getRandomValues`). **No export takes an RNG, a seed, or any
//! entropy from JavaScript**, so a JS caller cannot weaken the sealing of a
//! wallet secret by passing the wrong argument.
//!
//! This crate previously exported `sealWithSeed(password, secret, seed: u64)`
//! — a 64-bit-seeded ChaCha20 at the `FAST_TEST` KDF preset — as a test
//! fixture, one autocomplete keystroke away from [`seal`] on the same module
//! object the extension's offscreen vault holds. It shipped in the published
//! npm package. It is REMOVED (dig_ecosystem #2549), and three independent
//! things now have to be undone to bring it back, each of which fails a build
//! rather than a review:
//!
//! 1. `dig_keystore::opaque::seal_with_rng` is behind the non-default
//!    `test-vectors` feature, which this crate does not enable as a normal
//!    dependency — naming it here is `E0432`/`E0603` under
//!    `wasm-pack build --release`.
//! 2. `rand_chacha` is a DEV-dependency of this crate, so `ChaCha20Rng` is
//!    not nameable in this file at all.
//! 3. `wasm/tests/shipped_surface.rs` pins the exact exported-name set and
//!    scans this file for seeded-RNG tokens.
//!
//! The known-answer vector that `sealWithSeed` existed to serve is unaffected:
//! `wasm/tests/opaque_wasm.rs` now calls `seal_with_rng` DIRECTLY (a dev-only
//! dependency edge), which proves the same cross-target byte identity without
//! a pass-through in the shipped module.
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
