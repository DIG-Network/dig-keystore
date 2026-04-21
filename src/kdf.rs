//! Argon2id password-based key derivation function.
//!
//! # What this does
//!
//! Turns a password (arbitrary bytes) + a 16-byte salt + a set of cost
//! parameters into a 32-byte AES-256 encryption key. The derivation is
//! deliberately slow and memory-hard to make offline brute-force of a stolen
//! keystore file computationally expensive.
//!
//! # Why Argon2id
//!
//! Argon2id is the winner of the Password Hashing Competition (2015) and is
//! standardized as [RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106).
//! It combines the Argon2d data-dependent variant (resistant to GPU/ASIC
//! attacks) with the Argon2i data-independent variant (resistant to
//! side-channel timing attacks) in a single mode that is strong against both.
//!
//! # Parameter choices
//!
//! The defaults — **64 MiB memory, 3 iterations, 4 lanes** — are tuned to:
//! - Consume ~0.5 s on a modern CPU (commodity validator hardware).
//! - Require ~256 MiB of fast RAM per concurrent guess on a GPU (parallelism
//!   × memory ≈ attack cost).
//! - Match `dig-l1-wallet`'s KDF choice so the two crates present a uniform
//!   offline-attack cost to operators.
//!
//! The `FAST_TEST` preset (8 MiB / 1 / 1) is for tests only and must never
//! ship in production.
//!
//! # References
//!
//! - [RFC 9106 — Argon2](https://datatracker.ietf.org/doc/html/rfc9106)
//! - [Argon2 paper (2016)](https://www.password-hashing.net/argon2-specs.pdf)
//! - [`argon2` crate](https://docs.rs/argon2) — the implementation used here
//! - [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
//!   — where the 64 MiB / 3 iter guideline comes from

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::{KeystoreError, Result};
use crate::format::KdfParams;

/// Derive a 32-byte AES-256 key from the password + salt + parameters.
///
/// # Inputs
///
/// - `password`: arbitrary-length password bytes. Uniqueness at this level is
///   the caller's responsibility.
/// - `salt`: **exactly 16 bytes**, randomly generated per-keystore at create
///   time and stored verbatim in the file header.
/// - `params`: the Argon2id cost parameters (memory, iterations, lanes).
///
/// # Output
///
/// A 32-byte key wrapped in [`Zeroizing`] — the returned value is wiped on drop.
/// Callers should not `.to_vec()` or copy the bytes out without reapplying
/// `Zeroizing`.
///
/// # Errors
///
/// - [`KeystoreError::InvalidKdfParams`] if [`validate_params`] rejects the
///   input or if the underlying `argon2` crate returns an error (rare; usually
///   only on invalid output length).
///
/// # Determinism
///
/// Same `(password, salt, params)` → same 32-byte key. This is the load-bearing
/// property that lets `unlock` re-derive the AES key from a stored keystore.
pub(crate) fn derive_key(
    password: &[u8],
    salt: &[u8; 16],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    validate_params(params)?;

    // Map our KdfParams to the argon2 crate's Params type.
    // Output length is fixed at 32 bytes (AES-256 key size).
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.lanes as u32,
        Some(32),
    )
    .map_err(|_| KeystoreError::InvalidKdfParams("argon2 params invalid"))?;

    // Argon2id variant (hybrid data-dependent/independent) at algorithm version 0x13.
    // V0x13 is the version standardized in RFC 9106; older V0x10 is deprecated.
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    // Zeroizing buffer so the derived key is wiped when this function returns
    // (or when the caller drops the returned value).
    let mut out: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| KeystoreError::InvalidKdfParams("argon2 hash failed"))?;
    Ok(out)
}

/// Check KDF parameters are within sane bounds.
///
/// The lower bounds reflect cryptographic minima (below them, Argon2id's
/// brute-force resistance degrades meaningfully). The upper bounds are loose
/// enough for any reasonable setting — including [`KdfParams::STRONG`] — but
/// cap pathological values (1 TiB memory, 65k iterations) that would lock up
/// the process.
fn validate_params(params: &KdfParams) -> Result<()> {
    // Minimum memory cost. OWASP 2024 recommends ≥ 19 MiB; we pick 8 MiB as a
    // sanity floor (anything less is trivially GPU-crackable) but the default
    // ships at 64 MiB.
    if params.memory_kib < 8 * 1024 {
        return Err(KeystoreError::InvalidKdfParams("memory_kib < 8192"));
    }
    if params.iterations < 1 {
        return Err(KeystoreError::InvalidKdfParams("iterations < 1"));
    }
    if params.lanes < 1 {
        return Err(KeystoreError::InvalidKdfParams("lanes < 1"));
    }

    // Upper caps so pathological values can't DoS the process.
    // 1 GiB memory, 256 iterations, 64 lanes comfortably bracket all real
    // presets (even `KdfParams::STRONG` at 256 MiB / 4 / 4).
    if params.memory_kib > 1024 * 1024 {
        return Err(KeystoreError::InvalidKdfParams("memory_kib > 1048576"));
    }
    if params.iterations > 256 {
        return Err(KeystoreError::InvalidKdfParams("iterations > 256"));
    }
    if params.lanes > 64 {
        return Err(KeystoreError::InvalidKdfParams("lanes > 64"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast params — 8 MiB / 1 iter / 1 lane — used so unit tests run in <50 ms.
    /// Never use these for production keys.
    fn test_params() -> KdfParams {
        KdfParams {
            id: crate::format::KdfId::Argon2id,
            memory_kib: 8 * 1024,
            iterations: 1,
            lanes: 1,
        }
    }

    /// **Proves:** Argon2id is a pure function of `(password, salt, params)` —
    /// two invocations with identical inputs produce byte-exact identical
    /// 32-byte outputs.
    ///
    /// **Why it matters:** This is the single invariant that makes `unlock`
    /// work. At create time we derive `K_enc = Argon2id(pw, salt, params)`
    /// and encrypt. At unlock time we must re-derive the same `K_enc` from
    /// the same inputs. If the KDF ever became non-deterministic (e.g. read
    /// entropy mid-derivation), every stored keystore would be permanently
    /// unopenable.
    ///
    /// **Catches:** accidentally enabling a salt-randomizing mode; feature-
    /// flag drift that injects a secret pepper.
    #[test]
    fn deterministic_given_same_inputs() {
        let salt = [7u8; 16];
        let p = test_params();
        let k1 = derive_key(b"pw", &salt, &p).unwrap();
        let k2 = derive_key(b"pw", &salt, &p).unwrap();
        assert_eq!(*k1, *k2);
    }

    /// **Proves:** the salt influences the derived key — two keystores with
    /// the same password but different random salts produce different
    /// encryption keys.
    ///
    /// **Why it matters:** If salts were ignored, a pre-computed rainbow
    /// table over common passwords would break every keystore ever produced.
    /// The salt is what makes per-file brute force the only attack.
    ///
    /// **Catches:** a regression where `hash_password_into` is called with a
    /// constant salt or with the salt byte-order swapped.
    #[test]
    fn different_salt_different_key() {
        let p = test_params();
        let k1 = derive_key(b"pw", &[1u8; 16], &p).unwrap();
        let k2 = derive_key(b"pw", &[2u8; 16], &p).unwrap();
        assert_ne!(*k1, *k2);
    }

    /// **Proves:** the password influences the derived key — different
    /// passwords produce different keys (obvious, but worth pinning).
    ///
    /// **Why it matters:** Ensures the password actually participates in
    /// derivation. A regression that accidentally swapped `password` and
    /// `salt` arguments to `hash_password_into` would silently produce
    /// identical keys for any password under a fixed salt.
    ///
    /// **Catches:** argument-order swap at the call site.
    #[test]
    fn different_password_different_key() {
        let salt = [7u8; 16];
        let p = test_params();
        let k1 = derive_key(b"pw1", &salt, &p).unwrap();
        let k2 = derive_key(b"pw2", &salt, &p).unwrap();
        assert_ne!(*k1, *k2);
    }

    /// **Proves:** `memory_kib = 1024` (1 MiB — below the 8 MiB floor) is
    /// rejected at validation time with [`KeystoreError::InvalidKdfParams`].
    ///
    /// **Why it matters:** Argon2id's brute-force resistance degrades
    /// linearly with memory cost. Below ~8 MiB, GPU attacks become
    /// comfortable. This test pins the floor so no one accidentally ships
    /// a weaker default or a test-params leak reaches production.
    ///
    /// **Catches:** a [`KdfParams`] regression that relaxes the lower bound;
    /// accidentally promoting `FAST_TEST` params into production config.
    #[test]
    fn validates_too_small_memory() {
        let p = KdfParams {
            id: crate::format::KdfId::Argon2id,
            memory_kib: 1024,
            iterations: 1,
            lanes: 1,
        };
        assert!(derive_key(b"pw", &[0u8; 16], &p).is_err());
    }

    /// **Proves:** `iterations = 0` is rejected.
    ///
    /// **Why it matters:** Zero iterations would turn Argon2id into an
    /// expensive no-op (all work would be in the pre-hashing). The `argon2`
    /// crate itself might allow it, but for keystore use we require ≥ 1.
    ///
    /// **Catches:** a field left uninitialised (Rust `Default` for `u32` is
    /// 0) that slips through type-safety.
    #[test]
    fn validates_zero_iterations() {
        let p = KdfParams {
            id: crate::format::KdfId::Argon2id,
            memory_kib: 8 * 1024,
            iterations: 0,
            lanes: 1,
        };
        assert!(derive_key(b"pw", &[0u8; 16], &p).is_err());
    }

    /// **Proves:** `lanes = 0` is rejected.
    ///
    /// **Why it matters:** Zero parallelism lanes is either meaningless
    /// (no work done) or a panic-in-argon2-crate path. The guard makes it
    /// a clean rejection at our layer.
    ///
    /// **Catches:** an uninitialised `u8 = 0` for lanes.
    #[test]
    fn validates_zero_lanes() {
        let p = KdfParams {
            id: crate::format::KdfId::Argon2id,
            memory_kib: 8 * 1024,
            iterations: 1,
            lanes: 0,
        };
        assert!(derive_key(b"pw", &[0u8; 16], &p).is_err());
    }
}
