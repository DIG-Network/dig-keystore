//! Opaque secret sealing — password-encrypts arbitrary-length secret bytes.
//!
//! # Why this exists (separate from `Keystore<K>`)
//!
//! The typed `Keystore<K>` container is generic over a `KeyScheme`, which
//! pins a *fixed* `SECRET_LEN` and derives a typed public key from the
//! secret. That fits validator/wallet seeds (32
//! bytes, always) but not every caller: a browser vault sealing BIP-39
//! entropy (16/20/24/28/32 bytes depending on word count) or any other
//! opaque application secret has no fixed length and no public-key concept
//! at all — it just wants "encrypt these bytes under this password, get them
//! back later."
//!
//! `opaque` provides that: the SAME on-disk container (§3 of `SPEC.md` —
//! 53-byte header, AES-256-GCM ciphertext+tag, trailing CRC-32, Argon2id KDF)
//! used by every typed `Keystore<K>` file, but for a secret of **any**
//! byte length, addressed by bytes-in/bytes-out rather than a
//! [`crate::backend::KeychainBackend`] path. This is the primitive the
//! `dig-keystore-wasm` binding (dig_ecosystem #147 Phase A) wraps so browser
//! callers (the DIG Chrome extension's vault) can seal/open secret material
//! under one canonical, audited implementation instead of hand-rolling
//! AES-GCM + Argon2id in JS.
//!
//! # Format identity
//!
//! A blob produced by [`seal`] is byte-for-byte a valid keystore file: same
//! header layout, same AAD binding, same CRC coverage. The only thing that
//! makes it "opaque" is the magic ([`MAGIC`] = `DIGOP1`) and scheme id
//! ([`SCHEME_ID`] = `0x0004`), which mark it as "no typed scheme — arbitrary
//! bytes" rather than `DIGVK1`/`DIGLW1`. `crate::format::is_known_magic`
//! recognizes it; nothing about `DIGVK1`/`DIGLW1` decoding changes.
//!
//! # Native ↔ wasm byte compatibility
//!
//! `dig-keystore-wasm`'s `seal`/`open` exports are direct, non-branching
//! calls into [`seal`]/[`open`] below — the identical Rust source compiled
//! for `wasm32-unknown-unknown`. There is no `cfg(target_arch)` fork in this
//! module, so a blob sealed on one target opens identically on the other.
//! `tests/opaque_vectors.rs` (native) and `wasm/tests/opaque_wasm.rs` (wasm)
//! share one deterministic known-answer vector as an empirical pin of this
//! property, in addition to the structural argument above.
//!
//! # Entropy contract (normative — `SPEC.md` §15.5)
//!
//! Every salt and nonce this module writes comes from the OPERATING SYSTEM's
//! CSPRNG. [`seal`] is the ONLY sealing entry point an ordinary consumer can
//! name, and it hard-wires [`rand_core::OsRng`]; there is no parameter, env
//! var, or feature on the default surface that can substitute a different
//! source.
//!
//! The deterministic variant [`seal_with_rng`] exists solely to pin the
//! cross-target known-answer vector, and is gated behind the non-default
//! `test-vectors` feature. That gate is the enforcement, not the doc-comment
//! above it: without the feature the symbol does not resolve, so a
//! predictable-RNG sealing path is a COMPILE ERROR in any production
//! dependency closure rather than a review catch. `scripts/surface-check.sh`
//! proves the gate by compiling a probe consumer that names it and asserting
//! `E0432`.
//!
//! `R: RngCore + CryptoRng` on [`seal_with_rng`] is a second, weaker line:
//! it makes `rand::rngs::SmallRng` a type error (`E0277`), but it does NOT
//! make a *seeded* CSPRNG one — `ChaCha20Rng::seed_from_u64(n)` satisfies
//! `CryptoRng` while carrying only 64 bits of unpredictability. Seed
//! PROVENANCE is not expressible in Rust's type system, which is exactly why
//! the feature gate (reachability), not the bound (type), is what protects
//! production here.

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::cipher;
use crate::error::{KeystoreError, Result};
use crate::format::{
    decode_file, encode_file, CipherId, KdfParams, KeystoreHeader, FORMAT_VERSION_V1,
};
use crate::kdf;
use crate::password::Password;

/// 6-byte on-disk magic for opaque-secret blobs. See the module-level docs
/// for how this relates to the typed key-scheme magics (`DIGVK1`/`DIGLW1`).
pub const MAGIC: [u8; 6] = *b"DIGOP1";

/// Scheme id for opaque-secret blobs, stored in [`KeystoreHeader::scheme_id`].
/// `0x0002` and `0x0001`/`0x0003` are taken by the typed key-scheme
/// containers; `0x0004` is the next free id.
pub const SCHEME_ID: u16 = 0x0004;

/// Seal `secret` (any length, including empty) under `password`, returning
/// the encoded container bytes.
///
/// The 128-bit Argon2id salt and 96-bit AES-GCM nonce are drawn from
/// [`rand_core::OsRng`] — the operating system CSPRNG (`getrandom(2)` /
/// `BCryptGenRandom` / `crypto.getRandomValues` under wasm). This is the only
/// sealing entry point on the crate's default surface, and the RNG is not a
/// parameter of it: see the module-level "Entropy contract".
///
/// The deterministic variant used to pin the cross-target known-answer vector
/// is `seal_with_rng`, gated behind the non-default `test-vectors` feature.
pub fn seal(password: &Password, secret: &[u8], kdf_params: KdfParams) -> Result<Vec<u8>> {
    seal_with_os_or_given_rng(password, secret, kdf_params, &mut rand_core::OsRng)
}

/// **Test vectors only — gated behind the non-default `test-vectors` feature.**
///
/// Like [`seal`] but with a caller-supplied RNG, so a known-answer vector can
/// be asserted byte-identical on native and `wasm32-unknown-unknown`
/// (`tests/opaque_vectors.rs` and `wasm/tests/opaque_wasm.rs`).
///
/// # ⚠️ Never seal a real secret through this
///
/// A caller-supplied RNG is a caller-supplied salt and nonce. Seeded from a
/// small integer, the Argon2id salt becomes precomputable and the AES-GCM
/// nonce predictable, so an attacker who later obtains the blob attacks the
/// password with a rainbow table instead of a per-blob KDF. That is the
/// Milk Sad / Trust Wallet defect class (CVE-2023-31290, CVE-2022-32969) and
/// no test can observe it in the output bytes — only reading the entropy
/// source can.
///
/// The `test-vectors` feature is what keeps that reachable only from a test
/// build: it is off by default, no production consumer in the ecosystem
/// enables it, and `scripts/surface-check.sh` asserts a default-features
/// consumer naming this function fails to compile with `E0432`.
#[cfg(feature = "test-vectors")]
pub fn seal_with_rng<R: RngCore + CryptoRng>(
    password: &Password,
    secret: &[u8],
    kdf_params: KdfParams,
    rng: &mut R,
) -> Result<Vec<u8>> {
    seal_with_os_or_given_rng(password, secret, kdf_params, rng)
}

/// The single sealing implementation, shared by [`seal`] (which pins
/// [`rand_core::OsRng`]) and the `test-vectors`-gated `seal_with_rng`.
///
/// Deliberately crate-private: making the RNG a parameter is the whole risk
/// this module is guarding, so the parameterised form is not part of the
/// default public surface. Keeping ONE body is what makes the known-answer
/// vector meaningful — the deterministic test exercises the identical code
/// path production uses, with only the RNG swapped.
fn seal_with_os_or_given_rng<R: RngCore + CryptoRng>(
    password: &Password,
    secret: &[u8],
    kdf_params: KdfParams,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    // Provisional header used as AAD once payload_len is finalized below —
    // same construction as `Keystore::create_with_rng` (keystore.rs).
    let mut header = KeystoreHeader {
        magic: MAGIC,
        format_version: FORMAT_VERSION_V1,
        scheme_id: SCHEME_ID,
        kdf: kdf_params,
        cipher: CipherId::Aes256Gcm,
        salt,
        nonce,
        payload_len: 0,
    };
    header.payload_len = (secret.len() + cipher::TAG_SIZE) as u32;

    let enc_key = kdf::derive_key(password.as_bytes(), &header.salt, &header.kdf)?;
    let header_bytes = header.encode();
    let ciphertext_and_tag = cipher::encrypt(&enc_key, &header.nonce, secret, &header_bytes)?;
    Ok(encode_file(&header, &ciphertext_and_tag))
}

/// Open a blob produced by [`seal`] (or, in a `test-vectors` build, by
/// `seal_with_rng`), returning the original secret bytes wrapped in
/// [`Zeroizing`].
///
/// # Errors
///
/// - [`KeystoreError::SchemeMismatch`] if the blob's magic/scheme id is not
///   [`MAGIC`]/[`SCHEME_ID`] (e.g., it's a `DIGVK1`/`DIGLW1` keystore file).
/// - [`KeystoreError::DecryptFailed`] for a wrong password or any tampering
///   (ciphertext or header/AAD) — see `crate::cipher` for why the two are
///   not distinguished.
/// - The generic decode errors (`Truncated`, `CrcMismatch`,
///   `UnsupportedFormat`, `UnsupportedKdf`, `UnsupportedCipher`) for a
///   malformed blob.
pub fn open(password: &Password, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (header, ciphertext_and_tag, header_bytes) = decode_file(blob)?;
    if header.magic != MAGIC || header.scheme_id != SCHEME_ID {
        return Err(KeystoreError::SchemeMismatch {
            expected: SCHEME_ID,
            expected_name: "Opaque",
            found: header.scheme_id,
        });
    }
    let key = kdf::derive_key(password.as_bytes(), &header.salt, &header.kdf)?;
    cipher::decrypt(&key, &header.nonce, &ciphertext_and_tag, &header_bytes)
}

/// `true` if `password` opens `blob` without exposing the secret. Runs the
/// full KDF + AEAD verification; only the boolean result escapes.
pub fn verify_password(password: &Password, blob: &[u8]) -> bool {
    open(password, blob).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    // ChaCha20Rng (not `rand::StdRng`, which is ChaCha12 internally as of
    // rand 0.8) — this MUST be the exact same concrete RNG type+algorithm as
    // `wasm/src/lib.rs`'s `seal_with_seed` test helper, or the same numeric
    // seed produces different salt/nonce bytes on each target and the
    // native↔wasm KAT vector below silently stops proving anything.
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn fast_params() -> KdfParams {
        KdfParams::FAST_TEST
    }

    /// **Proves:** sealing then opening recovers the exact secret bytes for
    /// secret lengths that a fixed-`SECRET_LEN` `KeyScheme` could never
    /// accept (5, 16, 20, 24, 28, 32, 100 — spanning every BIP-39 entropy
    /// size plus arbitrary short/long blobs), and for the empty secret.
    ///
    /// **Why it matters:** This is the entire reason `opaque` exists instead
    /// of reusing `Keystore<K>` — a browser vault's secret material is not a
    /// fixed 32-byte seed. If length handling regressed (e.g., a hidden
    /// assumption crept in that truncates/pads to 32 bytes), this catches it
    /// across the realistic range.
    ///
    /// **Catches:** an accidental `SECRET_LEN`-style length assumption, or a
    /// buffer-sizing bug in the AES-GCM plumbing that only surfaces for
    /// non-32-byte inputs.
    #[test]
    fn roundtrip_recovers_exact_secret_at_every_length() {
        for len in [0usize, 5, 16, 20, 24, 28, 32, 100] {
            let secret = vec![0xABu8; len];
            let password = Password::from("correct horse battery staple");
            let blob = seal(&password, &secret, fast_params()).unwrap();
            let recovered = open(&password, &blob).unwrap();
            assert_eq!(&*recovered, &secret[..], "length {len} failed to roundtrip");
        }
    }

    /// **Proves:** opening with the wrong password fails closed with
    /// `DecryptFailed`, never returning partial or garbage plaintext.
    ///
    /// **Why it matters:** This is the wiring-level proof that `opaque`
    /// actually authenticates the password rather than, say, decoding the
    /// header and returning the ciphertext bytes verbatim.
    ///
    /// **Catches:** a copy-paste bug that derives the key from a constant
    /// instead of the caller's password.
    #[test]
    fn wrong_password_fails() {
        let secret = b"top secret entropy".to_vec();
        let blob = seal(&Password::from("right"), &secret, fast_params()).unwrap();
        let err = open(&Password::from("wrong"), &blob).unwrap_err();
        assert!(matches!(err, KeystoreError::DecryptFailed));
    }

    /// **Proves:** flipping a byte inside the ciphertext (well past the
    /// header) is detected — either by the outer CRC-32 fast-fail or, had
    /// the CRC agreed, by the AES-GCM tag — and rejected, never silently
    /// decrypted to corrupted bytes. Mirrors `tests/tamper.rs`'s
    /// `tampering_any_byte_fails`, which established that CRC legitimately
    /// wins the race for most byte flips (it runs before any cryptography).
    ///
    /// **Why it matters:** Proves `opaque::open` is wired through the real
    /// decode-then-authenticated-decrypt path (`decode_file` +
    /// `cipher::decrypt`), not a bare cipher that would happily "decrypt"
    /// tampered bytes into garbage.
    ///
    /// **Catches:** a regression that swaps AEAD for a non-authenticated
    /// mode, skips tag verification, or drops the CRC fast-fail.
    #[test]
    fn tampered_ciphertext_fails() {
        let secret = b"another secret".to_vec();
        let password = Password::from("pw");
        let mut blob = seal(&password, &secret, fast_params()).unwrap();
        // Flip a byte inside the ciphertext region (after the 53-byte header).
        let i = blob.len() - 6;
        blob[i] ^= 0xFF;
        let err = open(&password, &blob).unwrap_err();
        assert!(matches!(
            err,
            KeystoreError::DecryptFailed | KeystoreError::CrcMismatch { .. }
        ));
    }

    /// **Proves:** `verify_password` returns `true` for the correct password
    /// and `false` for a wrong one, without panicking either way.
    ///
    /// **Why it matters:** This is the primitive a browser vault's "unlock"
    /// UI would call to validate a password attempt before deciding whether
    /// to expose the secret to the rest of the flow.
    ///
    /// **Catches:** an inverted boolean, or a version that throws instead of
    /// returning `false` on a wrong password.
    #[test]
    fn verify_password_reports_correctly() {
        let secret = b"seed material".to_vec();
        let blob = seal(&Password::from("hunter2"), &secret, fast_params()).unwrap();
        assert!(verify_password(&Password::from("hunter2"), &blob));
        assert!(!verify_password(&Password::from("wrong"), &blob));
    }

    /// **Proves:** the sealing body is a pure, deterministic function of its
    /// inputs — the exact byte-for-byte KAT vector shared with
    /// `tests/opaque_vectors.rs` (native) and `wasm/tests/opaque_wasm.rs`
    /// (wasm-bindgen-test).
    ///
    /// **Why it matters:** This is the anchor of the native↔wasm
    /// byte-compatibility proof (dig_ecosystem #147 Phase A): the wasm suite
    /// calls the identical body (via the `test-vectors`-gated
    /// `seal_with_rng`) with the identical seed, so both targets MUST agree
    /// on this constant. If they ever disagreed, Phase B's "old blobs still
    /// open" guarantee would be unverifiable across targets.
    ///
    /// **Catches:** any change to the RNG algorithm, field ordering, or
    /// cipher/KDF wiring that would silently change the container's bytes
    /// for identical inputs.
    ///
    /// Calls the crate-private body directly so the vector is still pinned in
    /// a build WITHOUT the `test-vectors` feature — the gate must not cost
    /// coverage of the format itself.
    #[test]
    fn deterministic_kat_matches_pinned_vector() {
        let mut rng = ChaCha20Rng::seed_from_u64(KAT_SEED);
        let blob = seal_with_os_or_given_rng(
            &Password::from(KAT_PASSWORD),
            KAT_SECRET,
            KdfParams::FAST_TEST,
            &mut rng,
        )
        .unwrap();
        let got = hex::encode(&blob);

        // First run: print the expected value, fail with a clear message so the
        // maintainer pastes it into KAT_HEX below (mirrors tests/vectors.rs).
        if KAT_HEX == "_REGENERATE_ME_ON_FIRST_RUN" {
            panic!("KAT_HEX = \"{got}\";\n(paste into `src/opaque.rs` KAT_HEX and re-run)");
        }
        assert_eq!(got, KAT_HEX, "opaque KAT vector drifted");
    }

    /// Shared KAT inputs — ALSO used by `tests/opaque_vectors.rs` (native)
    /// and mirrored (via `sealWithSeed`) in `wasm/tests/opaque_wasm.rs`.
    pub(crate) const KAT_SEED: u64 = 0x4B_4159_5354_4F52; // "KAT_STOR"-ish, arbitrary fixed constant
    pub(crate) const KAT_PASSWORD: &str = "opaque-kat-password";
    pub(crate) const KAT_SECRET: &[u8] = b"\x00\x01\x02\x03opaque-kat-secret-bytes\xFF\xFE";
    /// Regenerate with: run this test once, it will panic with a mismatch
    /// against this placeholder — paste the printed value here.
    pub(crate) const KAT_HEX: &str = "4449474f5031000100040100002000000000010101d2491ad536cec869b6d6174731645eeacabcde0420b2f2a8151f13900000002df6427db43857eb57c6c5606c5ed12abee298cdcdd56313136add9aada0b8cfb523b6fa6480fa8bcdfbdf78e63bbe815355";
}
