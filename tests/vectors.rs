//! Deterministic known-answer tests (KATs).
//!
//! These fix the RNG seed, password, and KDF parameters so the produced
//! keystore's public key is deterministic. If anyone accidentally changes a
//! key-derivation constant (e.g., switches BLS basic-scheme ↔ augmented-scheme),
//! these tests will fail — pinning the output to a known value.

use std::sync::Arc;

use dig_keystore::{
    backend::{BackendKey, KeychainBackend, MemoryBackend},
    scheme::{BlsSigning, KeyScheme, L1WalletBls},
    KdfParams, Keystore, Password,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn kat_params() -> KdfParams {
    // Must match across test runs.
    KdfParams::FAST_TEST
}

/// Seed 0xDEADBEEF + `BlsSigning` -> deterministic public key.
///
/// Blessed on `chia-bls` 0.26.0, the line this crate shipped on through v0.9.0,
/// and re-verified unchanged on 0.36.1. That equality across the two lines is
/// what makes the dependency uplift safe to ship: an EIP-2333 derivation change
/// would have moved this value, and every `DIGVK1` key already at rest would
/// have started opening onto a different identity.
///
/// **Never regenerate this to make a red build green.** A changed value means
/// stored keys no longer derive the identity they were created with, which is a
/// custody break, not a test that needs updating.
const BLS_SIGNING_KAT_PUBKEY_HEX: &str =
    "84775315f4005177c319d6c6769b3c212db960584bc739fe6bba9b836d1ca54b310f319376ef7462f1d03684bfa686cd";

/// **Proves:** creating a `BlsSigning` keystore with RNG seed `0xDEADBEEF`,
/// password `"kat-password"`, and [`KdfParams::FAST_TEST`] always produces
/// the same derived public key.
///
/// **Why it matters:** This is the crate's load-bearing derivation-stability
/// test. Any change to the seed-generation path, Argon2id, AES-256-GCM, the
/// file format, or the `chia-bls` `from_seed` derivation produces a different
/// pubkey and fails here — forcing a maintainer to confirm the change is
/// intentional before accepting it.
///
/// **It must compare unconditionally.** This test formerly opened with a
/// "regeneration flow": when the constant still held a placeholder it printed
/// the generated value and `return`ed *success*. Nobody ever pasted the value
/// in, so for nine releases the crate's derivation gate compared nothing and
/// passed for any output. Do not reintroduce a first-run branch; if the
/// expected value is genuinely unknown, obtain it from a run and commit it —
/// a gate that can skip itself is not a gate.
///
/// **Catches:** accidental version bumps in `chia-bls` that change
/// EIP-2333 derivation, reorderings in the file-format encoder that change
/// what RNG reads which field, a switch from `rand::StdRng` to a different
/// algorithm.
#[test]
fn bls_signing_deterministic_pubkey() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
    let ks = Keystore::<BlsSigning>::create_with_rng(
        backend,
        BackendKey::new("kat"),
        Password::from("kat-password"),
        None,
        kat_params(),
        &mut rng,
    )
    .unwrap();

    let pk = *ks
        .unlock(Password::from("kat-password"))
        .unwrap()
        .public_key();
    let got = hex::encode(pk.to_bytes());

    assert_eq!(
        got, BLS_SIGNING_KAT_PUBKEY_HEX,
        "BLS key derivation changed — if intentional, regenerate this KAT"
    );
}

/// **Proves:** the `L1WalletBls` scheme produces a 48-byte compressed G1
/// pubkey (standard BLS12-381 compressed-point size) when created with a
/// seeded RNG.
///
/// **Why it matters:** Smoke test for the L1 wallet scheme. Unlike the
/// `BlsSigning` KAT this doesn't pin the pubkey value (since no downstream
/// consumer is yet frozen on L1 wallet pubkeys), but it pins the output
/// *size*. If chia-bls ever changed the compressed-point encoding (e.g.,
/// to 96 bytes uncompressed), this would fail and flag the incompatibility.
///
/// **Catches:** a chia-bls API change that swaps compressed ↔ uncompressed
/// encoding; a scheme-internal bug where `public_key` returns an
/// intermediate scalar instead of the compressed point.
#[test]
fn l1_wallet_bls_deterministic_pubkey() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let mut rng = StdRng::seed_from_u64(0x0123_4567);
    let ks = Keystore::<L1WalletBls>::create_with_rng(
        backend,
        BackendKey::new("kat"),
        Password::from("kat-password"),
        None,
        kat_params(),
        &mut rng,
    )
    .unwrap();

    let pk = *ks
        .unlock(Password::from("kat-password"))
        .unwrap()
        .public_key();
    // Smoke test — just verify the pubkey is 48 bytes (BLS12-381 G1 compressed).
    assert_eq!(pk.to_bytes().len(), 48);
}

/// **Proves:** the total on-disk file size for a default BLS keystore is
/// exactly **105 bytes** = 53 (header) + 48 (ciphertext+tag) + 4 (CRC-32).
///
/// **Why it matters:** This is a protocol-level invariant — it is the
/// reference file size operators check when they run
/// `stat <keystore>.dks`. If we changed the layout (added a field, shrank
/// the tag, moved the CRC), every deployed keystore would become
/// unreadable. The test pins the exact byte budget.
///
/// **Catches:** any structural change to the file format: new header
/// fields, different tag size, missing CRC, duplicated payload.
#[test]
fn file_layout_header_size_stable() {
    // This is a protocol-level invariant: the header is exactly 53 bytes. If
    // it changes, every stored keystore becomes unreadable.
    let backend = Arc::new(MemoryBackend::new());
    let trait_backend: Arc<dyn KeychainBackend> = backend.clone();
    let key = BackendKey::new("layout");

    let mut rng = StdRng::seed_from_u64(1);
    Keystore::<BlsSigning>::create_with_rng(
        trait_backend,
        key.clone(),
        Password::from("pw"),
        None,
        kat_params(),
        &mut rng,
    )
    .unwrap();

    let bytes = backend.read(&key).unwrap();
    // Header: 53 bytes, payload: secret_len (32) + tag (16) = 48 bytes, CRC: 4 bytes.
    assert_eq!(bytes.len(), 53 + 48 + 4);
}

/// **Proves:** the magic bytes each scheme actually writes are exactly
/// `b"DIGVK1"` and `b"DIGLW1"`, read from the production
/// [`KeyScheme::MAGIC`] constants.
///
/// **Why it matters:** magic bytes are part of the on-disk specification. They
/// must stay stable across library versions so an operator can
/// `xxd <file>.dks | head -1` and see which scheme's key this is. Changing one
/// makes every keystore written by an earlier version unrecognisable (SPEC.md
/// §5.1, backwards compatibility).
///
/// **Catches:** a typo during a magic-constant edit (`DIGVK2`), a copy-paste
/// that makes both schemes share one magic, a regression to non-printable
/// bytes.
///
/// Reading `KeyScheme::MAGIC` is the load-bearing part. This test previously
/// declared its own private `Magic` trait holding the literals and asserted
/// those against themselves, so it passed for any production value — including
/// none at all. An assertion whose two sides come from the same place proves
/// only that `==` works.
#[test]
fn magic_bytes_are_ascii() {
    assert_eq!(&<BlsSigning as KeyScheme>::MAGIC, b"DIGVK1");
    assert_eq!(&<L1WalletBls as KeyScheme>::MAGIC, b"DIGLW1");

    // Printable ASCII is the property an operator relies on when reading a
    // hex dump, so assert it rather than trusting the literals above to stay
    // printable through a future edit.
    for magic in [
        <BlsSigning as KeyScheme>::MAGIC,
        <L1WalletBls as KeyScheme>::MAGIC,
    ] {
        assert!(
            magic.iter().all(|b| b.is_ascii_graphic()),
            "magic bytes must stay printable ASCII, got {magic:?}"
        );
    }
}
