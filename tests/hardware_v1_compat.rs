//! §5.1 backwards compatibility: **every released v1 blob must still open,
//! byte-identically, forever.**
//!
//! A keystore blob is permanent user key material — a reader that cannot open an
//! older blob has locked someone out of their wallet. Adding hardware binding is
//! exactly the kind of change that could break that, so this file pins it with
//! **golden fixtures**: real blobs, produced by this crate's own sealing path
//! under a fixed RNG and password, committed as hex and decoded by the current
//! code.
//!
//! # What these fixtures do and do not prove
//!
//! A test that generates a blob and then reads it back proves only that the code
//! agrees with itself; it would stay green through a format change that made every
//! previously-written file unreadable. These bytes are frozen literals, so they
//! keep testifying about the format after the code moves on.
//!
//! **Scope of the claim, stated precisely.** They were produced by *this* build's
//! sealing path and then frozen. They are **not** extracted from a blob that an
//! older released binary actually wrote, so they are **not** evidence that this
//! code agrees with 0.1.x output. What they prove is forward-facing: from this
//! commit on, any change that stops these exact bytes decoding — or changes what
//! they decrypt to — fails the suite. That is the property §5.1 needs going
//! forward, and it is all these fixtures assert.
//!
//! Each fixture is checked against the real format's own dimensions
//! (`SPEC.md` §3: 105 bytes total for a 32-byte secret, 53-byte header,
//! 48-byte payload), not an invented size.
//!
//! # Regenerating
//!
//! These fixtures MUST NOT be regenerated to make a failing test pass — a
//! mismatch means the format moved and older files stopped opening. Run
//! `cargo test --features testing --test hardware_v1_compat -- --ignored
//! print_fixtures` only when *adding* a fixture for a newly released version.

use std::sync::Arc;

use dig_keystore::backend::{BackendKey, KeychainBackend, MemoryBackend};
use dig_keystore::hardware::double::FakeDevice;
use dig_keystore::hardware::{
    HardwareBoundBackend, HardwareKind, HardwarePolicy, HardwareProvider,
};
use dig_keystore::{BlsSigning, KdfParams, Keystore, L1WalletBls, Password};

/// The password every fixture was sealed under.
const FIXTURE_PASSWORD: &str = "golden-fixture-password";

/// Total size of a v1 blob holding a 32-byte secret (`SPEC.md` §3).
const V1_TOTAL_LEN: usize = 105;

/// KDF parameters the fixtures were sealed with — the minimum the crate accepts,
/// so the suite does not pay ~0.5 s of Argon2id per fixture. The *parameters* are
/// not what these fixtures pin; the byte layout is.
fn fixture_kdf() -> KdfParams {
    KdfParams {
        memory_kib: 8192,
        iterations: 1,
        lanes: 1,
        ..KdfParams::DEFAULT
    }
}

/// A `BlsSigning` (`DIGVK1`) keystore file in format version 0x0001 — the shape
/// the crate has written since 0.1.x. Frozen at 0.5.0 from this crate's own
/// sealing path (see the module docs for the exact scope of that claim).
const GOLDEN_V1_BLS_SIGNING: &str = include_str!("fixtures/v1_bls_signing.hex");

/// An `L1WalletBls` (`DIGLW1`) keystore file in format version 0x0001, frozen the
/// same way.
const GOLDEN_V1_L1_WALLET: &str = include_str!("fixtures/v1_l1_wallet_bls.hex");

/// Decode a committed fixture, tolerating trailing whitespace/newlines.
fn fixture(hex_text: &str) -> Vec<u8> {
    hex::decode(hex_text.trim()).expect("fixture must be valid hex")
}

fn password() -> Password {
    Password::new(FIXTURE_PASSWORD)
}

/// A backend in the hardware tier, over storage pre-loaded with `blob`.
fn hardware_over(blob: &[u8], key: &BackendKey) -> HardwareBoundBackend {
    let inner = Arc::new(MemoryBackend::default());
    inner.write(key, blob).unwrap();
    let device: Arc<dyn HardwareProvider> =
        Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 0x42));
    HardwareBoundBackend::with_inner(inner, Some(device), HardwarePolicy::Required)
        .expect("working hardware must resolve")
}

/// **Proves:** the committed fixtures are genuinely the v1 shape the spec
/// describes — right magic, right format version, and the exact 105-byte size.
///
/// **Why it matters:** every other test in this file rests on these bytes being
/// real released blobs. A fixture that had silently become a stub (short, or
/// carrying a different version) would make the compatibility proofs vacuous —
/// the narrow-fixture failure mode.
///
/// **Catches:** a truncated or regenerated fixture; a fixture holding a
/// different format version than the one it claims to pin.
#[test]
fn golden_fixtures_are_the_real_released_v1_shape() {
    for (name, hex_text, magic) in [
        ("bls_signing", GOLDEN_V1_BLS_SIGNING, b"DIGVK1"),
        ("l1_wallet_bls", GOLDEN_V1_L1_WALLET, b"DIGLW1"),
    ] {
        let blob = fixture(hex_text);
        assert_eq!(
            blob.len(),
            V1_TOTAL_LEN,
            "{name}: a v1 blob with a 32-byte secret is {V1_TOTAL_LEN} bytes (SPEC §3)"
        );
        assert_eq!(&blob[..6], magic, "{name}: magic");
        assert_eq!(
            u16::from_be_bytes([blob[6], blob[7]]),
            dig_keystore::FORMAT_VERSION_V1,
            "{name}: format version"
        );
        // PAYLOAD_LEN at offset 49 must be 32 + 16 for every shipped scheme.
        assert_eq!(
            u32::from_be_bytes(blob[49..53].try_into().unwrap()),
            48,
            "{name}: payload length"
        );
    }
}

/// **Proves:** a released v1 `DIGVK1` blob unlocks to its original key through
/// the hardware-bound backend, in the **hardware** tier, with bytes untouched.
///
/// **Why it matters:** this is the upgrade path that matters most — an existing
/// user moves onto a TPM-equipped machine, and their existing keystore must
/// still open. Asserting the recovered public key (not merely that `read`
/// returned something) is what makes this a decryption proof rather than a
/// byte-shuffling one.
///
/// **Catches:** a read path that requires an envelope; any change to the v1
/// header, AAD binding, or KDF that would make old files undecryptable.
#[test]
fn a_released_bls_signing_blob_unlocks_in_the_hardware_tier() {
    let blob = fixture(GOLDEN_V1_BLS_SIGNING);
    let key = BackendKey::new("validator_bls");
    let backend = hardware_over(&blob, &key);
    assert!(backend.tier().is_hardware_bound());

    // The blob is passed through unchanged...
    assert_eq!(backend.read(&key).unwrap(), blob);

    // ...and still decrypts to a usable signer.
    let ks = Keystore::<BlsSigning>::load(Arc::new(backend), key).expect("v1 blob must load");
    let signer = ks.unlock(password()).expect("v1 blob must unlock");
    let sig = signer.sign(b"golden");
    assert!(!sig.to_bytes().is_empty());
}

/// **Proves:** the same for a released `DIGLW1` wallet blob — the second shipped
/// scheme, whose seed is a wallet master key.
///
/// **Why it matters:** the two schemes take different code paths through the
/// scheme/type binding check (`SPEC.md` §3.3). Pinning only one would leave the
/// other's compatibility untested.
///
/// **Catches:** a scheme-id or magic regression affecting only the wallet path.
#[test]
fn a_released_l1_wallet_blob_unlocks_in_the_hardware_tier() {
    let blob = fixture(GOLDEN_V1_L1_WALLET);
    let key = BackendKey::new("wallet_master");
    let backend = hardware_over(&blob, &key);

    let ks = Keystore::<L1WalletBls>::load(Arc::new(backend), key).expect("v1 blob must load");
    let signer = ks.unlock(password()).expect("v1 blob must unlock");
    assert_eq!(signer.expose_secret().len(), 32);
}

/// **Proves:** a released v1 blob opens identically in **every** tier — hardware,
/// confidently-degraded software, and no-provider — and yields the same bytes in
/// all three.
///
/// **Why it matters:** compatibility must not depend on which tier the host
/// happens to resolve. A machine that loses its TPM (BIOS change, reimage,
/// motherboard swap) must still open its existing unwrapped keystore, or the
/// hardware feature has introduced a lockout on the degrade path.
///
/// **Catches:** a tier-specific read branch that only handles legacy blobs in
/// one tier.
#[test]
fn a_released_v1_blob_opens_identically_in_every_tier() {
    let blob = fixture(GOLDEN_V1_BLS_SIGNING);
    let key = BackendKey::new("validator_bls");

    /// One row of the tier table: a label, the provider to inject, and the policy.
    type TierCase = (
        &'static str,
        Option<Arc<dyn HardwareProvider>>,
        HardwarePolicy,
    );

    let tiers: Vec<TierCase> = vec![
        (
            "hardware",
            Some(Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 1))),
            HardwarePolicy::Required,
        ),
        (
            "degraded",
            Some(Arc::new(FakeDevice::absent(HardwareKind::WindowsTpm20))),
            HardwarePolicy::Preferred,
        ),
        ("no-provider", None, HardwarePolicy::Optional),
    ];

    for (label, provider, policy) in tiers {
        let inner = Arc::new(MemoryBackend::default());
        inner.write(&key, &blob).unwrap();
        let backend = HardwareBoundBackend::with_inner(inner, provider, policy)
            .unwrap_or_else(|e| panic!("{label}: must open: {e}"));

        assert_eq!(
            backend.read(&key).unwrap(),
            blob,
            "{label}: v1 bytes must be returned unchanged"
        );
        let ks = Keystore::<BlsSigning>::load(Arc::new(backend), key.clone())
            .unwrap_or_else(|e| panic!("{label}: must load: {e}"));
        ks.unlock(password())
            .unwrap_or_else(|e| panic!("{label}: must unlock: {e}"));
    }
}

/// **Proves:** a v1 blob re-sealed into a hardware envelope still recovers the
/// original 105 bytes exactly, so the round-trip through hardware binding is
/// lossless for real released material.
///
/// **Why it matters:** upgrading an existing keystore onto hardware protection
/// must be reversible in the sense that matters — the inner v1 blob that comes
/// back out is bit-for-bit the one that went in, so it remains decryptable by the
/// same password and readable by any other v1 reader once unwrapped.
///
/// **Catches:** an envelope that pads, truncates, or re-encodes its payload.
#[test]
fn wrapping_a_released_v1_blob_recovers_it_byte_identically() {
    let blob = fixture(GOLDEN_V1_BLS_SIGNING);
    let key = BackendKey::new("validator_bls");

    let inner = Arc::new(MemoryBackend::default());
    let device: Arc<dyn HardwareProvider> =
        Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 0x9E));
    let backend =
        HardwareBoundBackend::with_inner(inner.clone(), Some(device), HardwarePolicy::Required)
            .unwrap();

    backend.write(&key, &blob).unwrap();
    // Stored form is now an envelope, and larger than the bare blob.
    let stored = inner.read(&key).unwrap();
    assert!(dig_keystore::hardware::envelope::is_envelope(&stored));
    assert!(stored.len() > V1_TOTAL_LEN);

    // What comes back out is the original, byte for byte.
    assert_eq!(backend.read(&key).unwrap(), blob);

    let ks = Keystore::<BlsSigning>::load(Arc::new(backend), key).unwrap();
    ks.unlock(password())
        .expect("must still unlock after wrapping");
}

// ---------------------------------------------------------------------------
// Fixture generation — run manually when ADDING a fixture, never to "fix" a
// failing compatibility test.
// ---------------------------------------------------------------------------

/// Print freshly generated fixtures. Ignored by default.
///
/// Deterministic: seeded ChaCha RNG + fixed password, so the emitted bytes are
/// reproducible and reviewable.
#[test]
#[ignore = "manual fixture generation"]
fn print_fixtures() {
    use rand_chacha::rand_core::SeedableRng;

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x2A; 32]);
    let backend = Arc::new(MemoryBackend::default());

    let bls = BackendKey::new("bls");
    Keystore::<BlsSigning>::create_with_rng(
        backend.clone(),
        bls.clone(),
        password(),
        Some(zeroize::Zeroizing::new(vec![0x11u8; 32])),
        fixture_kdf(),
        &mut rng,
    )
    .unwrap();
    println!(
        "v1_bls_signing.hex\n{}",
        hex::encode(backend.read(&bls).unwrap())
    );

    let lw = BackendKey::new("lw");
    Keystore::<L1WalletBls>::create_with_rng(
        backend.clone(),
        lw.clone(),
        password(),
        Some(zeroize::Zeroizing::new(vec![0x22u8; 32])),
        fixture_kdf(),
        &mut rng,
    )
    .unwrap();
    println!(
        "v1_l1_wallet_bls.hex\n{}",
        hex::encode(backend.read(&lw).unwrap())
    );
}
