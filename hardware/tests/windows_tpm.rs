//! Tests that touch **real silicon**, and the honest handling of a host that has
//! none.
//!
//! # The problem these tests are built around
//!
//! No GitHub runner has a TPM. A `#[cfg]`-gated test that cannot execute on the
//! host is unfalsifiable, a `#[ignore]`d one is skipped in silence, and a test
//! filter that matches nothing still prints `ok`. Each of those turns "we never
//! checked" into something that reads exactly like "we checked and it was fine".
//!
//! # How that is avoided here
//!
//! **The hardware assertions are opt-in and the opt-in is loud.** Set
//! `DIG_KEYSTORE_REQUIRE_TPM=1` and every test below asserts against real
//! hardware, failing if it is absent. Leave it unset and the same tests still
//! *run* — they assert the properties an unbound host must have, and they print
//! what was and was not exercised.
//!
//! So a runner without a TPM produces a pass that means "the degraded path is
//! correct", not "the TPM path is correct", and a runner with the variable set
//! cannot pass by skipping. **Neither shape can report a hardware property it did
//! not observe.**
//!
//! Set the variable on any CI runner that genuinely has a TPM, and on a developer
//! machine before touching `platform::windows`.
//!
//! # Nothing here prints key material
//!
//! Content keys, wrapped blobs and keystore bytes are asserted over, never
//! displayed. The one thing printed is the probe classification.

#![cfg(target_os = "windows")]

use dig_keystore::hardware::{
    ContentKey, HardwareKind, HardwareProbe, HardwareProvider, KeyCustody, ProtectionTier,
    CONTENT_KEY_LEN,
};
use dig_keystore_hardware::platform::windows::CngPlatformKeyProvider;

/// Whether this run is asserting against real hardware.
///
/// Read from the environment rather than probed, on purpose: deciding
/// "are we testing hardware?" by *asking the hardware* makes the answer
/// unfalsifiable — a broken probe would simply excuse itself.
fn tpm_required() -> bool {
    std::env::var("DIG_KEYSTORE_REQUIRE_TPM").is_ok_and(|v| v == "1")
}

/// The provider, plus whether it is genuinely bound to hardware.
///
/// Fails the test when hardware is required and absent, so the opt-in cannot be
/// satisfied by a skip.
fn provider() -> (CngPlatformKeyProvider, bool) {
    let provider = CngPlatformKeyProvider::detect();
    let bound = matches!(provider.probe(), HardwareProbe::Available(_));

    if tpm_required() && !bound {
        panic!(
            "DIG_KEYSTORE_REQUIRE_TPM=1 but this host is not TPM-bound: {:?}",
            provider.probe()
        );
    }
    (provider, bound)
}

/// **Property (`SPEC.md` §17.1, conformance C-21):** the platform refuses to
/// export the wrapping key.
///
/// This is the property the whole feature rests on, so it is asserted against the
/// platform rather than reasoned about. `custody()` returns `NonExportable` only
/// after `NCryptExportKey(BCRYPT_RSAFULLPRIVATE_BLOB)` has actually been refused,
/// so this assertion IS the export attempt.
///
/// **On a host without a TPM this asserts the complementary property** — that an
/// unbound provider does not claim hardware custody — which is a real assertion
/// about a real code path, not a placeholder for the one that did not run.
#[test]
fn the_platform_refuses_to_export_the_wrapping_key() {
    let (provider, bound) = provider();

    if bound {
        assert_eq!(
            provider.custody(),
            KeyCustody::NonExportable,
            "the TPM allowed its private key to be exported — this host offers no \
             cross-machine binding and must not be reported as hardware-bound"
        );
        eprintln!("EXERCISED: real TPM refused a private-key export");
    } else {
        assert!(
            !provider.custody().is_hardware_grade(),
            "an unbound provider must not claim hardware-grade custody"
        );
        eprintln!(
            "NOT EXERCISED: no TPM on this host ({:?}). The export-refusal property \
             was NOT checked. Set DIG_KEYSTORE_REQUIRE_TPM=1 on a TPM-equipped host.",
            provider.probe()
        );
    }
}

/// **Property:** a content key wrapped by the TPM round-trips, and the wrapped
/// form is neither the key itself nor empty.
///
/// The two negative assertions matter as much as the round-trip: a provider that
/// returned the content key verbatim would round-trip perfectly while wrapping
/// nothing, and one that returned an empty blob would write an envelope with no
/// wrapped key in it.
#[test]
fn a_content_key_round_trips_through_the_tpm() {
    let (provider, bound) = provider();
    if !bound {
        eprintln!("NOT EXERCISED: no TPM on this host; the wrap round-trip was NOT checked.");
        return;
    }

    // Distinct per byte so a truncation or a repeat cannot pass unnoticed.
    let mut material = [0u8; CONTENT_KEY_LEN];
    for (i, b) in material.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(11);
    }
    let content_key = ContentKey::new(material);

    let wrapped = provider.wrap_key(&content_key).expect("TPM wrap");
    assert!(!wrapped.is_empty(), "an empty wrap protects nothing");
    assert_ne!(
        wrapped.as_slice(),
        content_key.as_slice(),
        "a wrap that returns the content key verbatim wraps nothing"
    );

    let recovered = provider.unwrap_key(&wrapped).expect("TPM unwrap");
    assert_eq!(recovered.as_slice(), content_key.as_slice());
    eprintln!("EXERCISED: real TPM wrap/unwrap round-trip");
}

/// **Property:** the TPM refuses a wrapped key it did not produce.
///
/// This is the cross-machine binding guarantee, observed on one machine: a
/// foreign blob is *exactly* what a keystore copied from another host presents.
/// It must **fail**, not decode to something else — a decoy that decoded would be
/// far worse than an error, because the caller would then use those bytes as an
/// AES key.
///
/// The fixture is a wrapped blob of the right length with its ciphertext altered,
/// rather than random bytes of arbitrary length: a length-check rejection would
/// pass this test while proving nothing about the RSA-OAEP integrity check.
#[test]
fn the_tpm_refuses_a_wrapped_key_it_did_not_produce() {
    let (provider, bound) = provider();
    if !bound {
        eprintln!("NOT EXERCISED: no TPM on this host; foreign-blob refusal was NOT checked.");
        return;
    }

    let mut foreign = provider
        .wrap_key(&ContentKey::new([3u8; CONTENT_KEY_LEN]))
        .expect("TPM wrap");
    // Flip a bit in the middle of the RSA ciphertext: same length, same shape,
    // different content — the situation a blob from another device presents.
    let midpoint = foreign.len() / 2;
    foreign[midpoint] ^= 0x01;

    let outcome = provider.unwrap_key(&foreign);
    assert!(
        outcome.is_err(),
        "the TPM returned a key for a blob it did not wrap; that is the \
         cross-machine binding guarantee failing"
    );
    eprintln!("EXERCISED: real TPM refused a foreign wrapped key");
}

/// **Property:** the assembled backend reports the tier this host genuinely has,
/// and the two possible answers are both asserted rather than one being assumed.
///
/// Under `Optional` the call always returns, so this test observes the *tier*,
/// which is the thing a user surface renders.
#[test]
fn the_assembled_backend_reports_this_host_tier_truthfully() {
    let (_, bound) = provider();

    let backend = dig_keystore_hardware::bind_strongest(
        dig_keystore::testing::MemoryBackend::new(),
        dig_keystore::hardware::HardwarePolicy::Optional,
    )
    .expect("Optional always opens");

    if bound {
        assert_eq!(
            backend.tier(),
            &ProtectionTier::Hardware(HardwareKind::WindowsTpm20)
        );
        eprintln!("EXERCISED: end-to-end backend bound to the real TPM");
    } else {
        assert!(
            !backend.tier().is_hardware_bound(),
            "a host with no usable TPM must not report a hardware tier"
        );
        assert!(
            backend.tier().degrade_reason().is_some(),
            "a software tier must always carry its reason"
        );
        eprintln!("NOT EXERCISED: no TPM; the hardware tier path was NOT checked.");
    }
}
