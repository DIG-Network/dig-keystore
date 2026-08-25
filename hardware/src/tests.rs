//! Composition tests: ladder → [`HardwareBoundBackend`] → the floor.
//!
//! [`ladder::tests`](crate::ladder) proves which rung is chosen. These prove that
//! the chosen rung is what the assembled backend actually reports and actually
//! does — a correct ladder wired into a backend that discards its verdict is
//! indistinguishable from a broken ladder, from where the user is standing.
//!
//! **Every test here runs on every host.** No TPM, no `#[cfg]` gate, no
//! `#[ignore]`.

use std::sync::Arc;

use dig_keystore::backend::{BackendKey, Exclusivity, KeychainBackend};
use dig_keystore::hardware::double::FakeDevice;
use dig_keystore::hardware::{
    envelope, DegradeReason, HardwareKind, HardwarePolicy, HardwareProvider,
};
use dig_keystore::testing::MemoryBackend;
use dig_keystore::{KeystoreError, Result};

use crate::bind_strongest_from;

/// A representative already-sealed keystore blob. The bytes are opaque here —
/// `dig-keystore` has already applied AES-256-GCM + Argon2id before anything in
/// this crate sees them, which is exactly why the floor is never bypassed.
const SEALED_BLOB: &[u8] = b"DIGK1\x00 pretend this is an argon2id-sealed v1 keystore";

fn key() -> BackendKey {
    BackendKey::new("identity")
}

fn one(device: FakeDevice) -> Vec<Arc<dyn HardwareProvider>> {
    vec![Arc::new(device) as Arc<dyn HardwareProvider>]
}

// ---------------------------------------------------------------------------
// The reason survives the composition
// ---------------------------------------------------------------------------

/// **Property — the one this composition exists to get right.** The reason the
/// ladder settled on reaches the assembled backend intact.
///
/// **Nearest wrong implementation:** the obvious one, and the one that was
/// written first here — hand the ladder's `Option<provider>` straight to
/// `HardwareBoundBackend::new`. It produces a backend that is correct in every
/// respect except that it reports
/// [`NotRequested`](DegradeReason::NotRequested): "nobody asked for hardware",
/// on a host that asked, looked, and found none.
///
/// Both are `Software`, both are `!is_hardware_bound()`, and both open the same
/// keystore — so **only the reason distinguishes them**, and it is asserted
/// directly rather than through `is_hardware_bound()`.
#[test]
fn a_settled_degrade_reason_is_not_replaced_by_not_requested() {
    let backend = bind_strongest_from(
        MemoryBackend::new(),
        &one(FakeDevice::absent(HardwareKind::WindowsTpm20)),
        HardwarePolicy::Optional,
    )
    .expect("Optional always opens");

    assert_eq!(
        backend.tier().degrade_reason(),
        Some(&DegradeReason::NoHardwarePresent),
        "the host WAS inspected; reporting `NotRequested` would say nobody asked"
    );
}

/// **The control:** when there genuinely was no candidate, `NotRequested` is the
/// right answer and must still be reachable.
///
/// Without this, an implementation that reported `NoHardwarePresent`
/// unconditionally would pass the test above.
#[test]
fn an_empty_candidate_list_still_reports_not_requested() {
    let backend = bind_strongest_from(MemoryBackend::new(), &[], HardwarePolicy::Optional)
        .expect("Optional always opens");

    assert_eq!(
        backend.tier().degrade_reason(),
        Some(&DegradeReason::NotRequested)
    );
}

/// **Property:** a proven candidate produces a backend that reports the hardware
/// tier and names the right class.
#[test]
fn a_proven_candidate_produces_a_hardware_tier() {
    let backend = bind_strongest_from(
        MemoryBackend::new(),
        &one(FakeDevice::working(HardwareKind::WindowsTpm20, 1)),
        HardwarePolicy::Preferred,
    )
    .expect("proven");

    assert!(backend.tier().is_hardware_bound());
    assert_eq!(
        backend.tier().hardware_kind(),
        Some(HardwareKind::WindowsTpm20)
    );
}

// ---------------------------------------------------------------------------
// The floor
// ---------------------------------------------------------------------------

/// **Property:** on a degraded host the bytes that reach storage are the caller's
/// already-sealed blob, **byte for byte** — never a bare secret, and never a
/// half-applied envelope.
///
/// **Nearest wrong implementation:** one that writes a `DIGHW1` envelope with an
/// empty or identity wrapping when no provider is present. That still "works" —
/// it round-trips — while advertising hardware protection in the stored bytes
/// that nothing backs. Asserting the round-trip alone cannot see it; asserting
/// the *stored* bytes can.
#[test]
fn a_degraded_host_writes_the_untouched_sealed_blob() {
    let backend = bind_strongest_from(
        MemoryBackend::new(),
        &one(FakeDevice::absent(HardwareKind::WindowsTpm20)),
        HardwarePolicy::Optional,
    )
    .expect("Optional always opens");

    backend.write(&key(), SEALED_BLOB).expect("write");

    let stored = backend.inner().read(&key()).expect("stored bytes");
    assert_eq!(
        stored, SEALED_BLOB,
        "a host with no hardware must write exactly the bytes it always wrote"
    );
    assert!(
        !envelope::is_envelope(&stored),
        "an unwrapped blob must not carry an envelope that claims a wrapping"
    );
}

/// **Property:** on a bound host the stored bytes are an envelope, and the
/// caller blob is not sitting in them in the clear.
///
/// The second assertion is the one worth having: an envelope that merely
/// *prefixes* the plaintext would satisfy `is_envelope` and round-trip perfectly.
#[test]
fn a_bound_host_writes_an_envelope_that_does_not_contain_the_blob() {
    let backend = bind_strongest_from(
        MemoryBackend::new(),
        &one(FakeDevice::working(HardwareKind::WindowsTpm20, 1)),
        HardwarePolicy::Preferred,
    )
    .expect("proven");

    backend.write(&key(), SEALED_BLOB).expect("write");
    let stored = backend.inner().read(&key()).expect("stored bytes");

    assert!(envelope::is_envelope(&stored));
    assert!(
        !stored.windows(SEALED_BLOB.len()).any(|w| w == SEALED_BLOB),
        "the wrapped blob must not appear verbatim inside its own envelope"
    );
    assert_eq!(backend.read(&key()).expect("read"), SEALED_BLOB);
}

/// **Property — the whole point of hardware binding.** A blob sealed on one
/// device does not open on another.
///
/// Two devices differing only in their device key stand for two machines. The
/// second must **fail**, and fail as a hardware refusal rather than by returning
/// different bytes — a decoy that decoded to garbage would be far worse than an
/// error, because the caller would then try to use it as a keystore.
#[test]
fn a_blob_sealed_on_one_device_does_not_open_on_another() {
    let device_a = FakeDevice::working(HardwareKind::WindowsTpm20, 1);
    let sealed = {
        let backend = bind_strongest_from(
            MemoryBackend::new(),
            &one(device_a),
            HardwarePolicy::Preferred,
        )
        .expect("proven");
        backend.write(&key(), SEALED_BLOB).expect("write");
        backend.inner().read(&key()).expect("stored bytes")
    };

    // A different machine: same hardware class, different device key.
    let elsewhere = MemoryBackend::new();
    elsewhere
        .write(&key(), &sealed)
        .expect("copy the blob over");
    let backend = bind_strongest_from(
        elsewhere,
        &one(FakeDevice::working(HardwareKind::WindowsTpm20, 2)),
        HardwarePolicy::Preferred,
    )
    .expect("the second machine has working hardware of its own");

    let err = backend
        .read(&key())
        .expect_err("a copied blob must not open on another device");
    assert!(
        matches!(err, KeystoreError::HardwareUnwrapFailed { .. }),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// The three-valued existence read survives the composition
// ---------------------------------------------------------------------------

/// A backend whose existence probe cannot answer — a failing mount, an
/// unreadable parent, an `EIO`.
///
/// It answers `Err` from `exists` while `read` would too, so the double cannot
/// accidentally make the composed backend look three-valued by some other route.
struct UnreadableBackend;

impl KeychainBackend for UnreadableBackend {
    fn read(&self, _key: &BackendKey) -> Result<Vec<u8>> {
        Err(unreadable())
    }
    fn write(&self, _key: &BackendKey, _data: &[u8]) -> Result<()> {
        Err(unreadable())
    }
    fn write_new(&self, _key: &BackendKey, _data: &[u8]) -> Result<()> {
        Err(unreadable())
    }
    fn delete(&self, _key: &BackendKey) -> Result<()> {
        Err(unreadable())
    }
    fn list(&self, _prefix: &str) -> Result<Vec<BackendKey>> {
        Err(unreadable())
    }
    fn exists(&self, _key: &BackendKey) -> Result<bool> {
        Err(unreadable())
    }
}

fn unreadable() -> KeystoreError {
    KeystoreError::Backend(std::sync::Arc::new(std::io::Error::other(
        "simulated I/O fault",
    )))
}

/// **Property:** an existence probe that *could not answer* stays unanswered
/// through the hardware composition — it never becomes `Ok(false)`.
///
/// This is the dig-keystore#16 defect class, and this crate is where it would be
/// most expensive: `Keystore::create_with_rng` uses this answer to decide whether
/// to **mint**, and `write` replaces. A spurious `false` overwrites the existing
/// blob — and once that blob is hardware-wrapped, the overwrite is not
/// recoverable from any backup of the file, because the TPM key that opened it
/// was never the file.
///
/// Asserted through the *composed* backend rather than the inner one, because the
/// composition is where a well-meaning `unwrap_or(false)` would be added.
#[test]
fn an_unanswerable_existence_probe_stays_unanswered_through_the_composition() {
    let backend = bind_strongest_from(
        UnreadableBackend,
        &one(FakeDevice::working(HardwareKind::WindowsTpm20, 1)),
        HardwarePolicy::Preferred,
    )
    .expect("proven");

    let outcome = backend.exists(&key());
    assert!(
        outcome.is_err(),
        "an I/O fault must not read as a confident absence; got {outcome:?}"
    );
}

/// **The control:** a backend that CAN answer still answers, on both arms.
///
/// Without it, a composition that returned `Err` from `exists` unconditionally
/// would pass the test above — and would refuse to mint on every host.
#[test]
fn an_answerable_existence_probe_answers_both_ways() {
    let backend = bind_strongest_from(
        MemoryBackend::new(),
        &one(FakeDevice::working(HardwareKind::WindowsTpm20, 1)),
        HardwarePolicy::Preferred,
    )
    .expect("proven");

    assert!(
        !backend.exists(&key()).expect("answerable"),
        "a vacant key is confidently absent, not an error"
    );
    backend.write(&key(), SEALED_BLOB).expect("write");
    assert!(
        backend.exists(&key()).expect("answerable"),
        "a written key is confidently present"
    );
}

/// **Property:** the exclusivity a caller relies on to avoid clobbering is the
/// *inner* backend's real one, not a stronger one invented by the wrapper.
///
/// `create_with_rng` consults `write_new_exclusivity()` to decide whether
/// `write_new` alone is enough. A wrapper that claimed `Atomic` over a
/// `BestEffort` store would move the overwrite race rather than remove it, and
/// would do so while looking safer.
#[test]
fn exclusivity_is_reported_from_the_inner_backend_not_invented() {
    let inner_claim = MemoryBackend::new().write_new_exclusivity();
    let backend = bind_strongest_from(
        MemoryBackend::new(),
        &one(FakeDevice::working(HardwareKind::WindowsTpm20, 1)),
        HardwarePolicy::Preferred,
    )
    .expect("proven");

    assert_eq!(backend.write_new_exclusivity(), inner_claim);
    // And the claim is a real one, not the vacuous default: a wrapper that
    // returned `BestEffort` regardless would pass the equality above if the
    // inner backend happened to be `BestEffort` too.
    assert!(matches!(
        inner_claim,
        Exclusivity::Atomic | Exclusivity::BestEffort
    ));
}

/// **Property:** `write_new` refuses to replace an existing blob through the
/// composition.
///
/// The hardware wrapper sits between `create_with_rng` and storage, so a wrapper
/// that reached for `write` instead of `write_new` would reinstate exactly the
/// overwrite dig-keystore#16 removed — silently, since the write would succeed.
#[test]
fn write_new_refuses_to_replace_through_the_composition() {
    let backend = bind_strongest_from(
        MemoryBackend::new(),
        &one(FakeDevice::working(HardwareKind::WindowsTpm20, 1)),
        HardwarePolicy::Preferred,
    )
    .expect("proven");

    backend.write_new(&key(), SEALED_BLOB).expect("first mint");
    let first = backend.inner().read(&key()).expect("stored");

    backend
        .write_new(&key(), b"a second, different keystore")
        .expect_err("write_new must not replace an existing keystore");

    assert_eq!(
        backend.inner().read(&key()).expect("stored"),
        first,
        "the original bytes must be untouched after a refused write_new"
    );
}

// ---------------------------------------------------------------------------
// The caller's policy must survive the composition
// ---------------------------------------------------------------------------
//
// `bind_strongest_from` resolves the tier TWICE: the ladder self-tests a
// candidate to choose it, and `HardwareBoundBackend::new` then re-resolves so
// that ONE authority owns every `Hardware` claim. That second resolution is not
// redundant — it is an independent chance to fail, and the policy governing it
// is the caller's, not this crate's.
//
// The four tests below are a set, and each is needed. Two assert refusal and two
// assert binding: a suite of refusals alone would pass just as happily against an
// implementation that hardcoded `Required` and refused honest hardware, which is
// a different defect with the same test result.

/// A device that passes inspection, is selected by the ladder, and is then
/// refuted by the backend's own self-test.
///
/// `failing_unwrap_after(1)` spends its single honest unwrap on the ladder's
/// self-test, so the second resolution is the first to see it broken. This is
/// the double's own model of "healthy when inspected, unusable moments later".
fn breaks_after_selection() -> Vec<Arc<dyn HardwareProvider>> {
    vec![Arc::new(
        FakeDevice::working(HardwareKind::WindowsTpm20, 1).failing_unwrap_after(1),
    )]
}

/// A device that is inspectable once — enough for the ladder — and uninspectable
/// when the backend re-probes it. A TPM contended by BitLocker or Credential
/// Guard between the two resolutions.
fn uninspectable_after_selection() -> Vec<Arc<dyn HardwareProvider>> {
    vec![Arc::new(
        FakeDevice::working(HardwareKind::WindowsTpm20, 1).indeterminate_probe_after(1),
    )]
}

fn honest() -> Vec<Arc<dyn HardwareProvider>> {
    vec![Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 1))]
}

/// **Property:** `Required` refuses when the SECOND resolution refutes the
/// device, not merely when the first one does.
///
/// `Required` is documented as "anything other than a self-tested working
/// hardware component is an error; the keystore does not open." A caller that
/// asked for mandatory hardware and receives `Ok` writes a keystore portable to
/// any machine — the precise opposite of what it asked for — and nothing
/// anywhere reports an error.
///
/// Asserted on the RETURN of `bind_strongest_from` rather than on a tier, because
/// the defect is that a value crossing a function boundary was replaced: an
/// implementation that reports the right tier while returning `Ok` is exactly the
/// broken one.
#[test]
fn required_refuses_a_device_the_backends_own_self_test_refutes() {
    let err = bind_strongest_from(
        MemoryBackend::new(),
        &breaks_after_selection(),
        HardwarePolicy::Required,
    )
    .expect_err("Required must not open over a refuted self-test");

    // The refusal must come from the mandatory-hardware rule. A device that is
    // refuted by a self-test is `HardwareUnusable`, which is a CONFIDENT
    // negative — so this is `Required`'s rule firing, not the indeterminate one.
    assert!(
        matches!(err, KeystoreError::HardwareRequired { .. }),
        "expected the mandatory-hardware refusal, got {err:?}"
    );
}

/// **Property:** `Preferred` fails closed when the RE-probe cannot inspect the
/// device.
///
/// This is verbatim the downgrade `src/hardware/backend.rs` exists to prevent:
/// "a transient probe failure silently strips hardware protection from a machine
/// that has it, and the resulting software blob then opens anywhere." The rule
/// was enforced on the first resolution and dropped on the second.
#[test]
fn preferred_fails_closed_when_the_reprobe_cannot_inspect_the_device() {
    let err = bind_strongest_from(
        MemoryBackend::new(),
        &uninspectable_after_selection(),
        HardwarePolicy::Preferred,
    )
    .expect_err("Preferred must not downgrade an uninspectable device into an absence");

    // The SPECIFIC variant, not merely "an error": it proves the refusal came
    // from the indeterminate rule rather than from the blanket `Required` rule,
    // which is the distinction between fixing this defect and hiding it behind a
    // stricter policy.
    assert!(
        matches!(err, KeystoreError::HardwareProbeIndeterminate { .. }),
        "expected the fail-closed indeterminate refusal, got {err:?}"
    );
}

/// **The control that makes the two refusals mean something.**
///
/// Without it, both tests above pass against an implementation that hardcoded
/// `Required` — or one that simply refused everything. An honest device must
/// still bind, and must still report a genuine hardware tier.
#[test]
fn an_honest_device_still_binds_under_required() {
    let backend = bind_strongest_from(MemoryBackend::new(), &honest(), HardwarePolicy::Required)
        .expect("an honest, self-tested device satisfies Required");

    assert!(
        backend.tier().is_hardware_bound(),
        "got {:?}",
        backend.tier()
    );
}

/// **The second control:** the policy is THREADED, not merely made stricter.
///
/// The same device that `Required` refuses above must still open under
/// `Optional`, degraded and honest about why. An implementation that hardcoded
/// `Required` would fail here, and one that hardcoded `Optional` would fail the
/// two refusals — so only passing the caller's policy through satisfies all four.
#[test]
fn optional_still_opens_degraded_over_the_same_refuted_device() {
    let backend = bind_strongest_from(
        MemoryBackend::new(),
        &breaks_after_selection(),
        HardwarePolicy::Optional,
    )
    .expect("Optional opens on any host");

    assert!(
        !backend.tier().is_hardware_bound(),
        "a refuted device must not be reported as hardware"
    );
    assert!(
        matches!(
            backend.tier().degrade_reason(),
            Some(DegradeReason::HardwareUnusable { .. })
        ),
        "the reason must name the refutation, got {:?}",
        backend.tier().degrade_reason()
    );
}
