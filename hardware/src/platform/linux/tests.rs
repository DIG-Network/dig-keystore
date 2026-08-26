//! Provider tests. Like the codec, these run on **every** host: the classifier
//! they exercise is the code that runs on every machine WITHOUT a TPM, which is
//! almost every machine, and it decides whether such a host degrades or fails
//! closed.
//!
//! What is deliberately not here is a stand-in TPM. `detect_at` takes paths so a
//! test can supply a real sysfs-shaped directory and a real empty device
//! directory; it is not a seam for a fake device that answers commands. A double
//! that succeeded where silicon refuses would report a capability nobody had
//! verified, and the wrap/unwrap path is exactly the part this loop cannot
//! prove — see the residual evidence named in `SPEC.md` §17.5.

use super::*;
use crate::platform::tpm2;
use dig_keystore::hardware::CONTENT_KEY_LEN;
use tempfile::TempDir;

/// A sysfs-shaped directory in which the kernel has enumerated one TPM chip.
fn sysfs_with_a_chip() -> TempDir {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("tpm0")).unwrap();
    dir
}

/// **Proves:** a host where the kernel enumerates no TPM is a **confident
/// absence**, whether the enumeration directory is empty or missing entirely.
///
/// **Why it matters:** `Absent` and `Indeterminate` are treated differently by
/// the ladder — the first degrades to the software floor, the second fails
/// closed under any policy stricter than `Optional`. An empty `/sys/class/tpm`
/// is the kernel reporting that it looked and found nothing, which is a fact
/// about the host and not a failure to inspect it, so degrading is correct. Read
/// the other way, every container and VM in the world would be unable to open a
/// keystore.
///
/// **Both vehicles are asserted** because they reach different branches: an
/// empty directory reads successfully and yields no entries, a missing one fails
/// the read outright.
#[test]
fn a_host_with_no_enumerated_tpm_is_a_confident_absence() {
    let empty = TempDir::new().unwrap();
    let devices = TempDir::new().unwrap();

    let provider = LinuxTpmProvider::detect_at(empty.path(), devices.path());
    assert_eq!(provider.probe(), HardwareProbe::Absent);

    let missing = empty.path().join("no-such-subsystem");
    let provider = LinuxTpmProvider::detect_at(&missing, devices.path());
    assert_eq!(
        provider.probe(),
        HardwareProbe::Absent,
        "a kernel with no TPM subsystem offers this process no usable TPM"
    );
}

/// **Proves:** a host where a TPM IS enumerated but its device cannot be opened
/// is also a confident absence — not an indeterminate probe.
///
/// **Why it matters:** this is the ordinary case for an unprivileged process on
/// a machine whose `/dev/tpmrm0` belongs to the `tss` group. The TPM was
/// inspected; it is simply not usable by *this* process. Classifying it as
/// `Indeterminate` would make every such host fail closed under the default
/// policy and be unable to open its own keystore — the wrong failure direction
/// for a degrade ladder whose bottom rung is a fully sealed file.
///
/// **This is the assertion the previous test cannot make.** There the kernel
/// enumerated nothing, so the device was never reached; here enumeration
/// SUCCEEDS and the classification turns entirely on what the open failure
/// means.
#[test]
fn an_enumerated_tpm_this_process_cannot_open_is_a_confident_absence() {
    let sysfs = sysfs_with_a_chip();
    let devices = TempDir::new().unwrap();

    let provider = LinuxTpmProvider::detect_at(sysfs.path(), devices.path());
    assert_eq!(
        provider.probe(),
        HardwareProbe::Absent,
        "a TPM this process may not open is not a TPM it could not inspect"
    );
    assert!(
        format!("{provider:?}").contains("no usable TPM device"),
        "the operator must be told which device could not be opened: {provider:?}"
    );
}

/// **Proves:** a device that opens but does not answer like a TPM makes the
/// probe **`Indeterminate`**, not `Absent` — and that the transport surfaces a
/// nonsense answer as a refusal rather than acting on it.
///
/// **Why it matters:** this is the third classification arm and the only one
/// that fails closed. The kernel enumerated a chip and the device opened, so
/// nothing here is a statement that the host has no TPM; what happened is that
/// the conversation could not be believed. Under any policy stricter than
/// `Optional` that must refuse, and reporting it as `Absent` would silently
/// degrade a host whose trusted component is malfunctioning — the one case where
/// quietly dropping to software is least defensible.
///
/// **The fixture is a plain empty file, and that is the point.** It is strictly
/// LESS capable than a TPM: it accepts the command bytes and returns nothing.
/// A stand-in that answered `CreatePrimary` convincingly would let this test
/// report a wrap/unwrap capability nobody has observed on silicon, which is
/// exactly the evidence this crate does not have — see the module docs. Every
/// assertion here is that a refusal happens.
///
/// **Catches:** a transport that treats a short read as an empty success, and a
/// classifier that folds "answered nonsense" into "is not there".
#[test]
fn a_device_that_does_not_answer_like_a_tpm_is_indeterminate() {
    let sysfs = sysfs_with_a_chip();
    let devices = TempDir::new().unwrap();
    // Named as the resource manager so `open_device` selects it on the first
    // attempt, exactly as it would a real one.
    std::fs::write(devices.path().join("tpmrm0"), b"").unwrap();

    let provider = LinuxTpmProvider::detect_at(sysfs.path(), devices.path());

    assert!(
        matches!(provider.probe(), HardwareProbe::Indeterminate { .. }),
        "a device that answers nothing was inspected, not found absent: {provider:?}"
    );
    assert_eq!(
        provider.custody(),
        KeyCustody::ProcessMemory,
        "no key was established, so no custody claim is earned"
    );
    assert!(
        provider
            .wrap_key(&ContentKey::new([3u8; CONTENT_KEY_LEN]))
            .is_err(),
        "a provider that established no key must refuse to wrap"
    );
}

/// **Proves:** the two unavailability classes render their own detail, so an
/// operator reading a log learns which one they are in.
///
/// **Why it matters:** the difference between "there is no TPM here" and "the
/// TPM would not answer" is the difference between an expected degrade and a
/// broken machine, and the two reach the operator only through this text.
#[test]
fn each_unavailability_class_renders_its_own_reason() {
    assert_eq!(
        Unavailable::NotUsable("no TPM enumerated".to_owned()).to_string(),
        "no TPM enumerated"
    );
    assert_eq!(
        Unavailable::NotInspectable("the TPM did not answer".to_owned()).to_string(),
        "the TPM did not answer"
    );
    // Both variants render, because an operator reading only one of them cannot
    // tell an expected degrade from a broken machine.
}

/// A device file that answers the FIRST command written to it with `response`.
///
/// The device is opened read-write at offset zero, so `write_all` overwrites the
/// leading bytes and leaves the read position just past the command. Padding the
/// file with exactly one command's worth of filler therefore puts `response`
/// where the subsequent read lands.
///
/// **This is not a TPM and cannot become one.** It answers exactly one canned
/// message and every message it is used to send here is a REFUSAL. A fixture
/// that answered `CreatePrimary` affirmatively would manufacture a key handle
/// and let the suite report a wrap capability nobody has observed on silicon —
/// see the module docs. Refusals only.
fn device_answering(dir: &TempDir, response: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join("tpmrm0");
    let mut contents = vec![0u8; tpm2::create_primary_command().len()];
    contents.extend_from_slice(response);
    std::fs::write(&path, contents).unwrap();
    path
}

/// A well-formed, unsessioned TPM response carrying `rc` and no parameters.
fn refusal(rc: u32) -> Vec<u8> {
    let mut out = 0x8001u16.to_be_bytes().to_vec();
    out.extend_from_slice(&10u32.to_be_bytes());
    out.extend_from_slice(&rc.to_be_bytes());
    out
}

/// **Proves:** a TPM that answers `CreatePrimary` with an **authorization**
/// refusal is a confident `Absent`, while one that answers with a **transient**
/// refusal stays `Indeterminate`.
///
/// **Why it matters — this is a lockout, not a cosmetic misclassification.**
/// `create_primary_command` authorises against `TPM_RH_OWNER` with an empty
/// password. On a host whose owner hierarchy carries an authValue — enterprise
/// imaging, `tpm2_changeauth -c owner`, a Windows dual-boot — or which is in DA
/// lockout, the TPM answers with a non-zero response code. Classified
/// `Indeterminate`, that reason dominates the ladder, `degrade_under` errors
/// under the `#[default]` `Preferred` policy, and `HardwareBoundBackend` cannot
/// be constructed at all — so the user cannot **LOAD** an existing keystore,
/// not merely mint one. Those hosts opened at the software tier before the Linux
/// binding existed, so reading this as an uncertainty is a regression.
///
/// The answer is not an uncertainty: the TPM was reached, it understood the
/// command, and it said no. That is an **inspected** non-usability, which C-46
/// (`SPEC.md` §17.5) classifies `Absent` — degrade to the fully sealed software
/// floor, which is exactly what those hosts had before.
///
/// **The transient control is what keeps the fix one-sided.** `TPM_RC_RETRY`
/// (`0x922`) sits one value above `TPM_RC_LOCKOUT` (`0x921`) and means the TPM
/// could not answer *yet*. A fix that mapped every response code to `Absent`
/// would silently degrade a host whose TPM was merely busy — the failure
/// direction the fail-closed doctrine exists for — and this control fails it.
///
/// **Asserted through `detect_at`, not through the classifier**, because the
/// defect is a placement: the response code reaches `establish` and is discarded
/// there. A classifier proven in isolation would stay green with the discard
/// still in place.
#[test]
fn an_authorization_refusal_is_absent_and_a_transient_refusal_is_indeterminate() {
    let sysfs = sysfs_with_a_chip();

    // TPM_RC_BAD_AUTH on handle 1 — `0x1A2`, the DECORATED form a real device
    // sends, not the bare constant. A format-one code carries the offending
    // handle in bits 8-11, so a classifier comparing raw values matches the
    // constant in a unit test and nothing on hardware; driving the decorated
    // form through the whole path is what makes this test able to see that.
    let denied = TempDir::new().unwrap();
    device_answering(&denied, &refusal(0x1A2));
    let provider = LinuxTpmProvider::detect_at(sysfs.path(), denied.path());
    assert_eq!(
        provider.probe(),
        HardwareProbe::Absent,
        "an authorization refusal is an answer, not a failure to inspect: {provider:?}"
    );

    // TPM_RC_RETRY: the TPM could not answer yet. Nothing was established about
    // the host, so this must still fail closed.
    let busy = TempDir::new().unwrap();
    device_answering(&busy, &refusal(0x922));
    let provider = LinuxTpmProvider::detect_at(sysfs.path(), busy.path());
    assert!(
        matches!(provider.probe(), HardwareProbe::Indeterminate { .. }),
        "a transient refusal establishes nothing and must stay indeterminate: {provider:?}"
    );

    // Neither earns a custody claim: no key was established in either case.
    assert_eq!(provider.custody(), KeyCustody::ProcessMemory);
}

/// **Proves:** the fallback constructors never claim hardware custody.
///
/// **Why it matters:** `unreachable` and `absent` bind no key, so a
/// `NonExportable` claim from either would be unbacked by any refusal — exactly
/// the claim the [`HardwareProvider`] contract forbids, and the one that would
/// let a software-wrapped keystore present as hardware-bound.
///
/// **Both arms asserted:** a test covering only `unreachable` cannot see a wrong
/// `absent`.
#[test]
fn an_unbound_provider_never_claims_non_exportable_custody() {
    for provider in [
        LinuxTpmProvider::unreachable("the TPM did not answer"),
        LinuxTpmProvider::absent("no TPM enumerated"),
    ] {
        assert_eq!(provider.custody(), KeyCustody::ProcessMemory);
        assert!(!provider.custody().is_hardware_grade());
    }
}

/// **Proves:** an uninspectable host probes `Indeterminate` and a confidently
/// TPM-less one probes `Absent`.
///
/// **Why it matters:** these are the two answers the ladder treats differently,
/// so collapsing them here would defeat the fail-closed rule at its source.
#[test]
fn unreachable_probes_indeterminate_and_absent_probes_absent() {
    assert!(matches!(
        LinuxTpmProvider::unreachable("the TPM returned a malformed response").probe(),
        HardwareProbe::Indeterminate { .. }
    ));
    assert_eq!(
        LinuxTpmProvider::absent("no TPM enumerated").probe(),
        HardwareProbe::Absent
    );
}

/// **Proves:** an unbound provider refuses to wrap rather than returning
/// something wrap-shaped.
#[test]
fn an_unbound_provider_refuses_to_wrap() {
    let provider = LinuxTpmProvider::absent("no TPM enumerated");
    let err = provider
        .wrap_key(&ContentKey::new([7u8; CONTENT_KEY_LEN]))
        .expect_err("no key is bound, so nothing can be wrapped");
    assert!(matches!(err, KeystoreError::HardwareWrapFailed { .. }));
}

/// **Proves:** an unbound provider refuses to UNWRAP too.
///
/// Tested separately from the wrap arm because `unwrap_key` is the one whose
/// failure a caller is most tempted to treat as recoverable (`SPEC.md` §17.5b).
#[test]
fn an_unbound_provider_refuses_to_unwrap() {
    let err = LinuxTpmProvider::unreachable("the TPM did not answer")
        .unwrap_key(&[1, 2, 3, 4])
        .expect_err("no key is bound, so nothing can be unwrapped");
    assert!(
        matches!(err, KeystoreError::HardwareWrapFailed { .. }),
        "got {err:?}"
    );
}

/// **Proves:** the kind is fixed for this provider, whatever its binding state.
///
/// **Why it matters:** `HardwareKind` is the discriminant written into a sealed
/// envelope header, so a provider that reported a different kind when degraded
/// would let the class recorded in a blob depend on whether the TPM happened to
/// answer.
#[test]
fn the_hardware_kind_does_not_depend_on_the_binding_state() {
    assert_eq!(
        LinuxTpmProvider::absent("none").kind(),
        HardwareKind::LinuxTpm20
    );
    assert_eq!(
        LinuxTpmProvider::unreachable("down").kind(),
        HardwareKind::LinuxTpm20
    );
}

/// **Proves:** the diagnostic surface reports the binding state and the reason,
/// and renders nothing derived from key material.
///
/// **Why it matters:** `Debug` here is real code on the path an operator reads
/// when a TPM is not being used, and this crate holds seeds.
#[test]
fn the_diagnostic_surface_reports_state_without_rendering_key_material() {
    let rendered = format!("{:?}", LinuxTpmProvider::absent("no TPM enumerated"));
    assert!(rendered.contains("bound: false"), "got {rendered}");
    assert!(rendered.contains("ProcessMemory"), "got {rendered}");
    assert!(rendered.contains("Absent"), "got {rendered}");
    assert!(rendered.contains("no TPM enumerated"), "got {rendered}");
}
