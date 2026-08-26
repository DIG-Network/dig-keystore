//! Provider tests for the Secure Enclave binding.
//!
//! These are `cfg(target_os = "macos")` by construction — the module they test
//! links the Security framework — so they run on the macOS CI leg and nowhere
//! else. Everything asserted here is reachable **without** a Secure Enclave: the
//! classifier and the unbound constructors, which are the code that decides
//! whether a Mac degrades or fails closed. The wrap/unwrap path needs real SEP
//! silicon and is the named residual evidence in `SPEC.md` §17.5, not something
//! a stand-in is built for here.

use super::*;
use dig_keystore::hardware::CONTENT_KEY_LEN;

/// **Proves:** only a framework answer meaning "this process may not use the
/// Secure Enclave" is treated as a confident absence.
///
/// **Why it matters:** the nearest wrong implementation treats *any* failure as
/// "this Mac has no Secure Enclave", which would tell an M-series owner with a
/// locked keychain that their hardware does not exist. The opposite error is
/// just as bad in the other direction: classifying an entitlement failure as
/// indeterminate makes every unsigned binary fail closed under the default
/// policy and unable to open its own keystore.
///
/// **Catches:** a widened set, and the specific case of `None` — an error with
/// no `OSStatus` at all — being read as an absence rather than as an unknown.
#[test]
fn only_an_unusable_enclave_is_a_confident_absence() {
    assert!(is_confident_absence(Some(ERR_SEC_MISSING_ENTITLEMENT)));
    assert!(is_confident_absence(Some(ERR_SEC_UNIMPLEMENTED)));

    // errSecInteractionNotAllowed: the keychain is locked. The Secure Enclave is
    // emphatically still there.
    assert!(!is_confident_absence(Some(-25308)));
    // errSecAuthFailed.
    assert!(!is_confident_absence(Some(-25293)));
    // No code at all is an unknown, never an absence.
    assert!(!is_confident_absence(None));
}

/// **Proves:** the fallback constructors never claim hardware custody.
///
/// **Why it matters:** `unreachable` and `absent` bind no key, so a
/// `NonExportable` claim from either would be unbacked by any refusal — the
/// exact claim the trait forbids, and the one that would let a software-wrapped
/// keystore present as hardware-bound.
///
/// **Both arms asserted:** a test covering only `unreachable` cannot see a wrong
/// `absent`.
#[test]
fn an_unbound_provider_never_claims_non_exportable_custody() {
    for provider in [
        SecureEnclaveProvider::unreachable("keychain locked"),
        SecureEnclaveProvider::absent(),
    ] {
        assert_eq!(provider.custody(), KeyCustody::ProcessMemory);
        assert!(!provider.custody().is_hardware_grade());
    }
}

/// **Proves:** an unreachable enclave probes `Indeterminate` and a confidently
/// unusable one probes `Absent`.
///
/// **Why it matters:** these are the two answers the ladder treats differently —
/// one is an error under the default policy and the other a degrade — so
/// collapsing them here would defeat the fail-closed rule at its source.
#[test]
fn unreachable_probes_indeterminate_and_absent_probes_absent() {
    assert!(matches!(
        SecureEnclaveProvider::unreachable("keychain locked").probe(),
        HardwareProbe::Indeterminate { .. }
    ));
    assert_eq!(
        SecureEnclaveProvider::absent().probe(),
        HardwareProbe::Absent
    );
}

/// **Proves:** an unbound provider refuses to wrap rather than returning
/// something wrap-shaped.
#[test]
fn an_unbound_provider_refuses_to_wrap() {
    let err = SecureEnclaveProvider::unreachable("keychain locked")
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
    let err = SecureEnclaveProvider::absent()
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
/// would let the class recorded in a blob depend on whether the enclave happened
/// to answer.
#[test]
fn the_hardware_kind_does_not_depend_on_the_binding_state() {
    assert_eq!(
        SecureEnclaveProvider::absent().kind(),
        HardwareKind::MacSecureEnclave
    );
    assert_eq!(
        SecureEnclaveProvider::unreachable("down").kind(),
        HardwareKind::MacSecureEnclave
    );
}

/// **Proves:** the diagnostic surface reports the binding state without
/// rendering the key reference.
///
/// **Why it matters:** `SecureEnclaveProvider` holds a live `SecKeyRef`, so its
/// `Debug` is hand-written rather than derived. That makes it real code on the
/// path an operator reads when the enclave is not being used.
#[test]
fn the_diagnostic_surface_reports_state_without_rendering_the_key_reference() {
    let rendered = format!("{:?}", SecureEnclaveProvider::absent());
    assert!(rendered.contains("bound: false"), "got {rendered}");
    assert!(rendered.contains("ProcessMemory"), "got {rendered}");
    assert!(rendered.contains("Absent"), "got {rendered}");
    assert!(
        !rendered.contains("SecKeyRef") && !rendered.contains("0x"),
        "no key reference may reach a log line: {rendered}"
    );
}
