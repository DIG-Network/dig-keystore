//! Per-platform trusted-component bindings, and the honest answer where there is
//! none.
//!
//! # What "not implemented" is allowed to say
//!
//! The temptation on a platform without a binding is to return a provider that
//! probes [`Absent`](dig_keystore::hardware::HardwareProbe::Absent), because it
//! reads as the safe default and it degrades cleanly. It is not safe: `Absent` is
//! a **confident claim about the machine**, and a build with no binding has not
//! looked at any machine. It would tell a user with a Secure Enclave that they do
//! not have one.
//!
//! So an unimplemented platform contributes **no candidate at all**, and the
//! reason surfaced is
//! [`PlatformUnsupported`](dig_keystore::hardware::DegradeReason::PlatformUnsupported)
//! — which names this build rather than the hardware.
//!
//! # The rule every provider classifies by
//!
//! Once a binding *does* exist, each provider has to sort every way it can fail
//! into `Absent` or
//! [`Indeterminate`](dig_keystore::hardware::HardwareProbe::Indeterminate), and
//! the two are not interchangeable: the ladder degrades on the first and fails
//! closed on the second under any policy stricter than
//! [`Optional`](dig_keystore::hardware::HardwarePolicy::Optional). One rule
//! decides it, and it is the same rule on every platform:
//!
//! > **Inspected, and no trusted component this process can use → `Absent`.
//! > Could not inspect at all → `Indeterminate`.**
//!
//! Both halves earn their place. Reading an inspected non-usability as
//! indeterminate makes an ordinary machine — a Linux host whose `/dev/tpmrm0`
//! belongs to a group this process is not in, a Mac whose binary carries no
//! Secure Enclave entitlement — unable to open its own keystore under the default
//! policy, which is the wrong failure direction for a ladder whose bottom rung is
//! already a fully sealed file. Reading an inability to inspect as an absence is
//! the confident lie the section above exists to forbid.

use std::sync::Arc;

use dig_keystore::hardware::{DegradeReason, HardwareProvider};

mod content_key;
pub mod linux;
pub mod tpm2;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

/// The trusted-component candidates for the target this build was compiled for,
/// in preference order.
///
/// Empty on a platform with no binding — see the module docs for why that is not
/// the same as an absence of hardware.
pub fn candidates() -> Vec<Arc<dyn HardwareProvider>> {
    // Every arm below calls a `detect` that NEVER fails: a host that cannot reach
    // its trusted component still yields a candidate, one that reports *why*.
    // Returning an empty list on failure would be quieter and wrong — the ladder
    // would settle on `NotRequested` and a strict policy would open a keystore it
    // should have refused.
    #[cfg(target_os = "windows")]
    {
        vec![Arc::new(windows::CngPlatformKeyProvider::detect()) as Arc<dyn HardwareProvider>]
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        vec![Arc::new(macos::SecureEnclaveProvider::detect()) as Arc<dyn HardwareProvider>]
    }
    #[cfg(target_os = "linux")]
    {
        vec![Arc::new(linux::LinuxTpmProvider::detect()) as Arc<dyn HardwareProvider>]
    }
    #[cfg(not(any(
        target_os = "windows",
        all(target_os = "macos", target_arch = "aarch64"),
        target_os = "linux"
    )))]
    {
        Vec::new()
    }
}

/// Why this build has no provider for the current platform, or `None` when it
/// does have one.
///
/// Callers that build their own ladder use this to report the *right* reason for
/// an empty candidate list, rather than the caller-shaped
/// [`NotRequested`](DegradeReason::NotRequested).
pub fn unsupported_reason() -> Option<DegradeReason> {
    #[cfg(any(
        target_os = "windows",
        all(target_os = "macos", target_arch = "aarch64"),
        target_os = "linux"
    ))]
    {
        None
    }
    // An Intel Mac has a Secure Enclave only behind a T2, and nothing in this
    // build can tell whether one is there. Rather than guess — in a direction
    // that either fails every Intel Mac closed or tells a T2 owner they have no
    // enclave — this stays exactly as it was before the binding existed. See
    // `macos` for the full reasoning.
    #[cfg(all(target_os = "macos", not(target_arch = "aarch64")))]
    {
        Some(DegradeReason::PlatformUnsupported {
            detail: "the Secure Enclave binding in this build covers Apple silicon only; \
                     whether this Intel Mac has a T2 was not determined"
                .to_owned(),
        })
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Some(DegradeReason::PlatformUnsupported {
            detail: "no hardware trusted-component binding exists for this target".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Property:** on a platform with no binding, the candidate list is empty
    /// AND a reason exists — the two must move together, or an unimplemented
    /// platform degrades with the caller-shaped `NotRequested` and the user is
    /// told nobody asked when in fact nobody could answer.
    ///
    /// Runs on every host; which arm it takes depends on the target, and both
    /// arms assert.
    #[test]
    fn an_absent_binding_and_an_unsupported_reason_agree() {
        match unsupported_reason() {
            Some(DegradeReason::PlatformUnsupported { detail }) => {
                assert!(
                    candidates().is_empty(),
                    "a platform reported as unsupported must offer no candidate"
                );
                assert!(!detail.is_empty(), "the reason must name what is missing");
            }
            Some(other) => panic!("an unsupported platform must say so: got {other:?}"),
            None => assert!(
                !candidates().is_empty(),
                "a platform with a binding must offer a candidate"
            ),
        }
    }

    /// **Property:** a candidate is never reported as absent hardware merely for
    /// being unavailable to this build.
    ///
    /// The nearest wrong implementation returns a provider that probes `Absent`
    /// on unimplemented platforms — clean, quiet, and a false statement about the
    /// user machine.
    #[test]
    fn an_unsupported_platform_never_claims_the_host_has_no_hardware() {
        assert!(
            !matches!(unsupported_reason(), Some(DegradeReason::NoHardwarePresent)),
            "`NoHardwarePresent` is a claim about the machine; this build inspected nothing"
        );
    }
}
