//! Per-platform trusted-component bindings, and the honest answer where there is
//! none.
//!
//! # What "not implemented" is allowed to say
//!
//! Only one platform binding ships today. The temptation on the other two is to
//! return a provider that probes
//! [`Absent`](dig_keystore::hardware::HardwareProbe::Absent), because it reads as
//! the safe default and it degrades cleanly. It is not safe: `Absent` is a
//! **confident claim about the machine**, and a build with no macOS binding has
//! not looked at any Mac. It would tell a user with a Secure Enclave that they do
//! not have one.
//!
//! So an unimplemented platform contributes **no candidate at all**, and the
//! reason surfaced is
//! [`PlatformUnsupported`](dig_keystore::hardware::DegradeReason::PlatformUnsupported)
//! — which names this build rather than the hardware.

use std::sync::Arc;

use dig_keystore::hardware::{DegradeReason, HardwareProvider};

#[cfg(target_os = "windows")]
pub mod windows;

/// The trusted-component candidates for the target this build was compiled for,
/// in preference order.
///
/// Empty on a platform with no binding — see the module docs for why that is not
/// the same as an absence of hardware.
pub fn candidates() -> Vec<Arc<dyn HardwareProvider>> {
    #[cfg(target_os = "windows")]
    {
        // `detect` never fails: a host that cannot reach CNG still yields a
        // candidate, one that reports *why*. Returning an empty list on failure
        // would be quieter and wrong — the ladder would settle on `NotRequested`
        // and a strict policy would open a keystore it should have refused.
        vec![Arc::new(windows::CngPlatformKeyProvider::detect()) as Arc<dyn HardwareProvider>]
    }
    #[cfg(not(target_os = "windows"))]
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
    #[cfg(target_os = "windows")]
    {
        None
    }
    #[cfg(target_os = "macos")]
    {
        Some(DegradeReason::PlatformUnsupported {
            detail: "macOS Secure Enclave binding is not implemented in this build \
                     (dig_ecosystem #1693); the host was not inspected"
                .to_owned(),
        })
    }
    #[cfg(target_os = "linux")]
    {
        Some(DegradeReason::PlatformUnsupported {
            detail: "Linux TPM 2.0 binding is not implemented in this build \
                     (dig_ecosystem #1693); the host was not inspected"
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
