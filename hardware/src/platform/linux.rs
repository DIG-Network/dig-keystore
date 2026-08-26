//! Linux TPM 2.0 binding, spoken directly to the kernel resource manager.
//!
//! # What the silicon actually guarantees
//!
//! The wrapping key is a **primary key in the owner hierarchy** created with
//! `fixedTPM | fixedParent` (see [`tpm2::WRAP_KEY_ATTRS`]), so its private half
//! can never be duplicated off the device. That, and only that, is what a
//! [`ProtectionTier::Hardware`](dig_keystore::hardware::ProtectionTier::Hardware)
//! claim means: a keystore sealed here does not open on another machine.
//!
//! A primary key is derived deterministically from the hierarchy seed and the
//! template, so the same key reappears on every boot with nothing persisted —
//! no owner authorisation, no `EvictControl`, no state outside the TPM. The cost
//! is that deriving an RSA primary is slow on real silicon (seconds, sometimes
//! tens of seconds); it happens once per provider, and persisting the key to a
//! handle to avoid it is deliberately left as later work rather than guessed at
//! here.
//!
//! # Why `/dev/tpmrm0`
//!
//! The kernel **resource manager** device virtualises the TPM's very small
//! transient-object memory across processes. Talking to `/dev/tpm0` directly
//! takes exclusive ownership and evicts whatever else was using the chip —
//! systemd, disk encryption, an attestation agent. `tpm0` is used only when the
//! resource manager is absent.
//!
//! # Non-exportability is asserted, never assumed
//!
//! [`HardwareProvider::custody`] may report
//! [`NonExportable`](KeyCustody::NonExportable) only after the platform has
//! actually refused an export. So construction does two things, and **both**
//! must hold: it reads the key back with `TPM2_ReadPublic` and requires the
//! TPM's *own* description to carry `fixedTPM | fixedParent` — requesting a
//! property in a template and observing it in the device's answer are different
//! claims — and it then attempts a real `TPM2_Duplicate` off the device and
//! requires it to fail.
//!
//! # This module compiles on every target, and that is deliberate
//!
//! It uses nothing but `std`, so unlike the Windows binding it needs no
//! target-gated dependency. Compiling it everywhere means its unit tests run on
//! every host and every CI leg rather than only on Linux. Only the *wiring* into
//! [`super::candidates`] is `cfg(target_os = "linux")` — on any other target the
//! sysfs enumeration simply finds nothing, which is the correct answer there.

use std::fmt;
use std::path::Path;

use zeroize::Zeroizing;

use dig_keystore::hardware::{
    ContentKey, HardwareKind, HardwareProbe, HardwareProvider, KeyCustody,
};
use dig_keystore::{KeystoreError, Result};

use super::content_key;
use session::{TpmSession, Unavailable};

mod session;

/// Where the kernel enumerates the TPM chips it has found.
const SYSFS_TPM_CLASS: &str = "/sys/class/tpm";

/// Where the TPM character devices live.
const DEVICE_DIR: &str = "/dev";

/// How this component names itself in a refusal an operator reads.
const COMPONENT: &str = "the TPM";

/// A [`HardwareProvider`] backed by a non-exportable TPM 2.0 primary key.
pub struct LinuxTpmProvider {
    /// `None` when this provider could not establish a key — it then exists
    /// only to report why.
    session: Option<TpmSession>,
    /// The custody this provider is entitled to claim, decided at construction
    /// by reading the key back and attempting a real export. Never widened
    /// afterwards.
    custody: KeyCustody,
    /// What [`probe`](HardwareProvider::probe) will answer.
    probe: HardwareProbe,
    /// Non-secret sentence describing how this provider came to be in the state
    /// it is in. Empty when a key was established.
    detail: String,
}

impl fmt::Debug for LinuxTpmProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxTpmProvider")
            .field("bound", &self.session.is_some())
            .field("custody", &self.custody)
            .field("probe", &self.probe)
            .field("detail", &self.detail)
            .finish()
    }
}

impl LinuxTpmProvider {
    /// The correctly-classified provider for this host — never an error.
    ///
    /// This is the constructor callers want; a host with no TPM still yields a
    /// candidate, one that reports *why*. Returning nothing on failure would be
    /// quieter and wrong: the ladder would settle on the caller-shaped
    /// `NotRequested` and a strict policy would open a keystore it should have
    /// refused.
    pub fn detect() -> Self {
        Self::detect_at(Path::new(SYSFS_TPM_CLASS), Path::new(DEVICE_DIR))
    }

    /// [`detect`](Self::detect) against explicit paths.
    ///
    /// The seam exists so the *enumeration and classification* — which is the
    /// code that runs on every host that has no TPM, and therefore on almost
    /// every host — can be driven from a test with real directories. It is
    /// deliberately **not** a seam for faking the device: a stand-in that
    /// answered TPM commands would prove nothing about the silicon that will
    /// actually run this, and would report a capability nobody had verified.
    pub fn detect_at(sysfs: &Path, device_dir: &Path) -> Self {
        match TpmSession::establish(sysfs, device_dir) {
            Ok(session) => {
                // The MUST from the trait contract: claim `NonExportable` only
                // after the platform has refused an export.
                let custody = if session.export_is_refused() {
                    KeyCustody::NonExportable
                } else {
                    KeyCustody::ProcessMemory
                };
                Self {
                    session: Some(session),
                    custody,
                    probe: HardwareProbe::Available(HardwareKind::LinuxTpm20),
                    detail: String::new(),
                }
            }
            Err(Unavailable::NotUsable(detail)) => Self::absent(detail),
            Err(Unavailable::NotInspectable(detail)) => Self::unreachable(detail),
        }
    }

    /// A provider that binds nothing and reports `detail` as an
    /// **indeterminate** probe.
    ///
    /// Surfacing the failure this way — rather than omitting the candidate —
    /// keeps a policy stricter than
    /// [`Optional`](dig_keystore::hardware::HardwarePolicy::Optional) failing
    /// closed, which is the entire point of the three-valued probe.
    pub fn unreachable(detail: impl fmt::Display) -> Self {
        let detail = detail.to_string();
        Self {
            session: None,
            custody: KeyCustody::ProcessMemory,
            probe: HardwareProbe::indeterminate(&detail),
            detail,
        }
    }

    /// A provider reporting a *confident* absence: the host was inspected and
    /// has no TPM this process can use.
    ///
    /// `detail` survives in [`Debug`](fmt::Debug) even though
    /// [`Absent`](HardwareProbe::Absent) carries nothing — a confident negative
    /// has no degrees, but an operator asking why their TPM is not being used
    /// still needs the sentence.
    pub fn absent(detail: impl fmt::Display) -> Self {
        Self {
            session: None,
            custody: KeyCustody::ProcessMemory,
            probe: HardwareProbe::Absent,
            detail: detail.to_string(),
        }
    }

    fn session(&self) -> Result<&TpmSession> {
        self.session
            .as_ref()
            .ok_or_else(|| KeystoreError::HardwareWrapFailed {
                detail: "no TPM key is bound to this provider".to_owned(),
            })
    }
}

impl HardwareProvider for LinuxTpmProvider {
    fn kind(&self) -> HardwareKind {
        HardwareKind::LinuxTpm20
    }

    fn probe(&self) -> HardwareProbe {
        self.probe.clone()
    }

    fn custody(&self) -> KeyCustody {
        self.custody
    }

    fn wrap_key(&self, content_key: &ContentKey) -> Result<Vec<u8>> {
        self.session()?.wrap(content_key.as_slice()).map_err(|e| {
            KeystoreError::HardwareWrapFailed {
                detail: e.to_string(),
            }
        })
    }

    fn unwrap_key(&self, wrapped: &[u8]) -> Result<ContentKey> {
        // Zeroizing from the moment the plaintext exists, so every exit below —
        // including the wrong-length refusal — wipes it.
        let plain = Zeroizing::new(self.session()?.unwrap(wrapped).map_err(|e| {
            KeystoreError::HardwareUnwrapFailed {
                detail: e.to_string(),
            }
        })?);

        content_key::from_recovered(&plain, COMPONENT)
            .map_err(|detail| KeystoreError::HardwareUnwrapFailed { detail })
    }
}

#[cfg(test)]
mod tests;
