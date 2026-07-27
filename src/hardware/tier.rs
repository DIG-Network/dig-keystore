//! The protection-tier vocabulary: what protects the key material, and how
//! confident we are about it.
//!
//! # Why this module is only types
//!
//! The single most dangerous outcome for a hardware-binding feature is a
//! caller that *believes* a key is hardware-bound when it is not. A UI that
//! renders "protected by your TPM" over a plain software-wrapped file has
//! actively misled the user about the security of their wallet. So the honest
//! answer is encoded in the **type**, not left to a convention:
//!
//! - [`ProtectionTier`] is **total** — there is no "unknown" and no `Option`.
//!   Every keystore has exactly one tier, always answerable.
//! - [`ProtectionTier::Software`] **carries its [`DegradeReason`] inline**, so
//!   "we degraded" can never be reported without saying why. A reason held in
//!   a separate `Option` field would let an `if let Some(reason)` check skip
//!   silently when the field was absent, and an absent field is more dangerous
//!   than a wrong one.
//! - [`HardwareProbe`] distinguishes **`Absent`** ("there is definitively no
//!   hardware here") from **`Indeterminate`** ("I could not determine whether
//!   there is hardware"). Collapsing those two is the same defect class as a
//!   `bool` that cannot say "I could not check": it converts an inspection
//!   failure into a confident negative.

use std::fmt;

/// A class of OS hardware trusted component that can hold a non-exportable
/// wrapping key.
///
/// The discriminant is a stable wire id: it is written into the
/// [`envelope`](super::envelope) header, so a blob records which hardware
/// class sealed it. Values are **append-only** — never renumber or repurpose
/// one (§5.1: a sealed blob is permanent at-rest data).
///
/// `#[non_exhaustive]`: append-only means this WILL grow, so a downstream `match`
/// must carry a wildcard arm rather than break each time hardware is added.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HardwareKind {
    /// Windows TPM 2.0, reached through the CNG **Platform Crypto Provider**.
    WindowsTpm20,
    /// Apple **Secure Enclave** (`kSecAttrTokenIDSecureEnclave`).
    MacSecureEnclave,
    /// Linux TPM 2.0 via the tpm2 software stack.
    LinuxTpm20,
}

impl HardwareKind {
    /// Stable on-wire discriminant written into a sealed envelope header.
    pub const fn wire_id(self) -> u8 {
        match self {
            Self::WindowsTpm20 => 0x01,
            Self::MacSecureEnclave => 0x02,
            Self::LinuxTpm20 => 0x03,
        }
    }

    /// Parse a wire discriminant, or `None` for an id this build does not know.
    ///
    /// An unknown id is a *forward*-compatibility case, not corruption: a
    /// newer writer may have sealed with hardware this build has no name for.
    /// The caller reports it as unopenable-here rather than as a bad file.
    pub const fn from_wire_id(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(Self::WindowsTpm20),
            0x02 => Some(Self::MacSecureEnclave),
            0x03 => Some(Self::LinuxTpm20),
            _ => None,
        }
    }

    /// Short human label for logs and UI.
    pub const fn label(self) -> &'static str {
        match self {
            Self::WindowsTpm20 => "Windows TPM 2.0",
            Self::MacSecureEnclave => "Apple Secure Enclave",
            Self::LinuxTpm20 => "Linux TPM 2.0",
        }
    }
}

impl fmt::Display for HardwareKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Why a keystore is software-wrapped rather than hardware-bound.
///
/// Always present alongside [`ProtectionTier::Software`] — a degrade is never
/// reportable without its cause.
///
/// `#[non_exhaustive]`: new ways to fail to bind will be discovered, and a
/// consumer should treat an unfamiliar reason as "not hardware-bound" rather than
/// fail to compile.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DegradeReason {
    /// The host was inspected successfully and has no usable hardware trusted
    /// component. This is a *confident* negative.
    NoHardwarePresent,

    /// The host **could not be inspected**: the probe errored, timed out, or
    /// returned nothing intelligible. We do not know whether hardware exists.
    ///
    /// Distinct from [`NoHardwarePresent`](Self::NoHardwarePresent) on purpose.
    /// Under any policy stricter than [`HardwarePolicy::Optional`] this is an
    /// error rather than a degrade (fail closed) — see
    /// [`HardwarePolicy`].
    ProbeIndeterminate {
        /// Non-secret detail of why the probe could not answer.
        detail: String,
    },

    /// Hardware was detected but failed its self-test, so it cannot be trusted
    /// to wrap or later unwrap key material.
    ///
    /// A probe that says "present" is a claim, not a proof; this reason exists
    /// because the claim is verified by use and can be refuted.
    HardwareUnusable {
        /// Non-secret detail of the failing operation.
        detail: String,
    },

    /// No hardware binding was attempted — the caller supplied no provider or
    /// explicitly opted out.
    NotRequested,

    /// **This particular blob** is not hardware-wrapped, whatever the host is
    /// capable of.
    ///
    /// The reason a keystore written before hardware binding existed — or
    /// written on a host that had none — reports a software tier even on a
    /// hardware-capable machine. Only rewriting the blob on such a host binds
    /// it; a capable host does not retroactively protect bytes already at rest.
    BlobNotWrapped,
}

impl fmt::Display for DegradeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHardwarePresent => f.write_str("no hardware trusted component on this host"),
            Self::ProbeIndeterminate { detail } => {
                write!(f, "could not determine hardware availability: {detail}")
            }
            Self::HardwareUnusable { detail } => {
                write!(f, "hardware present but unusable: {detail}")
            }
            Self::NotRequested => f.write_str("hardware binding not requested"),
            Self::BlobNotWrapped => f.write_str("this key material is not hardware-wrapped"),
        }
    }
}

/// What actually protects a keystore's wrapping key, reported truthfully.
///
/// Total by construction: there is no third "unknown" state and no `Option`
/// wrapper, so a caller can always ask [`is_hardware_bound`](Self::is_hardware_bound)
/// and get a real answer.
///
/// Deliberately **not** `#[non_exhaustive]`, unlike the enums it is built from.
/// The point of this type is that exactly two outcomes exist and a consumer must
/// handle both; allowing a wildcard arm would let the software case be swept into
/// a catch-all, which is precisely the mistake the type exists to prevent. New
/// nuance belongs in [`DegradeReason`] or [`HardwareKind`], both of which ARE
/// non-exhaustive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionTier {
    /// The wrapping key lives in the named hardware component and is
    /// non-exportable: the sealed blob cannot be opened on another machine.
    Hardware(HardwareKind),

    /// The wrapping key is the passphrase-derived software envelope
    /// (AES-256-GCM + Argon2id) — the floor, never a bare file. The
    /// [`DegradeReason`] says why hardware is not in use.
    Software(DegradeReason),
}

impl ProtectionTier {
    /// Whether the key material is genuinely bound to hardware.
    ///
    /// The one question a UI must ask before claiming hardware protection.
    pub const fn is_hardware_bound(&self) -> bool {
        matches!(self, Self::Hardware(_))
    }

    /// The hardware component in use, or `None` when software-wrapped.
    pub const fn hardware_kind(&self) -> Option<HardwareKind> {
        match self {
            Self::Hardware(kind) => Some(*kind),
            Self::Software(_) => None,
        }
    }

    /// Why this keystore is software-wrapped, or `None` when hardware-bound.
    pub const fn degrade_reason(&self) -> Option<&DegradeReason> {
        match self {
            Self::Hardware(_) => None,
            Self::Software(reason) => Some(reason),
        }
    }
}

impl fmt::Display for ProtectionTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hardware(kind) => write!(f, "hardware-bound ({kind})"),
            Self::Software(reason) => write!(f, "software-wrapped ({reason})"),
        }
    }
}

/// The result of asking a host whether it has a usable hardware trusted
/// component.
///
/// Three-valued on purpose. See the module docs: `Absent` and `Indeterminate`
/// are different facts and must not be collapsed.
///
/// `#[non_exhaustive]`: a future probe may report a state these three do not
/// cover, and that must not be a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardwareProbe {
    /// Hardware of this class is present and reachable.
    Available(HardwareKind),
    /// Definitively no usable hardware on this host.
    Absent,
    /// The probe itself failed — availability is unknown.
    Indeterminate {
        /// Non-secret detail of the probe failure.
        detail: String,
    },
}

impl HardwareProbe {
    /// Build an [`Indeterminate`](Self::Indeterminate) from any displayable
    /// detail.
    pub fn indeterminate(detail: impl fmt::Display) -> Self {
        Self::Indeterminate {
            detail: detail.to_string(),
        }
    }
}

/// How strictly a caller requires hardware binding.
///
/// The policy decides what an [`Absent`](HardwareProbe::Absent) or
/// [`Indeterminate`](HardwareProbe::Indeterminate) probe *means*, and it is the
/// place the fail-closed rule is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HardwarePolicy {
    /// Hardware is mandatory. Anything other than a self-tested working
    /// hardware component is an error; the keystore does not open.
    Required,

    /// **Default.** Prefer hardware, and degrade only on a *confident*
    /// negative.
    ///
    /// An [`Indeterminate`](HardwareProbe::Indeterminate) probe is an **error**,
    /// not a degrade: silently downgrading "I could not tell" into "there is
    /// none" would let a transient probe failure quietly strip hardware
    /// protection from a wallet that has it, and the resulting software blob
    /// would then be openable anywhere. Failing closed keeps that decision
    /// with the caller.
    #[default]
    Preferred,

    /// Degrade on any negative outcome — including an indeterminate probe —
    /// but always report the distinguishing [`DegradeReason`].
    ///
    /// For callers that must open regardless (recovery tooling, read-only
    /// inspection). Honest, but permissive.
    Optional,
}

impl HardwarePolicy {
    /// Whether this policy tolerates degrading to software at all.
    pub const fn allows_degrade(self) -> bool {
        !matches!(self, Self::Required)
    }

    /// Whether this policy tolerates degrading when the probe could not
    /// determine availability.
    pub const fn allows_indeterminate_degrade(self) -> bool {
        matches!(self, Self::Optional)
    }
}
