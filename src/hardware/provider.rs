//! The [`HardwareProvider`] seam — the whole contract a platform binding must
//! satisfy.
//!
//! # Why the seam is this narrow
//!
//! A hardware trusted component cannot wrap a keystore blob directly. A TPM 2.0
//! key reached through CNG is asymmetric (RSA/ECC) and bounded by the modulus
//! size; a Secure Enclave key is a P-256 key that never leaves the chip. So the
//! envelope is **hybrid**: a random 32-byte content key encrypts the blob with
//! AES-256-GCM in this crate, and the hardware only ever wraps *that key*.
//!
//! Keeping the trait to two 32-byte operations means each platform binding is a
//! few dozen lines of FFI instead of a second envelope format, and every
//! platform shares one audited AEAD path.
//!
//! # Where implementations will live
//!
//! **No platform provider ships yet** — this release contains the trait and the
//! envelope, and nothing that binds to real hardware. Passing no provider
//! resolves [`Software(NotRequested)`](super::DegradeReason::NotRequested).
//!
//! This package sets `unsafe_code = "forbid"` as a spec-pinned security property
//! (`SPEC.md` §12/§13.2, conformance C-15), so raw CNG / Security Framework FFI
//! cannot live here. Real bindings are therefore *planned* for a separate
//! `hardware/` workspace member (`dig-keystore-hardware`) that will mirror the
//! existing `wasm/` split, tracked as **dig_ecosystem #1693**; they will be
//! injected through this trait.

use zeroize::Zeroizing;

use super::tier::{HardwareKind, HardwareProbe};
use crate::error::Result;

/// Length of the symmetric content key a provider wraps.
pub const CONTENT_KEY_LEN: usize = 32;

/// The content key that a hardware provider wraps and unwraps.
///
/// Zeroized on drop: this is the only plaintext key material that transits the
/// provider boundary.
pub type ContentKey = Zeroizing<[u8; CONTENT_KEY_LEN]>;

/// Where a provider's wrapping key physically lives.
///
/// This is the property hardware binding actually buys, so it is reported
/// explicitly rather than inferred from the provider's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCustody {
    /// The wrapping key was generated inside the hardware component and cannot
    /// be exported from it. Copying the sealed blob to another machine does not
    /// let an attacker open it.
    ///
    /// An implementation MUST NOT report this unless the key was created
    /// non-exportable *and* an export attempt is refused by the platform.
    NonExportable,

    /// The wrapping key exists in process memory at some point. Offers no
    /// cross-machine binding; a provider reporting this MUST NOT be treated as
    /// a hardware tier.
    ProcessMemory,
}

impl KeyCustody {
    /// Whether this custody level is strong enough to claim a hardware tier.
    pub const fn is_hardware_grade(self) -> bool {
        matches!(self, Self::NonExportable)
    }
}

/// A binding to one OS hardware trusted component.
///
/// Implementations are injected into
/// [`HardwareBoundBackend`](super::HardwareBoundBackend), which probes and
/// self-tests them before claiming a hardware tier — an implementation is never
/// taken at its word.
pub trait HardwareProvider: Send + Sync + 'static {
    /// Which hardware class this provider binds to.
    fn kind(&self) -> HardwareKind;

    /// Inspect the host for usable hardware.
    ///
    /// MUST return [`HardwareProbe::Indeterminate`] — never
    /// [`Absent`](HardwareProbe::Absent) — when the inspection itself fails
    /// (an error, a timeout, an empty or unintelligible response). "I could not
    /// tell" and "there is none" are different answers and the caller acts
    /// differently on each.
    fn probe(&self) -> HardwareProbe;

    /// Where this provider's wrapping key lives.
    fn custody(&self) -> KeyCustody;

    /// Encrypt `content_key` to the hardware wrapping key.
    ///
    /// The returned bytes are opaque to this crate and are stored verbatim in
    /// the envelope header.
    fn wrap_key(&self, content_key: &ContentKey) -> Result<Vec<u8>>;

    /// Decrypt a previously wrapped content key using the hardware key.
    ///
    /// MUST fail — never return arbitrary bytes — when `wrapped` was sealed by a
    /// different hardware key (for instance a blob copied from another machine).
    /// That failure *is* the cross-machine binding guarantee.
    ///
    /// **The same failure occurs when this device is the original one and its
    /// key has since been destroyed** (a TPM clear, a mainboard swap), which is
    /// permanent loss rather than a refusal. A provider cannot tell the two
    /// apart — it holds a key, not a history — so it MUST NOT describe the
    /// failure as recoverable or imply the blob can simply be moved back. See
    /// `SPEC.md` §17.5b, which is normative for how this is reported.
    fn unwrap_key(&self, wrapped: &[u8]) -> Result<ContentKey>;
}
