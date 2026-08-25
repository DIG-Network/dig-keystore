//! Hardware binding for at-rest key material.
//!
//! Binds a keystore's wrapping key to the host's OS hardware trusted component
//! — Windows TPM 2.0 via the CNG Platform Crypto Provider, the Apple Secure
//! Enclave, or a Linux TPM 2.0 — so that **copying the sealed blob to another
//! machine does not let an attacker open it**. That non-exportability is the
//! entire property being bought; everything else here exists to make sure the
//! property is either genuinely present or honestly reported as absent.
//!
//! # Three rules this module is built around
//!
//! **1. A tier above, never a replacement.** The AES-256-GCM + Argon2id
//! passphrase envelope (`SPEC.md` §3) is the **floor**. Hardware wrapping is an
//! outer [`envelope`] around an already-sealed blob, so a host with no hardware
//! writes exactly the bytes it always wrote — never a bare file.
//!
//! **2. Report the tier truthfully, and per blob.** [`ProtectionTier`] is total
//! and carries its [`DegradeReason`] inside the `Software` variant, so "degraded
//! to software" can never be mistaken for — or reported without distinguishing
//! it from — "hardware-bound".
//!
//! Two questions exist and both are exposed:
//! [`tier`](HardwareBoundBackend::tier) is what this **host** is capable of,
//! while [`blob_tier`](HardwareBoundBackend::blob_tier) is what protects **one
//! stored key**, read from its bytes. They can legitimately disagree — a capable
//! host may hold a keystore written before this feature existed — so anything a
//! **user** sees must come from `blob_tier`. A capable host does not
//! retroactively protect bytes already at rest.
//!
//! **3. Fail closed, on both questions.** "Is hardware present?" and "could I
//! determine whether hardware is present?" are separate answers
//! ([`HardwareProbe::Absent`] vs [`HardwareProbe::Indeterminate`]). Under the
//! default [`HardwarePolicy::Preferred`], a confident absence degrades but an
//! indeterminate probe is an error — because silently turning "I could not tell"
//! into "there is none" would strip hardware protection from a machine that has
//! it, on nothing more than a transient probe failure.
//!
//! **4. Binding is reversible, and must be.** The trusted component becomes a
//! SECOND required factor: once a blob is wrapped, a cleared TPM or a lost
//! device means the correct passphrase no longer opens it, permanently. So
//! [`unbind`](HardwareBoundBackend::unbind) exists to return a blob to the
//! portable §3 form while the hardware still answers, and
//! [`bind`](HardwareBoundBackend::bind) migrates an older blob up. `bind`
//! overwrites the only copy, so it proves the new seal reopens *from storage*
//! before reporting success and restores the previous bytes if it cannot —
//! and `unbind` verifies the same way, because a user who is told "unbound"
//! may then go and clear the TPM.
//!
//! # Backwards compatibility (§5.1, HARD RULE)
//!
//! The v1 keystore format is unchanged, byte for byte. Detection is by prefix:
//! any blob that is not a `DIGHW1` envelope is passed through untouched, so
//! every keystore written before this feature keeps opening forever. See
//! [`envelope::is_envelope`] and `tests/hardware_v1_compat.rs`, which decodes
//! committed golden v1 blobs through this backend.
//!
//! # Providing hardware
//!
//! **No platform provider ships in this release.** This module provides the seam,
//! the envelope and the tier semantics; nothing here binds to a real TPM or
//! Secure Enclave yet, so on every host today the tier resolves to
//! [`Software(NotRequested)`](DegradeReason::NotRequested) unless a caller
//! supplies its own provider.
//!
//! This package forbids `unsafe` code as a spec-pinned security property
//! (`SPEC.md` §12/§13.2, conformance C-15), so platform FFI cannot live here.
//! Bindings are planned for a separate `hardware/` workspace member — tracked as
//! **dig_ecosystem #1693** — and will be injected through the
//! [`HardwareProvider`] trait. A provider is never taken at its word: it is
//! probed *and* self-tested before a hardware tier is claimed.

mod backend;
pub mod envelope;
mod provider;
mod tier;

pub use backend::{degrade_under, resolve_provider_tier, HardwareBoundBackend};
pub use provider::{ContentKey, HardwareProvider, KeyCustody, CONTENT_KEY_LEN};
pub use tier::{DegradeReason, HardwareKind, HardwarePolicy, HardwareProbe, ProtectionTier};

#[cfg(any(test, feature = "testing"))]
pub mod double;

#[cfg(test)]
mod tests;
