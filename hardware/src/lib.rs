//! Platform trusted-component providers for [`dig_keystore`].
//!
//! `dig-keystore` defines the [`HardwareProvider`] seam and the `DIGHW1`
//! envelope, but ships no binding to real silicon: it sets
//! `unsafe_code = "forbid"` as a spec-pinned security property (`SPEC.md`
//! §12/§13.2, conformance C-15), and every platform trusted-component API is
//! FFI. This crate is where that FFI lives, so the forbid stays intact in the
//! crate that holds the key material.
//!
//! # What this buys
//!
//! A wrapping key created inside the host trusted component and **non-exportable
//! from it**, so copying a sealed keystore to another machine does not let an
//! attacker open it. That property, and only that property, is what a
//! [`ProtectionTier::Hardware`](dig_keystore::hardware::ProtectionTier::Hardware)
//! claim means.
//!
//! # The ladder, and why it is the part that matters
//!
//! | rung | protection | where |
//! |---|---|---|
//! | 1 | host trusted component, non-exportable wrapping key | this crate |
//! | 2 | OS credential store | `dig_keystore::OsKeychainBackend` |
//! | 3 | AES-256-GCM + Argon2id passphrase envelope — **the floor** | `dig_keystore` |
//!
//! Rung 3 is never skipped. Hardware wrapping is an outer envelope around an
//! already-sealed blob, so a host with no trusted component writes exactly the
//! bytes it always wrote — never a bare file.
//!
//! Most hosts, and every CI runner, land below rung 1. So [`ladder`] — the
//! decision about *which* rung, and the reason recorded for landing below the top
//! — is the code that actually runs everywhere, and it is tested on every host
//! through the provider seam. See [`ladder`] for how those fixtures are built.
//!
//! # Platform status, stated plainly
//!
//! | platform | status |
//! |---|---|
//! | Windows | **implemented** — TPM 2.0 through the CNG *Microsoft Platform Crypto Provider* ([`platform::windows`]) |
//! | macOS | **not implemented** — reports [`PlatformUnsupported`](dig_keystore::hardware::DegradeReason::PlatformUnsupported) |
//! | Linux | **not implemented** — reports [`PlatformUnsupported`](dig_keystore::hardware::DegradeReason::PlatformUnsupported) |
//!
//! An unimplemented platform degrades to rung 2/3 and **says so with a reason
//! naming this build**, never as `NoHardwarePresent`: that would be a confident
//! claim about the machine, and nothing here inspected it.
//!
//! # Example
//!
//! ```no_run
//! use dig_keystore::backend::FileBackend;
//! use dig_keystore::hardware::HardwarePolicy;
//!
//! // Strongest available tier for this host, honestly reported.
//! let backend = dig_keystore_hardware::bind_strongest(
//!     FileBackend::new("/var/lib/dig/keys"),
//!     HardwarePolicy::Preferred,
//! )?;
//! println!("this host: {}", backend.tier());
//! # Ok::<(), dig_keystore::KeystoreError>(())
//! ```

#![warn(missing_docs)]

use std::sync::Arc;

use dig_keystore::backend::KeychainBackend;
use dig_keystore::hardware::{
    degrade_under, HardwareBoundBackend, HardwarePolicy, HardwareProvider,
};
use dig_keystore::Result;

pub mod ladder;
pub mod platform;

pub use ladder::{walk, Attempt, AttemptOutcome, Rung};

/// The trusted-component candidates available on this host, in preference order.
///
/// Returns an empty slice on a platform this build has no provider for. That is
/// distinct from "this machine has no trusted component" and is reported as such
/// — see [`platform`].
pub fn platform_candidates() -> Vec<Arc<dyn HardwareProvider>> {
    platform::candidates()
}

/// Wrap `inner` in the strongest protection tier this host can actually prove,
/// degrading honestly.
///
/// Walks [`platform_candidates`] through [`ladder::walk`], then hands the winner
/// — or nothing — to [`HardwareBoundBackend`]. `inner` supplies rungs 2 and 3:
/// pass `OsKeychainBackend` where a credential store is wanted underneath, or
/// `FileBackend` for the passphrase-envelope floor.
///
/// # Errors
///
/// Per `policy`, and only from the ladder settling: `Required` refuses any
/// software tier, and the default `Preferred` refuses to open when a candidate
/// could not be inspected at all — rather than downgrading that into an absence.
pub fn bind_strongest<B: KeychainBackend>(
    inner: B,
    policy: HardwarePolicy,
) -> Result<HardwareBoundBackend> {
    // A platform this build has no binding for is reported as such. Falling
    // through to `bind_strongest_from` with an empty list would settle on
    // `NotRequested` — "nobody asked" — when the truth is that nobody could
    // answer. The distinction is what an operator acts on.
    if let Some(reason) = platform::unsupported_reason() {
        // Apply the policy to that reason first, so `Required` still refuses.
        let _ = degrade_under(reason.clone(), policy)?;
        return Ok(HardwareBoundBackend::degraded(inner, reason));
    }
    bind_strongest_from(inner, &platform_candidates(), policy)
}

/// As [`bind_strongest`], with the candidate list supplied by the caller.
///
/// The seam that makes the composition testable without hardware, and the way a
/// consumer injects a provider this crate does not ship.
///
/// # Errors
///
/// As [`bind_strongest`].
pub fn bind_strongest_from<B: KeychainBackend>(
    inner: B,
    candidates: &[Arc<dyn HardwareProvider>],
    policy: HardwarePolicy,
) -> Result<HardwareBoundBackend> {
    let rung = ladder::walk(candidates, policy)?;
    let settled = rung.tier().degrade_reason().cloned();
    match rung.into_provider() {
        // Re-resolved by the backend rather than asserted from here, so that ONE
        // authority owns every `Hardware` claim in the system — a claim asserted
        // from outside that authority is exactly the kind nobody re-checks.
        //
        // `policy` is passed through, and that is load-bearing rather than tidy.
        // The second resolution re-probes and re-runs the wrap/unwrap self-test
        // against LIVE hardware, so it is an independent chance to fail, not
        // redundant work: a TPM contended by BitLocker, Credential Guard or
        // Windows Hello can refuse the round-trip it had just passed. Handing
        // that resolution a weaker policy than the caller's would let it fail
        // OPEN — `Required` would return `Ok` over a refuted self-test, and
        // `Preferred` would downgrade an uninspectable device into an absence,
        // which is precisely the outcome `degrade_under` exists to refuse.
        //
        // Applying the policy twice is idempotent: `walk` has already errored
        // under `Required` on every non-hardware settle, so this only closes the
        // second resolution's hole.
        Some(provider) => HardwareBoundBackend::new(inner, Some(provider), policy),
        // The ladder already applied `policy` and established the reason; carry
        // that reason through instead of letting the backend re-derive a
        // caller-shaped `NotRequested` from the missing provider.
        None => Ok(HardwareBoundBackend::degraded(
            inner,
            settled.unwrap_or(dig_keystore::hardware::DegradeReason::NotRequested),
        )),
    }
}

#[cfg(test)]
mod tests;
