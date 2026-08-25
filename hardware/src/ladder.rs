//! The degrade ladder: walk candidate trusted components in preference order
//! and settle on the strongest one that is *proven*, not merely claimed.
//!
//! # Why the ladder is the deliverable, and not the silicon
//!
//! Real TPM and Secure Enclave silicon is absent from CI and absent from most
//! developer machines. The code that runs on **every** machine is this: the
//! decision about which rung the host lands on, and the reason recorded when it
//! lands below the top. A wrong provider binding fails loudly on the one machine
//! that has the hardware; a wrong ladder fails silently on all the others, by
//! reporting protection that is not there.
//!
//! So the platform calls sit behind [`HardwareProvider`], and everything in this
//! module is exercised on any host through that seam.
//!
//! # The rung order
//!
//! 1. a hardware trusted component whose wrapping key is non-exportable,
//! 2. failing that, the OS credential store as the inner backend,
//! 3. failing that, the AES-256-GCM + Argon2id passphrase envelope.
//!
//! **Rung 3 is the floor, never a bare file.** This module decides rung 1; rungs
//! 2 and 3 are the `dig-keystore` backends, composed underneath by
//! [`bind_strongest`](crate::bind_strongest). A host with no hardware writes
//! exactly the bytes it always wrote.
//!
//! # Silence understates, it never overstates
//!
//! Every rule below exists to keep an *unknown* from being reported as a
//! *confident negative*. That is the defect class dig-keystore#16 found in
//! `Path::exists()`, where every error collapsed to `false` and a keystore was
//! overwritten as a result. Here the stakes are higher, not lower: a blob sealed
//! to hardware that is wrongly reported absent is not recoverable by retrying.

use std::fmt;
use std::sync::Arc;

use dig_keystore::hardware::{
    degrade_under, resolve_provider_tier, DegradeReason, HardwareKind, HardwarePolicy,
    HardwareProvider, ProtectionTier,
};
use dig_keystore::Result;

/// What one candidate provider turned out to be, recorded whether or not it won.
///
/// Kept per candidate — rather than summarised into a single sentence — because
/// "the second TPM was unusable" and "the first one could not be inspected" lead
/// an operator to different actions, and a ladder that reports only its verdict
/// throws that away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The hardware class this candidate binds to.
    pub kind: HardwareKind,
    /// What happened when it was probed and self-tested.
    pub outcome: AttemptOutcome,
}

/// The outcome of probing and self-testing one candidate.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Probed available, self-test passed. This candidate was selected.
    Selected,
    /// An earlier candidate had already been selected, so this one was never
    /// probed at all. Recorded rather than omitted so the list stays a faithful
    /// account of what the ladder did and did not touch.
    NotReached,
    /// Rejected, carrying the reason this candidate earned on its own.
    Rejected(DegradeReason),
}

/// The settled result of walking the ladder.
#[derive(Clone)]
pub struct Rung {
    /// The selected provider, or `None` when the host degraded to software.
    ///
    /// Present **exactly** when [`tier`](Self::tier) is
    /// [`ProtectionTier::Hardware`], so the two can never disagree.
    provider: Option<Arc<dyn HardwareProvider>>,
    /// The truthful tier, with its reason inline when it is software.
    tier: ProtectionTier,
    /// Every candidate considered, in the order they were considered.
    attempts: Vec<Attempt>,
}

impl Rung {
    /// The selected provider, or `None` on a software rung.
    pub fn provider(&self) -> Option<&Arc<dyn HardwareProvider>> {
        self.provider.as_ref()
    }

    /// The provider, consumed — for handing to
    /// [`HardwareBoundBackend`](dig_keystore::hardware::HardwareBoundBackend).
    pub fn into_provider(self) -> Option<Arc<dyn HardwareProvider>> {
        self.provider
    }

    /// The truthful protection tier this host landed on.
    pub fn tier(&self) -> &ProtectionTier {
        &self.tier
    }

    /// Every candidate considered, in preference order.
    pub fn attempts(&self) -> &[Attempt] {
        &self.attempts
    }
}

// Hand-written because `dyn HardwareProvider` is not `Debug` — a provider is a
// handle to a trusted component, and a derived `Debug` on one would be a standing
// invitation to print its innards. The handle is reported as a presence flag; the
// interesting state is the tier and the attempt list, both of which print fully.
impl fmt::Debug for Rung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rung")
            .field("tier", &self.tier)
            .field("provider_bound", &self.provider.is_some())
            .field("attempts", &self.attempts)
            .finish()
    }
}

/// Walk `candidates` in preference order and settle on the first *proven* one.
///
/// Each candidate is judged by [`resolve_provider_tier`], so the probe and the
/// wrap/unwrap self-test are the `dig-keystore` ones — this module never
/// re-derives "is this provider trustworthy?".
///
/// Judging is done under [`HardwarePolicy::Optional`] so that one candidate
/// failure yields a *reason* rather than aborting the walk; `policy` is then
/// applied **once**, to the reason the ladder finally settles on. Applying it per
/// candidate would let a strict policy turn the first indeterminate probe into an
/// error while a perfectly good second candidate sat unexamined.
///
/// # Errors
///
/// Only from the final policy application, exactly as
/// [`HardwareBoundBackend::new`](dig_keystore::hardware::HardwareBoundBackend::new):
/// [`Required`](HardwarePolicy::Required) errors on any software outcome, and
/// [`Preferred`](HardwarePolicy::Preferred) errors on an indeterminate one rather
/// than downgrading "I could not tell" into "there is none".
pub fn walk(candidates: &[Arc<dyn HardwareProvider>], policy: HardwarePolicy) -> Result<Rung> {
    let mut attempts = Vec::with_capacity(candidates.len());
    let mut selected: Option<(Arc<dyn HardwareProvider>, HardwareKind)> = None;

    for candidate in candidates {
        // Once one candidate is selected the rest are recorded but NOT probed:
        // probing a trusted component has a side effect — it can create a
        // persisted wrapping key — so a ladder that kept walking would provision
        // hardware the host has already decided not to use.
        if selected.is_some() {
            attempts.push(Attempt {
                kind: candidate.kind(),
                outcome: AttemptOutcome::NotReached,
            });
            continue;
        }

        let kind = candidate.kind();
        match resolve_provider_tier(candidate.as_ref(), HardwarePolicy::Optional) {
            Ok(ProtectionTier::Hardware(bound)) => {
                attempts.push(Attempt {
                    kind: bound,
                    outcome: AttemptOutcome::Selected,
                });
                selected = Some((Arc::clone(candidate), bound));
            }
            Ok(ProtectionTier::Software(reason)) => attempts.push(Attempt {
                kind,
                outcome: AttemptOutcome::Rejected(reason),
            }),
            // `Optional` degrades rather than erroring, so this arm is reachable
            // only if that contract changes. Record it as an indeterminate
            // rejection — the conservative reading — rather than failing the
            // whole walk on one candidate.
            Err(e) => attempts.push(Attempt {
                kind,
                outcome: AttemptOutcome::Rejected(DegradeReason::ProbeIndeterminate {
                    detail: e.to_string(),
                }),
            }),
        }
    }

    match selected {
        Some((provider, kind)) => Ok(Rung {
            provider: Some(provider),
            tier: ProtectionTier::Hardware(kind),
            attempts,
        }),
        None => {
            let tier = degrade_under(settled_reason(&attempts), policy)?;
            Ok(Rung {
                provider: None,
                tier,
                attempts,
            })
        }
    }
}

/// Reduce every rejection to the ONE reason the ladder reports.
///
/// The precedence is a fail-closed ordering, not a preference:
///
/// 1. **[`ProbeIndeterminate`](DegradeReason::ProbeIndeterminate)** dominates
///    everything. It is the only reason that is an *error* under the default
///    policy, so letting a confident reason outrank it would convert "I could not
///    tell" into "there is none" — the exact downgrade the three-valued probe
///    exists to prevent — and would do it by summarising rather than by lying.
/// 2. **[`HardwareUnusable`](DegradeReason::HardwareUnusable)** next: hardware
///    was found and then refuted, which an operator can act on.
/// 3. **[`NoHardwarePresent`](DegradeReason::NoHardwarePresent)** last: the only
///    confident negative, reportable only when *every* candidate agreed on it.
/// 4. No candidates at all is [`NotRequested`](DegradeReason::NotRequested) —
///    a different fact from "we looked and found none".
fn settled_reason(attempts: &[Attempt]) -> DegradeReason {
    let mut unusable: Option<&DegradeReason> = None;
    let mut unranked: Option<&DegradeReason> = None;
    let mut absent = false;

    for attempt in attempts {
        let AttemptOutcome::Rejected(reason) = &attempt.outcome else {
            continue;
        };
        match reason {
            DegradeReason::ProbeIndeterminate { .. } => return reason.clone(),
            DegradeReason::HardwareUnusable { .. } => unusable = unusable.or(Some(reason)),
            DegradeReason::NoHardwarePresent => absent = true,
            // A reason this build has no ordering for. `DegradeReason` is
            // `#[non_exhaustive]`, so one WILL appear; ranking it above the
            // confident negative keeps an unrecognised outcome from being
            // summarised as "there is no hardware here".
            _ => unranked = unranked.or(Some(reason)),
        }
    }

    unusable.or(unranked).cloned().unwrap_or(if absent {
        DegradeReason::NoHardwarePresent
    } else {
        DegradeReason::NotRequested
    })
}

#[cfg(test)]
mod tests;
