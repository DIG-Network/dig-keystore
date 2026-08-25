//! Ladder tests. **Every test in this module runs on every host** — no `#[cfg]`
//! gate, no `#[ignore]`, no TPM — because the ladder is the part that executes on
//! machines that have no trusted component, which is most of them.
//!
//! # How the fixtures are built
//!
//! Each test names the property, then builds the input that separates it from the
//! **nearest wrong implementation** rather than from an obviously broken one. The
//! nearest wrong implementations here are specific and plausible:
//!
//! - one that stops at the first candidate instead of falling through;
//! - one that trusts `probe()` and skips the self-test;
//! - one that summarises "nothing was selected" as `NoHardwarePresent`,
//!   swallowing an indeterminate probe — which reads perfectly correct until a
//!   strict policy is asked to fail closed and quietly does not.
//!
//! Several tests therefore come in **pairs**: a case that must report the
//! uncertain reason, and a control that must report the confident one. A test for
//! the uncertain case alone is satisfied by an implementation that reports
//! uncertainty unconditionally, which is a different lie in the same place.

use std::sync::Arc;

use dig_keystore::hardware::double::{FakeDevice, WrapBehaviour};
use dig_keystore::hardware::{
    DegradeReason, HardwareKind, HardwarePolicy, HardwareProvider, KeyCustody, ProtectionTier,
};
use dig_keystore::KeystoreError;

use super::{settled_reason, walk, AttemptOutcome};

/// The three kinds are used purely as distinguishable labels, so that "which
/// candidate was selected" is observable rather than inferred.
const FIRST: HardwareKind = HardwareKind::WindowsTpm20;
const SECOND: HardwareKind = HardwareKind::MacSecureEnclave;
const THIRD: HardwareKind = HardwareKind::LinuxTpm20;

fn candidates(devices: Vec<FakeDevice>) -> Vec<Arc<dyn HardwareProvider>> {
    devices
        .into_iter()
        .map(|d| Arc::new(d) as Arc<dyn HardwareProvider>)
        .collect()
}

fn reason(tier: &ProtectionTier) -> &DegradeReason {
    tier.degrade_reason()
        .unwrap_or_else(|| panic!("expected a software tier, got {tier}"))
}

// ---------------------------------------------------------------------------
// Order and fall-through
// ---------------------------------------------------------------------------

/// **Property:** the first proven candidate wins, and the ones behind it are
/// never touched.
///
/// **Nearest wrong implementation:** one that probes every candidate and then
/// picks the best. It selects the same provider, so asserting only on the
/// selection cannot see it. Probing a real trusted component *creates a persisted
/// wrapping key*, so walking past a decided answer provisions hardware the host
/// chose not to use.
///
/// The distinguishing observation is therefore the untouched second device:
/// `last_wrapped_content_key()` is `None` exactly when its self-test never ran.
#[test]
fn a_proven_first_candidate_wins_and_the_rest_are_never_probed() {
    let untouched = FakeDevice::working(SECOND, 2);
    let probe_witness = untouched.clone();

    let rung = walk(
        &candidates(vec![FakeDevice::working(FIRST, 1), untouched]),
        HardwarePolicy::Preferred,
    )
    .expect("a working first candidate degrades nothing");

    assert_eq!(rung.tier(), &ProtectionTier::Hardware(FIRST));
    assert_eq!(rung.provider().expect("selected").kind(), FIRST);
    assert_eq!(rung.attempts()[0].outcome, AttemptOutcome::Selected);
    assert_eq!(rung.attempts()[1].outcome, AttemptOutcome::NotReached);

    assert_eq!(
        probe_witness.last_wrapped_content_key(),
        None,
        "a candidate behind a decided answer must not be self-tested, because \
         probing real hardware provisions a persisted key"
    );
}

/// **Property:** a confidently-absent candidate falls through to a working one.
///
/// **Nearest wrong implementation:** one that treats the first candidate as the
/// answer whatever it says. Two hops are required: with a single absent candidate
/// the outcome is a software tier either way.
#[test]
fn an_absent_candidate_falls_through_to_a_working_one() {
    let rung = walk(
        &candidates(vec![
            FakeDevice::absent(FIRST),
            FakeDevice::working(SECOND, 2),
        ]),
        HardwarePolicy::Preferred,
    )
    .expect("the second candidate is proven");

    assert_eq!(rung.tier(), &ProtectionTier::Hardware(SECOND));
    assert_eq!(rung.provider().expect("selected").kind(), SECOND);
}

/// **Property:** a candidate that *claims* availability but fails its self-test
/// is rejected, and the walk continues past it.
///
/// **Nearest wrong implementation:** one that selects on `probe()` alone. It
/// would select the first device here and hand back a provider whose unwrap
/// returns the wrong key — a keystore that seals and never reopens.
#[test]
fn a_candidate_that_probes_available_but_fails_its_self_test_is_rejected() {
    let rung = walk(
        &candidates(vec![
            FakeDevice::working(FIRST, 1).with_behaviour(WrapBehaviour::WrongKeyOnUnwrap),
            FakeDevice::working(SECOND, 2),
        ]),
        HardwarePolicy::Preferred,
    )
    .expect("the second candidate is proven");

    assert_eq!(rung.tier(), &ProtectionTier::Hardware(SECOND));
    assert!(
        matches!(
            &rung.attempts()[0].outcome,
            AttemptOutcome::Rejected(DegradeReason::HardwareUnusable { .. })
        ),
        "a refuted self-test is `HardwareUnusable`, not an absence: hardware WAS \
         found here, got {:?}",
        rung.attempts()[0].outcome
    );
}

/// **Property:** custody, not the probe, decides whether a candidate is hardware
/// grade — a provider holding its wrapping key in process memory is never
/// selected however loudly it announces itself.
///
/// **Nearest wrong implementation:** one that short-circuits on
/// `probe() == Available`. That is a tempting optimisation precisely because it
/// looks like it saves a round-trip, and it would select a provider offering **no
/// cross-machine binding at all** while reporting `Hardware`.
///
/// This is a placement property, so it needs two hops: with a single candidate,
/// both implementations end on a software tier and the fixture cannot tell them
/// apart. The second, genuinely-hardware candidate is what makes the wrong
/// placement observable.
#[test]
fn a_process_memory_wrapping_key_is_never_selected_even_when_it_probes_available() {
    let rung = walk(
        &candidates(vec![
            FakeDevice::working(FIRST, 1).with_custody(KeyCustody::ProcessMemory),
            FakeDevice::working(SECOND, 2),
        ]),
        HardwarePolicy::Preferred,
    )
    .expect("the second candidate is proven");

    assert_eq!(
        rung.tier(),
        &ProtectionTier::Hardware(SECOND),
        "a ProcessMemory wrapping key buys no cross-machine binding and must not \
         be reported as a hardware tier"
    );
    assert_eq!(rung.provider().expect("selected").kind(), SECOND);
}

// ---------------------------------------------------------------------------
// Which reason survives — the pairs
// ---------------------------------------------------------------------------

/// **Property:** an indeterminate probe anywhere in the ladder survives being
/// summarised, even when a *confident* absence sits beside it.
///
/// **Nearest wrong implementation:** one that reports `NoHardwarePresent`
/// whenever nothing was selected. Under `Optional` both produce a software tier,
/// so the reason itself is the only observable — which is why it is asserted
/// directly rather than through `is_hardware_bound()`.
#[test]
fn an_indeterminate_probe_beside_an_absence_reports_the_uncertainty() {
    let rung = walk(
        &candidates(vec![
            FakeDevice::indeterminate(FIRST, "tpm service unreachable"),
            FakeDevice::absent(SECOND),
        ]),
        HardwarePolicy::Optional,
    )
    .expect("Optional always opens");

    assert!(
        matches!(
            reason(rung.tier()),
            DegradeReason::ProbeIndeterminate { .. }
        ),
        "got {:?}",
        reason(rung.tier())
    );
}

/// **Property:** the same, with the order reversed.
///
/// **Nearest wrong implementations this separates:** "first reason wins" and
/// "last reason wins". Each passes exactly one of this test and its predecessor,
/// so neither test is redundant and neither alone is sufficient.
#[test]
fn an_indeterminate_probe_dominates_even_when_it_is_last() {
    let rung = walk(
        &candidates(vec![
            FakeDevice::absent(FIRST),
            FakeDevice::indeterminate(SECOND, "tpm service unreachable"),
        ]),
        HardwarePolicy::Optional,
    )
    .expect("Optional always opens");

    assert!(
        matches!(
            reason(rung.tier()),
            DegradeReason::ProbeIndeterminate { .. }
        ),
        "got {:?}",
        reason(rung.tier())
    );
}

/// **The control for the two tests above.** Without it, an implementation that
/// reports `ProbeIndeterminate` *unconditionally* passes both — a different lie
/// in the same place, and one that would make every `Preferred` host fail to open.
///
/// **Property:** when every candidate agreed there is no hardware, the confident
/// negative is reported, because it is true.
#[test]
fn every_candidate_absent_reports_the_confident_negative() {
    let rung = walk(
        &candidates(vec![FakeDevice::absent(FIRST), FakeDevice::absent(SECOND)]),
        HardwarePolicy::Optional,
    )
    .expect("Optional always opens");

    assert_eq!(reason(rung.tier()), &DegradeReason::NoHardwarePresent);
}

/// **Property:** uncertainty outranks a refuted self-test too.
///
/// `HardwareUnusable` is a *confident* finding — hardware was found and proven
/// broken — so it must not mask a candidate that could not be inspected at all.
#[test]
fn an_indeterminate_probe_dominates_a_refuted_self_test() {
    let rung = walk(
        &candidates(vec![
            FakeDevice::working(FIRST, 1).with_behaviour(WrapBehaviour::FailWrap),
            FakeDevice::indeterminate(SECOND, "enclave query timed out"),
        ]),
        HardwarePolicy::Optional,
    )
    .expect("Optional always opens");

    assert!(
        matches!(
            reason(rung.tier()),
            DegradeReason::ProbeIndeterminate { .. }
        ),
        "got {:?}",
        reason(rung.tier())
    );
}

/// **The control for the test above:** with no uncertainty in play, the refuted
/// self-test is what gets reported — not the absence beside it. An operator can
/// act on "your TPM is present and broken"; "you have no TPM" sends them nowhere.
#[test]
fn a_refuted_self_test_beside_an_absence_reports_the_unusable_hardware() {
    let rung = walk(
        &candidates(vec![
            FakeDevice::absent(FIRST),
            FakeDevice::working(SECOND, 2).with_behaviour(WrapBehaviour::FailWrap),
        ]),
        HardwarePolicy::Optional,
    )
    .expect("Optional always opens");

    assert!(
        matches!(reason(rung.tier()), DegradeReason::HardwareUnusable { .. }),
        "got {:?}",
        reason(rung.tier())
    );
}

/// **Property:** "we were not asked" is not "we looked and found none".
///
/// An empty candidate list means no provider was offered — a caller decision —
/// and reporting it as `NoHardwarePresent` would state a fact about the machine
/// that was never established. It also matters mechanically: under `Preferred`
/// both are `Ok`, so only the reason distinguishes them.
#[test]
fn no_candidates_reports_not_requested_rather_than_an_absence() {
    let rung = walk(&[], HardwarePolicy::Optional).expect("Optional always opens");

    assert_eq!(reason(rung.tier()), &DegradeReason::NotRequested);
    assert!(rung.attempts().is_empty());
}

// ---------------------------------------------------------------------------
// Policy applied once, to the settled reason
// ---------------------------------------------------------------------------

/// **Property — the one the precedence rule exists for.** Under the default
/// policy, a ladder containing an uninspectable candidate must FAIL rather than
/// open software-wrapped.
///
/// **Nearest wrong implementation:** the summarise-to-`NoHardwarePresent` one
/// again — but here it is not merely reporting the wrong sentence, it returns
/// `Ok` where the contract requires `Err`. That is a transient probe failure
/// silently stripping hardware protection from a machine that has it, and the
/// resulting software blob then opens anywhere.
///
/// Paired with its control below, because a `walk` that errored on *every*
/// software outcome would also pass this one.
#[test]
fn preferred_policy_fails_closed_when_any_candidate_could_not_be_inspected() {
    let err = walk(
        &candidates(vec![
            FakeDevice::absent(FIRST),
            FakeDevice::indeterminate(SECOND, "tpm service unreachable"),
        ]),
        HardwarePolicy::Preferred,
    )
    .expect_err("an uninspectable candidate must not be downgraded into an absence");

    assert!(
        matches!(err, KeystoreError::HardwareProbeIndeterminate { .. }),
        "got {err:?}"
    );
}

/// **The control:** the same policy, the same absence of hardware, no
/// uncertainty — and it opens, software-wrapped, saying why.
#[test]
fn preferred_policy_opens_on_a_confident_absence() {
    let rung = walk(
        &candidates(vec![FakeDevice::absent(FIRST), FakeDevice::absent(SECOND)]),
        HardwarePolicy::Preferred,
    )
    .expect("a confident absence is a degrade, not an error");

    assert_eq!(reason(rung.tier()), &DegradeReason::NoHardwarePresent);
}

/// **Property:** policy is applied to the *settled* reason, once — not to each
/// candidate as it is judged.
///
/// **Nearest wrong implementation:** one that passes the caller policy down into
/// each candidate judgement. Under `Preferred` it would error on the first,
/// indeterminate candidate and never reach the working third — turning a host
/// that genuinely has hardware into a host that will not open at all.
#[test]
fn a_strict_policy_does_not_abort_the_walk_before_a_working_candidate() {
    let rung = walk(
        &candidates(vec![
            FakeDevice::indeterminate(FIRST, "tpm service unreachable"),
            FakeDevice::absent(SECOND),
            FakeDevice::working(THIRD, 3),
        ]),
        HardwarePolicy::Preferred,
    )
    .expect("a proven candidate beats an earlier indeterminate one");

    assert_eq!(rung.tier(), &ProtectionTier::Hardware(THIRD));
}

/// **Property:** `Required` refuses to open at all rather than degrade, whatever
/// the reason.
#[test]
fn required_policy_refuses_to_degrade() {
    let err = walk(
        &candidates(vec![FakeDevice::absent(FIRST)]),
        HardwarePolicy::Required,
    )
    .expect_err("Required tolerates no software tier");

    assert!(
        matches!(err, KeystoreError::HardwareRequired { .. }),
        "got {err:?}"
    );
}

/// **Property:** the provider handle and the reported tier cannot disagree.
///
/// A degraded rung that still held a provider is the state that would let a later
/// caller reach for hardware the ladder decided not to trust, so both arms are
/// asserted rather than just the interesting one.
#[test]
fn a_provider_is_held_exactly_when_the_tier_claims_hardware() {
    let bound = walk(
        &candidates(vec![FakeDevice::working(FIRST, 1)]),
        HardwarePolicy::Preferred,
    )
    .expect("proven");
    assert!(bound.tier().is_hardware_bound());
    assert!(bound.provider().is_some());

    let degraded = walk(
        &candidates(vec![FakeDevice::absent(FIRST)]),
        HardwarePolicy::Optional,
    )
    .expect("Optional always opens");
    assert!(!degraded.tier().is_hardware_bound());
    assert!(
        degraded.provider().is_none(),
        "a degraded rung must not hand back a provider it refused to trust"
    );
}

// ---------------------------------------------------------------------------
// The unranked arm, and the reporting surface
// ---------------------------------------------------------------------------

/// **Property (C-41):** a reason the precedence does not recognise still outranks
/// the confident negative.
///
/// `DegradeReason` is `#[non_exhaustive]`, so a variant this ordering has never
/// seen WILL appear — `PlatformUnsupported` already has. The failure mode is
/// quiet: an unfamiliar reason falling through to `NoHardwarePresent` reports
/// "this machine has no trusted component" on the strength of an outcome nobody
/// classified.
///
/// Asserted against `settled_reason` directly because `walk` cannot yet produce
/// such a reason — the arm would otherwise be unreachable, and an unreachable
/// guard is indistinguishable from an absent one.
#[test]
fn an_unrecognised_reason_outranks_the_confident_negative() {
    let unranked = DegradeReason::PlatformUnsupported {
        detail: "no binding for this platform".to_owned(),
    };

    assert_eq!(
        settled_reason(&[DegradeReason::NoHardwarePresent, unranked.clone()]),
        unranked,
        "an unclassified outcome must not be summarised as an absence"
    );
    // Order-independent, like the indeterminate rule it mirrors.
    assert_eq!(
        settled_reason(&[unranked.clone(), DegradeReason::NoHardwarePresent]),
        unranked
    );
}

/// **The control:** uncertainty still outranks the unrecognised reason, and a
/// refuted self-test still outranks it too.
///
/// Without this pair, an implementation that returned the unranked reason
/// unconditionally would pass the test above.
#[test]
fn an_unrecognised_reason_does_not_outrank_uncertainty_or_a_refutation() {
    let unranked = DegradeReason::PlatformUnsupported {
        detail: "no binding".to_owned(),
    };
    let uncertain = DegradeReason::ProbeIndeterminate {
        detail: "probe failed".to_owned(),
    };
    let refuted = DegradeReason::HardwareUnusable {
        detail: "wrap failed".to_owned(),
    };

    assert_eq!(
        settled_reason(&[unranked.clone(), uncertain.clone()]),
        uncertain
    );
    assert_eq!(settled_reason(&[unranked, refuted.clone()]), refuted);
}

/// **Property:** an empty rejection list is `NotRequested`, and this is asserted
/// on `settled_reason` itself as well as through `walk`.
#[test]
fn no_rejections_settle_on_not_requested() {
    assert_eq!(settled_reason(&[]), DegradeReason::NotRequested);
}

/// **Property:** the ladder's own reporting surface says whether a provider is
/// held without exposing the provider.
///
/// `Rung` cannot derive `Debug` — `dyn HardwareProvider` is a handle to a trusted
/// component, and a derived `Debug` on one would be a standing invitation to
/// print its innards. The hand-written impl is therefore real code on the
/// diagnostic path, and it is asserted rather than assumed.
#[test]
fn the_rung_debug_reports_binding_without_exposing_the_provider() {
    let bound = walk(
        &candidates(vec![FakeDevice::working(FIRST, 1)]),
        HardwarePolicy::Preferred,
    )
    .expect("proven");

    let rendered = format!("{bound:?}");
    assert!(rendered.contains("provider_bound: true"), "got {rendered}");
    assert!(rendered.contains("Selected"), "got {rendered}");
    assert!(
        !rendered.contains("FakeDevice"),
        "the provider itself must not be rendered: {rendered}"
    );

    // Both arms: a degraded rung must report the absence of a provider, not omit
    // the field.
    let degraded = walk(
        &candidates(vec![FakeDevice::absent(FIRST)]),
        HardwarePolicy::Optional,
    )
    .expect("Optional always opens");
    assert!(
        format!("{degraded:?}").contains("provider_bound: false"),
        "got {degraded:?}"
    );
}

/// **Property:** the attempt list is a faithful, ordered account of the walk.
///
/// It is the only record of what happened to the candidates that did not win, so
/// an operator diagnosing "why is my TPM not being used?" reads this and nothing
/// else.
#[test]
fn the_attempt_list_records_every_candidate_in_order() {
    let rung = walk(
        &candidates(vec![
            FakeDevice::absent(FIRST),
            FakeDevice::working(SECOND, 2),
            FakeDevice::working(THIRD, 3),
        ]),
        HardwarePolicy::Preferred,
    )
    .expect("the second candidate is proven");

    let kinds: Vec<_> = rung.attempts().iter().map(|a| a.kind).collect();
    assert_eq!(kinds, vec![FIRST, SECOND, THIRD]);
    assert!(matches!(
        rung.attempts()[0].outcome,
        AttemptOutcome::Rejected(DegradeReason::NoHardwarePresent)
    ));
    assert_eq!(rung.attempts()[1].outcome, AttemptOutcome::Selected);
    assert_eq!(rung.attempts()[2].outcome, AttemptOutcome::NotReached);

    // `into_provider` hands back the SELECTED candidate, not the first one.
    assert_eq!(
        rung.into_provider().expect("selected").kind(),
        SECOND,
        "the consumed handle must be the candidate that won"
    );
}
