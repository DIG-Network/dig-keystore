//! Unit tests for hardware binding.
//!
//! Each test names the property it pins and the wrong implementation it
//! distinguishes. Two fixture choices recur and are deliberate:
//!
//! - **Two devices, not one.** Cross-machine binding cannot be seen with a
//!   single device in play — a test with only one device would pass against an
//!   implementation that ignores the wrapping key entirely. Every binding test
//!   keeps an honest device as the control and varies only the second.
//! - **Real-format inner blobs.** The inner bytes are 105-byte v1-shaped blobs
//!   (`SPEC.md` §3: 53-byte header + 48-byte payload + 4-byte CRC), the true size
//!   of every shipped scheme, not a short synthetic stub — so length arithmetic
//!   is exercised at the size that actually occurs.

use std::sync::Arc;

use super::double::{FakeDevice, WrapBehaviour};
use super::envelope::{self, ENVELOPE_MAGIC};
use super::provider::{HardwareProvider, KeyCustody};
use super::tier::{DegradeReason, HardwareKind, HardwarePolicy, ProtectionTier};
use super::HardwareBoundBackend;
use crate::backend::{BackendKey, KeychainBackend, MemoryBackend};
use crate::error::KeystoreError;

/// Every hardware kind, so per-platform assertions cover the real set rather
/// than whichever one the host happens to be.
const ALL_KINDS: [HardwareKind; 3] = [
    HardwareKind::WindowsTpm20,
    HardwareKind::MacSecureEnclave,
    HardwareKind::LinuxTpm20,
];

/// A blob the exact size and shape of a real v1 keystore file: 105 bytes with a
/// `DIGVK1` magic. Sized from the format, not invented.
fn v1_shaped_blob(seed: u8) -> Vec<u8> {
    let mut blob = Vec::with_capacity(105);
    blob.extend_from_slice(b"DIGVK1");
    blob.extend_from_slice(&1u16.to_be_bytes()); // format version
    blob.extend_from_slice(&1u16.to_be_bytes()); // scheme id
    blob.push(0x01); // kdf id
    blob.extend_from_slice(&65536u32.to_be_bytes());
    blob.extend_from_slice(&3u32.to_be_bytes());
    blob.push(4); // lanes
    blob.push(0x01); // cipher id
    blob.extend_from_slice(&[seed; 16]); // salt
    blob.extend_from_slice(&[seed ^ 0xFF; 12]); // nonce
    blob.extend_from_slice(&48u32.to_be_bytes()); // payload len
    blob.extend_from_slice(&[seed; 48]); // ciphertext + tag
    let crc = crc32fast::hash(&blob);
    blob.extend_from_slice(&crc.to_be_bytes());
    assert_eq!(blob.len(), 105, "fixture must match the real v1 file size");
    blob
}

fn backend_with(
    device: Option<FakeDevice>,
    policy: HardwarePolicy,
) -> crate::Result<HardwareBoundBackend> {
    let provider = device.map(|d| Arc::new(d) as Arc<dyn HardwareProvider>);
    HardwareBoundBackend::new(MemoryBackend::default(), provider, policy)
}

// ---------------------------------------------------------------------------
// Tier detection — the reported tier must match reality, per platform.
// ---------------------------------------------------------------------------

/// **Proves:** for every hardware kind, a working device yields
/// `Hardware(that exact kind)` — not merely "some hardware tier".
///
/// **Why it matters:** the tier is what a UI renders. Reporting the wrong
/// component, or a generic "hardware", would misdescribe the protection in use.
///
/// **Catches:** a resolver that hard-codes one kind, or that returns the probed
/// kind while the provider binds another.
#[test]
fn tier_reports_the_exact_hardware_kind_per_platform() {
    for kind in ALL_KINDS {
        let be = backend_with(
            Some(FakeDevice::working(kind, 1)),
            HardwarePolicy::Preferred,
        )
        .expect("working device must resolve");
        assert_eq!(
            *be.tier(),
            ProtectionTier::Hardware(kind),
            "tier must name {kind} exactly"
        );
        assert_eq!(be.tier().hardware_kind(), Some(kind));
        assert!(be.tier().is_hardware_bound());
        assert!(
            be.tier().degrade_reason().is_none(),
            "a hardware tier has no degrade reason"
        );
    }
}

/// **Proves:** "degraded to software" is distinguishable from "hardware-bound",
/// and each degrade path reports its own distinct reason.
///
/// **Why it matters:** this is the defect the feature is most likely to ship —
/// a tier that reads as protected on a host with no protection. The assertion is
/// on the *specific* reason, so `NoHardwarePresent` and `ProbeIndeterminate`
/// cannot collapse into one another.
///
/// **Catches:** a `Software` tier without a reason; a resolver that maps every
/// negative outcome to the same reason; any tier that answers
/// `is_hardware_bound()` optimistically.
#[test]
fn software_tiers_are_distinguishable_and_carry_the_right_reason() {
    let cases: Vec<(FakeDevice, DegradeReason)> = vec![
        (
            FakeDevice::absent(HardwareKind::LinuxTpm20),
            DegradeReason::NoHardwarePresent,
        ),
        (
            FakeDevice::indeterminate(HardwareKind::LinuxTpm20, "tpm2 socket timed out"),
            DegradeReason::ProbeIndeterminate {
                detail: "tpm2 socket timed out".to_owned(),
            },
        ),
    ];

    for (device, expected) in cases {
        // `Optional` is the only policy that degrades on every outcome, which is
        // what lets one table cover both reasons.
        let be = backend_with(Some(device), HardwarePolicy::Optional).expect("optional opens");
        assert_eq!(*be.tier(), ProtectionTier::Software(expected.clone()));
        assert!(
            !be.tier().is_hardware_bound(),
            "a degraded tier must never read as hardware-bound"
        );
        assert_eq!(be.tier().degrade_reason(), Some(&expected));
    }

    // No provider at all is its own reason, not silently "no hardware present".
    let be = backend_with(None, HardwarePolicy::Optional).expect("no provider opens");
    assert_eq!(
        *be.tier(),
        ProtectionTier::Software(DegradeReason::NotRequested)
    );
}

/// **Proves:** the tier check can actually fail — a provider that *claims*
/// available hardware is refuted when the claim is not backed by behaviour.
///
/// **Why it matters:** a detection routine that only reads a probe and believes
/// it is not a check; it would report `Hardware` on any host where the probe is
/// optimistic or spoofed, which is the whole failure mode this feature must not
/// have. Each row is a different way to be inconsistent, so the resolver cannot
/// pass by handling one of them.
///
/// **Catches:** a `resolve_tier` that trusts `probe()` without a self-test; one
/// that accepts `ProcessMemory` custody as hardware-grade; one that ignores a
/// wrap error, a verbatim "wrap", or a round-trip that returns a different key.
#[test]
fn a_claimed_hardware_tier_is_refuted_when_the_claim_is_not_backed_by_behaviour() {
    let kind = HardwareKind::WindowsTpm20;
    let liars = [
        // Probes available, cannot wrap.
        FakeDevice::working(kind, 1).with_behaviour(WrapBehaviour::FailWrap),
        // Wraps, cannot unwrap.
        FakeDevice::working(kind, 1).with_behaviour(WrapBehaviour::FailUnwrap),
        // "Wraps" by returning the key verbatim — no protection at all.
        FakeDevice::working(kind, 1).with_behaviour(WrapBehaviour::Passthrough),
        // Round-trip yields a different key.
        FakeDevice::working(kind, 1).with_behaviour(WrapBehaviour::WrongKeyOnUnwrap),
        // Claims non-exportable custody it does not have.
        FakeDevice::working(kind, 1).with_custody(KeyCustody::ProcessMemory),
        // Contradicts itself about which component it binds.
        FakeDevice::working(kind, 1).with_kind(HardwareKind::LinuxTpm20),
    ];

    for (i, liar) in liars.into_iter().enumerate() {
        let be = backend_with(Some(liar), HardwarePolicy::Optional)
            .unwrap_or_else(|e| panic!("case {i}: optional policy must still open: {e}"));
        assert!(
            !be.tier().is_hardware_bound(),
            "case {i}: an unbacked hardware claim must not be reported as hardware-bound, got {:?}",
            be.tier()
        );
        assert!(
            matches!(
                be.tier().degrade_reason(),
                Some(DegradeReason::HardwareUnusable { .. })
            ),
            "case {i}: expected HardwareUnusable, got {:?}",
            be.tier().degrade_reason()
        );
    }

    // The control: the same device, honest, DOES reach the hardware tier — so
    // the assertions above are refuting the lie, not just always failing.
    let honest =
        backend_with(Some(FakeDevice::working(kind, 1)), HardwarePolicy::Optional).unwrap();
    assert_eq!(*honest.tier(), ProtectionTier::Hardware(kind));
}

// ---------------------------------------------------------------------------
// Fail-closed — the two questions are answered separately.
// ---------------------------------------------------------------------------

/// **Proves:** "could not determine" is handled distinctly from "no hardware"
/// and fails closed under the default policy, while a *confident* absence still
/// degrades under that same policy.
///
/// **Why it matters:** silence is the cheapest adversarial input. If an
/// indeterminate probe degraded silently, an attacker (or a flaky socket) could
/// strip hardware binding from a machine that has it by making the probe fail —
/// and the resulting software blob would then open anywhere.
///
/// **Catches:** a probe result collapsed into a two-valued answer; a policy that
/// treats both negatives identically. The `Absent` row is the control that keeps
/// this test from passing against an implementation that simply rejects
/// everything.
#[test]
fn indeterminate_probe_fails_closed_while_confident_absence_degrades() {
    let kind = HardwareKind::LinuxTpm20;

    // Default policy: could-not-determine is an ERROR.
    let err = backend_with(
        Some(FakeDevice::indeterminate(
            kind,
            "no /dev/tpmrm0 and tpm2 probe errored",
        )),
        HardwarePolicy::Preferred,
    )
    .expect_err("an indeterminate probe must fail closed under the default policy");
    match err {
        KeystoreError::HardwareProbeIndeterminate { detail } => {
            assert!(
                detail.contains("tpm2 probe errored"),
                "detail preserved: {detail}"
            );
        }
        other => panic!("expected HardwareProbeIndeterminate, got {other:?}"),
    }

    // Same policy, confident absence: degrades and opens.
    let be = backend_with(Some(FakeDevice::absent(kind)), HardwarePolicy::Preferred)
        .expect("a confident absence must still open under the default policy");
    assert_eq!(
        *be.tier(),
        ProtectionTier::Software(DegradeReason::NoHardwarePresent)
    );
}

/// **Proves:** `Required` refuses every non-hardware outcome, and the error
/// preserves *which* outcome it was.
///
/// **Why it matters:** a caller that demands hardware needs to know whether to
/// tell the user "your machine has no TPM" or "we could not reach your TPM" —
/// they lead to different actions.
///
/// **Catches:** a `Required` policy that degrades anyway; an error that flattens
/// the reason.
#[test]
fn required_policy_refuses_every_non_hardware_outcome_with_its_reason() {
    let kind = HardwareKind::MacSecureEnclave;

    let absent = backend_with(Some(FakeDevice::absent(kind)), HardwarePolicy::Required)
        .expect_err("Required must refuse an absent component");
    assert!(matches!(
        absent,
        KeystoreError::HardwareRequired {
            reason: DegradeReason::NoHardwarePresent
        }
    ));

    let none = backend_with(None, HardwarePolicy::Required)
        .expect_err("Required must refuse a missing provider");
    assert!(matches!(
        none,
        KeystoreError::HardwareRequired {
            reason: DegradeReason::NotRequested
        }
    ));

    let unusable = backend_with(
        Some(FakeDevice::working(kind, 1).with_behaviour(WrapBehaviour::FailWrap)),
        HardwarePolicy::Required,
    )
    .expect_err("Required must refuse unusable hardware");
    assert!(matches!(
        unusable,
        KeystoreError::HardwareRequired {
            reason: DegradeReason::HardwareUnusable { .. }
        }
    ));

    let indeterminate = backend_with(
        Some(FakeDevice::indeterminate(
            kind,
            "SecItemCopyMatching errored",
        )),
        HardwarePolicy::Required,
    )
    .expect_err("Required must refuse an undeterminable component");
    assert!(matches!(
        indeterminate,
        KeystoreError::HardwareProbeIndeterminate { .. }
    ));

    // Control: hardware present and working IS accepted under Required.
    let ok = backend_with(Some(FakeDevice::working(kind, 1)), HardwarePolicy::Required)
        .expect("Required must accept working hardware");
    assert_eq!(*ok.tier(), ProtectionTier::Hardware(kind));
}

// ---------------------------------------------------------------------------
// Degrade still works — the software envelope is the floor.
// ---------------------------------------------------------------------------

/// **Proves:** with no hardware, a blob still round-trips **and** is stored
/// byte-identically to what the caller wrote — the passphrase envelope passes
/// through as the floor, with no second layer and no bare-secret rewrite.
///
/// **Why it matters:** a machine without a TPM must not be locked out. Asserting
/// the *stored* bytes as well as the round-trip is what distinguishes a genuine
/// passthrough from a decorator that quietly re-encodes (which would break every
/// existing file and any other reader of that storage).
///
/// **Catches:** a degrade path that writes an envelope with a null/absent
/// wrapped key, or that alters the sealed bytes on the way past.
#[test]
fn no_hardware_still_unlocks_and_stores_the_software_envelope_unchanged() {
    let inner = Arc::new(MemoryBackend::default());
    let be = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::absent(HardwareKind::LinuxTpm20))),
        HardwarePolicy::Preferred,
    )
    .expect("degrade must open");

    let key = BackendKey::new("identity");
    let blob = v1_shaped_blob(0x5A);
    be.write(&key, &blob).unwrap();

    assert_eq!(be.read(&key).unwrap(), blob, "round-trip must be exact");
    assert_eq!(
        inner.read(&key).unwrap(),
        blob,
        "the software tier must store the sealed blob verbatim, not re-wrap it"
    );
    assert!(
        !envelope::is_envelope(&inner.read(&key).unwrap()),
        "no hardware envelope may be written when no hardware is bound"
    );
    assert!(!be.tier().is_hardware_bound());
}

// ---------------------------------------------------------------------------
// Non-exportability — the property being bought.
// ---------------------------------------------------------------------------

/// **Proves:** a blob sealed by one device cannot be opened by another device,
/// while the *same* device opens it fine.
///
/// **Why it matters:** this is the entire point of hardware binding — an
/// attacker who copies the sealed blob to another machine gets nothing. The
/// fixture is two devices differing in exactly one thing (the device key), with
/// the original kept as the honest control, so a failure here means "the other
/// machine was refused" rather than "nothing works".
///
/// **Catches:** an implementation that derives the content key from the blob, or
/// stores it in the envelope, or ignores the unwrap result — all of which would
/// let device B open device A's blob.
#[test]
fn a_blob_sealed_by_one_device_cannot_be_opened_by_another() {
    let kind = HardwareKind::WindowsTpm20;
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("identity");
    let blob = v1_shaped_blob(0x11);

    let machine_a = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::working(kind, 0xA1))),
        HardwarePolicy::Required,
    )
    .unwrap();
    machine_a.write(&key, &blob).unwrap();

    // Control: the sealing machine opens it.
    assert_eq!(machine_a.read(&key).unwrap(), blob);

    // A different device, same kind, same storage — the copied-blob scenario.
    let machine_b = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::working(kind, 0xB2))),
        HardwarePolicy::Required,
    )
    .unwrap();
    let err = machine_b
        .read(&key)
        .expect_err("another machine's hardware must not open this blob");
    assert!(
        matches!(err, KeystoreError::HardwareUnwrapFailed { .. }),
        "expected HardwareUnwrapFailed, got {err:?}"
    );
}

/// **Proves:** the wrapping key never appears in the stored bytes — neither the
/// content key nor anything that yields it without the hardware.
///
/// **Why it matters:** non-exportability is worthless if the key rides along in
/// the envelope. This inspects the actual stored artifact rather than trusting
/// the API.
///
/// **Catches:** a `wrap_key` that is a no-op or an encoding, and an envelope that
/// accidentally serialises the plaintext content key.
#[test]
fn the_stored_envelope_never_contains_the_content_key() {
    let kind = HardwareKind::WindowsTpm20;
    let inner = Arc::new(MemoryBackend::default());
    // Keep a handle on the device so the test can learn the ACTUAL content key it
    // was asked to wrap. Asserting against a key the test invented would prove
    // nothing about the key the code used.
    let device = Arc::new(FakeDevice::working(kind, 0xC3));
    let be = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(device.clone()),
        HardwarePolicy::Required,
    )
    .unwrap();

    let key = BackendKey::new("identity");
    let blob = v1_shaped_blob(0x22);
    be.write(&key, &blob).unwrap();

    let stored = inner.read(&key).unwrap();
    assert!(envelope::is_envelope(&stored));
    assert_eq!(&stored[..6], ENVELOPE_MAGIC);

    // The real content key used for this write must not appear anywhere in the
    // stored bytes — not in the wrapped-key region, not in the payload.
    let content_key = device
        .last_wrapped_content_key()
        .expect("the device must have been asked to wrap a content key");
    assert!(
        !contains_subslice(&stored, &content_key),
        "the plaintext content key must not appear anywhere in the stored envelope"
    );

    // Nor may the wrapped-key region simply BE the content key.
    let wrapped_len = u16::from_be_bytes([stored[22], stored[23]]) as usize;
    let wrapped = &stored[envelope::HEADER_FIXED..envelope::HEADER_FIXED + wrapped_len];
    assert_ne!(
        wrapped,
        &content_key[..],
        "the wrapped key must not be the content key verbatim"
    );

    // The plaintext inner blob must not be recoverable by inspection either.
    assert!(
        !contains_subslice(&stored, &blob),
        "the sealed inner blob must not appear verbatim in the envelope"
    );
}

/// Substring search over bytes — small inputs, clarity over speed.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// **Proves:** an envelope encountered on a host with no hardware tier is a hard
/// error, not raw ciphertext handed back to the caller.
///
/// **Why it matters:** returning the envelope bytes would make a copied blob look
/// like a corrupt keystore (or worse, get parsed as one) instead of correctly
/// reporting that this machine cannot open it. This is the second half of the
/// cross-machine story: not just "different hardware", but "no hardware at all".
///
/// **Catches:** a `read` whose envelope branch falls through to a passthrough
/// when no provider is held.
#[test]
fn an_envelope_cannot_be_opened_on_a_host_with_no_hardware() {
    let kind = HardwareKind::LinuxTpm20;
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("identity");

    let sealed_on_hardware = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::working(kind, 0xD4))),
        HardwarePolicy::Required,
    )
    .unwrap();
    sealed_on_hardware
        .write(&key, &v1_shaped_blob(0x33))
        .unwrap();

    let no_hardware = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::absent(kind))),
        HardwarePolicy::Preferred,
    )
    .unwrap();

    let err = no_hardware
        .read(&key)
        .expect_err("a hardware envelope must not open without hardware");
    match err {
        KeystoreError::NotHardwareBound { tier } => {
            assert!(
                tier.contains("software-wrapped"),
                "the error must say what tier this host actually has: {tier}"
            );
        }
        other => panic!("expected NotHardwareBound, got {other:?}"),
    }
}

/// **Proves:** an envelope sealed by a *different class* of hardware is refused
/// distinctly from one sealed by a different device of the same class.
///
/// **Why it matters:** the two situations need different messages ("this blob is
/// from a Mac" vs "this blob is from another machine"), and conflating them
/// hides a real migration case.
///
/// **Catches:** a read path that passes the wrapped key to the wrong provider and
/// reports a generic unwrap failure.
#[test]
fn an_envelope_from_a_different_hardware_class_is_refused_distinctly() {
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("identity");

    let mac = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::working(
            HardwareKind::MacSecureEnclave,
            1,
        ))),
        HardwarePolicy::Required,
    )
    .unwrap();
    mac.write(&key, &v1_shaped_blob(0x44)).unwrap();

    let windows = HardwareBoundBackend::with_inner(
        inner.clone(),
        // Same device key, so ONLY the hardware class differs — the unwrap would
        // otherwise succeed, which is what makes this test about the class check.
        Some(Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 1))),
        HardwarePolicy::Required,
    )
    .unwrap();

    let err = windows.read(&key).expect_err("cross-class must be refused");
    match err {
        KeystoreError::HardwareKindMismatch { expected, found } => {
            assert_eq!(expected, HardwareKind::WindowsTpm20.label());
            assert_eq!(found, HardwareKind::MacSecureEnclave.label());
        }
        other => panic!("expected HardwareKindMismatch, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Backwards compatibility (§5.1) — older blobs open unchanged.
// ---------------------------------------------------------------------------

/// **Proves:** a blob written before hardware binding existed — a bare v1
/// keystore file with no envelope — still reads byte-identically through the
/// hardware backend, in the hardware tier.
///
/// **Why it matters:** §5.1 is a HARD RULE and this is permanent user key
/// material. A reader that demanded an envelope would lock every existing user
/// out of their wallet the moment they upgraded onto a TPM-equipped machine.
///
/// **Catches:** a `read` that unconditionally decodes an envelope; a prefix check
/// that misclassifies a v1 magic.
#[test]
fn a_pre_existing_v1_blob_reads_unchanged_in_the_hardware_tier() {
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("legacy");
    let legacy = v1_shaped_blob(0x77);

    // Written directly to storage, as an older build would have left it.
    inner.write(&key, &legacy).unwrap();

    let be = HardwareBoundBackend::with_inner(
        inner,
        Some(Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 9))),
        HardwarePolicy::Required,
    )
    .unwrap();
    assert!(be.tier().is_hardware_bound());
    assert_eq!(
        be.read(&key).unwrap(),
        legacy,
        "a pre-existing v1 blob must read back byte-identically"
    );

    // The host is hardware-capable, but THIS key is not hardware-bound. The two
    // answers must differ here, and `blob_tier` is the one a UI may quote.
    assert_eq!(
        be.blob_tier(&key).unwrap(),
        ProtectionTier::Software(DegradeReason::BlobNotWrapped)
    );
}

// ---------------------------------------------------------------------------
// Per-blob tier — the question a UI actually has.
// ---------------------------------------------------------------------------

/// **Proves:** on a hardware-capable host holding a pre-existing unwrapped
/// keystore, `tier()` and `blob_tier()` give **different** answers, and only
/// `blob_tier()` reports the truth about that key.
///
/// **Why it matters:** this is the honesty property of the whole feature shifted
/// one level. Without it a UI reads `tier().is_hardware_bound() == true` and
/// renders "protected by your TPM" over a bare §3 blob that opens on any machine
/// after an offline Argon2id attack on the passphrase — telling the user they
/// have copy-resistance they do not have, and possibly leading them to guard the
/// file less carefully or choose a weaker passphrase.
///
/// **Catches:** a `blob_tier` that delegates to the host tier, or that is derived
/// from configuration rather than from the stored bytes. The wrapped key in the
/// same backend is the control, so the test cannot pass by always answering
/// "software".
#[test]
fn blob_tier_distinguishes_an_unwrapped_key_from_a_wrapped_one_on_the_same_host() {
    let inner = Arc::new(MemoryBackend::default());
    let legacy_key = BackendKey::new("legacy");
    let bound_key = BackendKey::new("bound");

    // A keystore written by an older build, straight to storage.
    inner.write(&legacy_key, &v1_shaped_blob(0xA0)).unwrap();

    let be = HardwareBoundBackend::with_inner(
        inner,
        Some(Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 3))),
        HardwarePolicy::Required,
    )
    .unwrap();

    // ...and one written through the hardware tier.
    be.write(&bound_key, &v1_shaped_blob(0xB0)).unwrap();

    // The HOST is hardware-capable.
    assert_eq!(
        *be.tier(),
        ProtectionTier::Hardware(HardwareKind::WindowsTpm20)
    );

    // The legacy KEY is not, and says why.
    let legacy_tier = be.blob_tier(&legacy_key).unwrap();
    assert!(
        !legacy_tier.is_hardware_bound(),
        "an unwrapped legacy blob must not report as hardware-bound, got {legacy_tier:?}"
    );
    assert_eq!(
        legacy_tier.degrade_reason(),
        Some(&DegradeReason::BlobNotWrapped)
    );
    assert_ne!(
        &legacy_tier,
        be.tier(),
        "host tier and blob tier must be able to disagree"
    );

    // The control: the freshly written key IS bound, so `blob_tier` is not
    // simply pessimistic.
    assert_eq!(
        be.blob_tier(&bound_key).unwrap(),
        ProtectionTier::Hardware(HardwareKind::WindowsTpm20)
    );
}

/// **Proves:** `blob_tier` names the class that **sealed the blob**, not the class
/// this host happens to have.
///
/// **Why it matters:** the tier describes stored key material, so a blob carried
/// over from a Mac must read as Secure-Enclave-bound even on a Windows host —
/// otherwise the report is about the machine again. Whether this host can *open*
/// it is a separate question that `read` answers.
///
/// **Catches:** an implementation that reports `self.tier` for any envelope, which
/// would be indistinguishable from correct if both hosts had the same class —
/// hence the deliberately mismatched pair.
#[test]
fn blob_tier_names_the_sealing_class_not_the_host_class() {
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("from_mac");

    let mac = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::working(
            HardwareKind::MacSecureEnclave,
            7,
        ))),
        HardwarePolicy::Required,
    )
    .unwrap();
    mac.write(&key, &v1_shaped_blob(0xC0)).unwrap();

    let windows = HardwareBoundBackend::with_inner(
        inner,
        Some(Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 7))),
        HardwarePolicy::Required,
    )
    .unwrap();

    assert_eq!(
        windows.blob_tier(&key).unwrap(),
        ProtectionTier::Hardware(HardwareKind::MacSecureEnclave),
        "the blob's own sealing class must be reported, not the host's"
    );
}

/// **Proves:** `blob_tier` fails closed on a wrapped blob it cannot fully
/// classify — an unrecognised hardware class, or a structurally invalid envelope
/// — rather than reporting it as software-protected.
///
/// **Why it matters:** reporting "software" for a blob that *is* wrapped would be
/// a lie in the safe-looking direction, and reporting "hardware" for a malformed
/// blob would be a lie in the dangerous one. Silence and unrecognised input are
/// the cheapest adversarial cases, so both are pinned.
///
/// **Catches:** a `blob_tier` whose fallback arm returns `Software`; a
/// classification that guesses a default hardware kind for an unknown wire id.
#[test]
fn blob_tier_fails_closed_on_a_blob_it_cannot_classify() {
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("identity");
    let be = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 4))),
        HardwarePolicy::Required,
    )
    .unwrap();
    be.write(&key, &v1_shaped_blob(0xD0)).unwrap();
    let good = inner.read(&key).unwrap();

    // An unassigned HW_KIND: sealed by hardware this build cannot name.
    let mut future = good.clone();
    future[8] = 0x7F;
    reseal_crc(&mut future);
    inner.write(&key, &future).unwrap();
    match be.blob_tier(&key) {
        Err(KeystoreError::UnknownHardwareClass { wire_id }) => assert_eq!(wire_id, 0x7F),
        other => panic!("expected UnknownHardwareClass, got {other:?}"),
    }

    // A corrupted envelope must not classify either.
    let mut corrupt = good.clone();
    corrupt[30] ^= 0xFF;
    inner.write(&key, &corrupt).unwrap();
    assert!(
        be.blob_tier(&key).is_err(),
        "a corrupt envelope must not be classified as software-protected"
    );

    // The control: the untouched envelope classifies fine.
    inner.write(&key, &good).unwrap();
    assert!(be.blob_tier(&key).unwrap().is_hardware_bound());
}

/// **Proves:** a structurally malformed envelope is reported distinctly from a
/// hardware refusal.
///
/// **Why it matters:** `HardwareUnwrapFailed` is documented as *the cross-machine
/// binding guarantee* — "the hardware refused". If a malformed blob also produced
/// it, that meaning would be muddied and a caller could not tell "this came from
/// another machine" from "these bytes are broken", which are different user
/// stories (move the key vs restore a backup).
///
/// **Catches:** the two conditions collapsed onto one variant. Two actors are in
/// play — a malformed blob and an honest-but-foreign device — so relocating the
/// distinction changes the observable result.
#[test]
fn a_malformed_envelope_is_distinct_from_a_hardware_refusal() {
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("identity");
    let sealing = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::working(
            HardwareKind::WindowsTpm20,
            0x51,
        ))),
        HardwarePolicy::Required,
    )
    .unwrap();
    sealing.write(&key, &v1_shaped_blob(0xE0)).unwrap();
    let good = inner.read(&key).unwrap();

    // Malformed: declares no wrapped key, kept length-consistent so the
    // empty-key rule is what objects.
    let mut no_key = good.clone();
    let w = u16::from_be_bytes([good[22], good[23]]) as usize;
    let p = u32::from_be_bytes(good[24..28].try_into().unwrap()) as usize;
    no_key[22..24].copy_from_slice(&0u16.to_be_bytes());
    no_key[24..28].copy_from_slice(&((p + w) as u32).to_be_bytes());
    reseal_crc(&mut no_key);
    inner.write(&key, &no_key).unwrap();
    assert!(
        matches!(
            sealing.read(&key),
            Err(KeystoreError::MalformedEnvelope { .. })
        ),
        "a malformed envelope must not be reported as a hardware refusal"
    );

    // Hardware refusal: intact blob, different machine.
    inner.write(&key, &good).unwrap();
    let other_machine = HardwareBoundBackend::with_inner(
        inner,
        Some(Arc::new(FakeDevice::working(
            HardwareKind::WindowsTpm20,
            0x62,
        ))),
        HardwarePolicy::Required,
    )
    .unwrap();
    assert!(
        matches!(
            other_machine.read(&key),
            Err(KeystoreError::HardwareUnwrapFailed { .. })
        ),
        "a foreign device must still report a hardware refusal"
    );
}

/// Recompute the trailing CRC-32 so a header edit is judged by the AEAD/structural
/// rules rather than tripping the corruption check first.
fn reseal_crc(bytes: &mut [u8]) {
    let body = bytes.len() - 4;
    let crc = crc32fast::hash(&bytes[..body]);
    bytes[body..].copy_from_slice(&crc.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Structural decode guards — one discriminating test per normative rule.
//
// These exist because of a lesson worth stating: every guard below sits on the
// HAPPY path, so line coverage reports it as covered while nothing asserts on it.
// Coverage measures execution, not verification — a guard is only tested by an
// input that makes it FIRE. Each case is therefore built to be rejected by
// exactly ONE guard: every other field is left self-consistent and the CRC is
// resealed, so if the guard under test were deleted the blob would proceed and
// the assertion would fail. Each asserts the specific error, never a broad type.
// ---------------------------------------------------------------------------

/// **Proves:** the [`FakeDevice`] double itself refuses malformed input rather than
/// returning arbitrary bytes — a short blob, a non-key blob, and a recall device
/// asked to unwrap before it has wrapped anything.
///
/// **Why it matters:** every binding test in this module rests on the double being
/// honest about failure. A double that quietly returned garbage instead of erroring
/// would make the tests that depend on "the other machine is refused" pass for the
/// wrong reason — the harness would become the false green.
///
/// **Catches:** a double whose `unwrap_key` indexes without a length check, or
/// whose recall slot yields a default key when empty.
#[test]
fn the_device_double_refuses_malformed_input_rather_than_inventing_a_key() {
    let honest = FakeDevice::working(HardwareKind::LinuxTpm20, 1);

    // Too short to carry the prefixed nonce.
    assert!(matches!(
        honest.unwrap_key(&[0u8; 4]),
        Err(KeystoreError::HardwareUnwrapFailed { .. })
    ));

    // Nonce present, but the sealed remainder is not a valid ciphertext.
    assert!(matches!(
        honest.unwrap_key(&[9u8; 20]),
        Err(KeystoreError::HardwareUnwrapFailed { .. })
    ));

    // A recall device that has wrapped nothing yet must not conjure a key.
    let recall = FakeDevice::working(HardwareKind::LinuxTpm20, 1)
        .with_behaviour(WrapBehaviour::EmptyWrapWithRecall);
    assert!(recall.last_wrapped_content_key().is_none());
    assert!(matches!(
        recall.unwrap_key(&[]),
        Err(KeystoreError::HardwareUnwrapFailed { .. })
    ));

    // A passthrough device handed something that is not a 32-byte key.
    let passthrough =
        FakeDevice::working(HardwareKind::LinuxTpm20, 1).with_behaviour(WrapBehaviour::Passthrough);
    assert!(matches!(
        passthrough.unwrap_key(b"not a key"),
        Err(KeystoreError::HardwareUnwrapFailed { .. })
    ));

    // Control: the honest device round-trips a key it actually wrapped.
    let key = envelope::random_content_key(&mut rand_core::OsRng);
    let wrapped = honest.wrap_key(&key).unwrap();
    assert_eq!(
        honest.unwrap_key(&wrapped).unwrap().as_slice(),
        key.as_slice()
    );
    assert_eq!(honest.last_wrapped_content_key().unwrap(), *key);
}

/// A valid envelope over a real-format inner blob, plus its handle for mutation.
fn good_envelope() -> Vec<u8> {
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("identity");
    let be = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::working(
            HardwareKind::LinuxTpm20,
            0x33,
        ))),
        HardwarePolicy::Required,
    )
    .unwrap();
    be.write(&key, &v1_shaped_blob(0x5C)).unwrap();
    inner.read(&key).unwrap()
}

/// **Proves:** the declared-length agreement rule fires — an envelope whose
/// `WRAPPED_LEN`/`PAYLOAD_LEN` do not account for exactly the bytes present is
/// rejected as `Truncated`, both when it under-declares and when it
/// over-declares.
///
/// **Why it matters:** this is the guard whose firing first produced a false
/// green elsewhere in this suite. Making that other fixture length-consistent
/// stopped this guard from masking the `WRAPPED_LEN` rule — but left the length
/// rule *itself* unasserted, so the vacuity moved one guard over rather than
/// shrinking. It is also the memory-safety guard: the over-declaring case slices
/// past the end of the buffer without it.
///
/// **Catches:** removal of the `declared != bytes.len()` check. Every other field
/// is left valid and the CRC resealed, so nothing else can object.
#[test]
fn an_envelope_whose_declared_lengths_disagree_with_its_size_is_rejected() {
    let good = good_envelope();
    let wrapped_len = u16::from_be_bytes([good[22], good[23]]);
    let payload_len = u32::from_be_bytes(good[24..28].try_into().unwrap());

    // Under-declares by one byte: still in-bounds to slice, so only the
    // agreement rule can object.
    let mut under = good.clone();
    under[22..24].copy_from_slice(&(wrapped_len - 1).to_be_bytes());
    reseal_crc(&mut under);
    match envelope::decode_for_test(&under) {
        Err(KeystoreError::Truncated { claimed, available }) => {
            assert_eq!(available, good.len());
            assert_eq!(claimed, good.len() - 1);
        }
        other => panic!("under-declared envelope must be Truncated, got {other:?}"),
    }

    // Over-declares far past the buffer: without the guard this indexes out of
    // bounds rather than erroring.
    let mut over = good.clone();
    over[24..28].copy_from_slice(&(payload_len + 1_000).to_be_bytes());
    reseal_crc(&mut over);
    match envelope::decode_for_test(&over) {
        Err(KeystoreError::Truncated { claimed, available }) => {
            assert_eq!(available, good.len());
            assert_eq!(claimed, good.len() + 1_000);
        }
        other => panic!("over-declared envelope must be Truncated, got {other:?}"),
    }

    // Control: untouched lengths decode.
    assert!(envelope::decode_for_test(&good).is_ok());
}

/// **Proves:** a `PAYLOAD_LEN` below the AES-GCM tag size is rejected as
/// `Truncated`, on a fixture that is otherwise **length-consistent**.
///
/// **Why it matters:** a payload shorter than the 16-byte tag cannot contain a
/// tag, so it can carry no authentication at all. The fixture is trimmed so the
/// declared total still equals the byte count — otherwise the length-agreement
/// guard would fire first and this rule would never be reached, which is exactly
/// the masking that hid it.
///
/// **Catches:** removal of the `payload_len < TAG_SIZE` check; without it the
/// blob decodes structurally and only fails later in the AEAD.
#[test]
fn an_envelope_whose_payload_cannot_hold_a_tag_is_rejected() {
    let good = good_envelope();
    let wrapped_len = u16::from_be_bytes([good[22], good[23]]) as usize;

    // One byte under the 16-byte tag, with the blob trimmed so
    // 28 + W + 15 + 4 == len exactly.
    const SHORT_PAYLOAD: u32 = 15;
    let total = envelope::HEADER_FIXED + wrapped_len + SHORT_PAYLOAD as usize + 4;
    let mut short = good[..total].to_vec();
    short[24..28].copy_from_slice(&SHORT_PAYLOAD.to_be_bytes());
    reseal_crc(&mut short);

    match envelope::decode_for_test(&short) {
        Err(KeystoreError::Truncated { claimed, .. }) => {
            assert_eq!(claimed, SHORT_PAYLOAD as usize);
        }
        other => panic!("a sub-tag payload must be Truncated, got {other:?}"),
    }

    // Pin the bound from the other side: exactly TAG_SIZE is structurally
    // acceptable (a bound tested only from below can only confirm itself).
    const TAG_ONLY: u32 = 16;
    let total = envelope::HEADER_FIXED + wrapped_len + TAG_ONLY as usize + 4;
    let mut at_bound = good[..total].to_vec();
    at_bound[24..28].copy_from_slice(&TAG_ONLY.to_be_bytes());
    reseal_crc(&mut at_bound);
    assert!(
        !matches!(
            envelope::decode_for_test(&at_bound),
            Err(KeystoreError::Truncated { .. })
        ),
        "a payload of exactly TAG_SIZE must pass the structural length rules"
    );
}

/// **Proves:** an envelope version this build does not implement is rejected as
/// `UnsupportedFormat`, carrying the version it saw.
///
/// **Why it matters:** the version is the dispatch point for every future
/// envelope shape. Silently parsing an unknown version with v1 rules would
/// misread fields — and because the version byte is inside the AAD, the failure
/// would surface as a confusing authentication error rather than "this build is
/// too old".
///
/// **Catches:** removal of the `ENV_VERSION` check.
#[test]
fn an_unknown_envelope_version_is_rejected_with_the_version_it_saw() {
    let mut future = good_envelope();
    future[6..8].copy_from_slice(&0x0002u16.to_be_bytes());
    reseal_crc(&mut future);

    match envelope::decode_for_test(&future) {
        Err(KeystoreError::UnsupportedFormat { found }) => assert_eq!(found, 0x0002),
        other => panic!("an unknown envelope version must be rejected, got {other:?}"),
    }
}

/// **Proves:** an unassigned `CIPHER_ID` is rejected as `UnsupportedCipher`,
/// carrying the id it saw.
///
/// **Why it matters:** the id selects the AEAD. Ignoring it would decrypt a
/// future ChaCha20-Poly1305 payload with AES-256-GCM.
///
/// **Catches:** removal of the `CIPHER_ID` check.
#[test]
fn an_unknown_envelope_cipher_id_is_rejected_with_the_id_it_saw() {
    let mut other_cipher = good_envelope();
    other_cipher[9] = 0x02;
    reseal_crc(&mut other_cipher);

    match envelope::decode_for_test(&other_cipher) {
        Err(KeystoreError::UnsupportedCipher(id)) => assert_eq!(id, 0x02),
        other => panic!("an unknown cipher id must be rejected, got {other:?}"),
    }
}

/// **Proves:** `decode` checks the magic itself, rather than relying on a caller
/// having pre-screened with `is_envelope`.
///
/// **Why it matters:** `decode` is reachable with bytes nobody screened, so the
/// check is not redundant with the backend's prefix test — a guard that is only
/// correct because of what its *callers* happen to do today breaks the first time
/// a new caller appears.
///
/// **Catches:** removal of the in-`decode` magic check.
#[test]
fn decode_rejects_a_foreign_magic_without_relying_on_its_caller() {
    let mut foreign = good_envelope();
    foreign[..6].copy_from_slice(b"DIGZZ9");
    reseal_crc(&mut foreign);

    match envelope::decode_for_test(&foreign) {
        Err(KeystoreError::UnknownMagic { saw }) => assert_eq!(&saw, b"DIGZZ9"),
        other => panic!("decode must check the magic itself, got {other:?}"),
    }
}

/// **Proves:** the self-test rejects a provider whose `wrap_key` returns an
/// **empty** wrapped key, even though its round-trip otherwise succeeds.
///
/// **Why it matters:** such a provider would write envelopes carrying no wrapped
/// key at all — the very shape `decode` refuses — so it must never reach a
/// hardware tier. The double had to be widened to express this at all: a device
/// that returned empty *and then failed to unwrap* is refuted by the round-trip
/// clause instead, leaving the empty-wrap guard silently untested. **A fixture
/// vocabulary that cannot express the adversary reports every guard as safe.**
///
/// **Catches:** removal of the `wrapped.is_empty()` check in the self-test.
#[test]
fn the_self_test_rejects_a_provider_that_wraps_to_nothing() {
    let kind = HardwareKind::WindowsTpm20;
    // Emits nothing, but recalls the key internally — so ONLY the empty-wrap
    // clause is violated.
    let liar = FakeDevice::working(kind, 1).with_behaviour(WrapBehaviour::EmptyWrapWithRecall);

    let be = backend_with(Some(liar), HardwarePolicy::Optional).expect("optional opens");
    assert!(
        !be.tier().is_hardware_bound(),
        "a provider that wraps to nothing must not reach a hardware tier, got {:?}",
        be.tier()
    );
    assert!(matches!(
        be.tier().degrade_reason(),
        Some(DegradeReason::HardwareUnusable { .. })
    ));

    // And under a policy that demands hardware, it is refused outright.
    assert!(matches!(
        backend_with(
            Some(FakeDevice::working(kind, 1).with_behaviour(WrapBehaviour::EmptyWrapWithRecall)),
            HardwarePolicy::Required
        ),
        Err(KeystoreError::HardwareRequired {
            reason: DegradeReason::HardwareUnusable { .. }
        })
    ));
}

/// **Proves:** the not-an-envelope rule holds for the whole class of non-`DIGHW1`
/// prefixes, including inner magics this build has never seen.
///
/// **Why it matters:** the guard must be stated over the class, not over the
/// three magics that exist today, or the next inner format silently becomes
/// unreadable. A future `DIGXX9` blob must pass through exactly like `DIGVK1`.
///
/// **Catches:** an `is_envelope` implemented as a whitelist of known inner
/// magics rather than a check for the envelope's own magic.
#[test]
fn every_non_envelope_prefix_passes_through_including_unknown_ones() {
    for magic in [
        &b"DIGVK1"[..],
        &b"DIGLW1"[..],
        &b"DIGOP1"[..],
        &b"DIGXX9"[..], // a format this build does not know
        &b"short"[..],  // too short to classify
        &b""[..],       // empty
    ] {
        assert!(
            !envelope::is_envelope(magic),
            "{magic:?} must not be treated as a hardware envelope"
        );
    }
    assert!(envelope::is_envelope(ENVELOPE_MAGIC));
    // A prefix that only partially matches is not an envelope either.
    assert!(!envelope::is_envelope(b"DIGHW"));
    assert!(envelope::is_envelope(b"DIGHW1trailing"));
}

// ---------------------------------------------------------------------------
// Envelope codec.
// ---------------------------------------------------------------------------

/// **Proves:** editing the `HW_KIND` byte of a sealed envelope makes the payload
/// fail authentication, because the header is bound as AAD.
///
/// **Why it matters:** without the AAD binding an attacker could relabel a blob's
/// hardware class, or swap in another machine's wrapped key, and the payload
/// would still decrypt. The CRC is repaired first, so this test isolates the
/// AEAD binding rather than tripping the corruption check.
///
/// **Catches:** an `encode` that omits the header from the AAD, or a `decode`
/// that replays a reconstructed header rather than the file's own bytes.
#[test]
fn editing_the_header_breaks_authentication_not_just_the_crc() {
    let kind = HardwareKind::LinuxTpm20;
    let inner = Arc::new(MemoryBackend::default());
    let device = Arc::new(FakeDevice::working(kind, 5));
    let be = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(device.clone()),
        HardwarePolicy::Required,
    )
    .unwrap();
    let key = BackendKey::new("identity");
    be.write(&key, &v1_shaped_blob(0x66)).unwrap();

    let mut stored = inner.read(&key).unwrap();
    // Relabel Linux TPM (0x03) as Windows TPM (0x01) at offset 8...
    assert_eq!(stored[8], HardwareKind::LinuxTpm20.wire_id());
    stored[8] = HardwareKind::WindowsTpm20.wire_id();
    // ...and repair the CRC so only the AEAD binding can object.
    let body_len = stored.len() - 4;
    let crc = crc32fast::hash(&stored[..body_len]);
    stored[body_len..].copy_from_slice(&crc.to_be_bytes());
    inner.write(&key, &stored).unwrap();

    // Read on a Windows-kind device with the SAME device key, so the wrapped key
    // still unwraps and the only remaining objection is the AAD binding.
    let relabelled = HardwareBoundBackend::with_inner(
        inner,
        Some(Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 5))),
        HardwarePolicy::Required,
    )
    .unwrap();
    assert!(
        matches!(relabelled.read(&key), Err(KeystoreError::DecryptFailed)),
        "a relabelled header must fail the AES-GCM tag"
    );
}

/// **Proves:** the codec rejects a truncated envelope, a corrupted one, and one
/// that declares no wrapped key, each with its own error.
///
/// **Why it matters:** silence and emptiness are the cheapest adversarial inputs.
/// A zero-length wrapped key in particular would mean "no hardware key protects
/// this" and must never decode as a hardware envelope.
///
/// **Catches:** length arithmetic that indexes past the end; a decoder that
/// accepts `WRAPPED_LEN = 0`; a CRC check that runs after the payload split.
#[test]
fn the_codec_rejects_truncated_corrupt_and_empty_key_envelopes() {
    let kind = HardwareKind::LinuxTpm20;
    let inner = Arc::new(MemoryBackend::default());
    let be = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::working(kind, 5))),
        HardwarePolicy::Required,
    )
    .unwrap();
    let key = BackendKey::new("identity");
    be.write(&key, &v1_shaped_blob(0x88)).unwrap();
    let good = inner.read(&key).unwrap();

    // The length floor is 28 (header) + 16 (tag) + 4 (CRC) = 48. Pin it from BOTH
    // sides and assert the ONE error each side produces, rather than accepting
    // either: below the floor the length rule must fire, at or above it the blob
    // is long enough to classify and the CRC over the wrong bytes is what objects.
    const FLOOR: usize = 48;
    for cut in [0usize, 6, 27, FLOOR - 1] {
        let err = envelope::decode_for_test(&good[..cut]).expect_err("below floor must fail");
        assert!(
            matches!(err, KeystoreError::Truncated { available, .. } if available == cut),
            "cut {cut} is below the floor and must be Truncated, got {err:?}"
        );
    }
    for cut in [FLOOR, good.len() - 1] {
        let err = envelope::decode_for_test(&good[..cut]).expect_err("short blob must fail");
        assert!(
            matches!(err, KeystoreError::CrcMismatch { .. }),
            "cut {cut} clears the floor, so the CRC must be what objects, got {err:?}"
        );
    }

    // A flipped payload byte trips the CRC before any cryptography.
    let mut corrupt = good.clone();
    let last_payload = corrupt.len() - 5;
    corrupt[last_payload] ^= 0xFF;
    assert!(matches!(
        envelope::decode_for_test(&corrupt),
        Err(KeystoreError::CrcMismatch { .. })
    ));

    // WRAPPED_LEN = 0 — "nothing protects this" must not decode.
    //
    // The fixture has to stay LENGTH-CONSISTENT or it proves nothing: simply
    // zeroing WRAPPED_LEN on a real envelope also makes the declared total
    // disagree with the byte count, so the length check fires and the empty-key
    // rule is never reached. Instead the wrapped-key bytes are re-attributed to
    // the payload, keeping `28 + 0 + payload_len + 4 == len`, so the ONLY
    // remaining objection is the empty wrapped key — and the assertion names
    // that one error rather than accepting any failure.
    let mut no_key = good.clone();
    let old_wrapped_len = u16::from_be_bytes([good[22], good[23]]) as usize;
    let old_payload_len = u32::from_be_bytes(good[24..28].try_into().unwrap()) as usize;
    assert!(
        old_wrapped_len > 0,
        "the control envelope must have a wrapped key"
    );
    no_key[22..24].copy_from_slice(&0u16.to_be_bytes());
    no_key[24..28].copy_from_slice(&((old_payload_len + old_wrapped_len) as u32).to_be_bytes());
    let body_len = no_key.len() - 4;
    let crc = crc32fast::hash(&no_key[..body_len]);
    no_key[body_len..].copy_from_slice(&crc.to_be_bytes());
    let err = envelope::decode_for_test(&no_key).expect_err("empty wrapped key must fail");
    assert!(
        matches!(err, KeystoreError::MalformedEnvelope { .. }),
        "an envelope declaring no wrapped key is MALFORMED, not a hardware refusal, got {err:?}"
    );

    // The control: the untouched envelope still decodes.
    assert!(envelope::decode_for_test(&good).is_ok());
}

/// **Proves:** every [`HardwareKind`] wire id round-trips and the ids are
/// distinct, while an unassigned id parses as `None` rather than defaulting.
///
/// **Why it matters:** these ids are written into permanent at-rest blobs
/// (§5.1). A renumbering or a collision would misattribute — or unseal — stored
/// key material, and a default-on-unknown would let a future blob be opened by
/// the wrong provider.
///
/// **Catches:** a duplicated discriminant; a `from_wire_id` with a catch-all arm.
#[test]
fn hardware_kind_wire_ids_are_stable_distinct_and_strict() {
    let mut seen = Vec::new();
    for kind in ALL_KINDS {
        let id = kind.wire_id();
        assert!(!seen.contains(&id), "duplicate wire id {id:#04x}");
        seen.push(id);
        assert_eq!(HardwareKind::from_wire_id(id), Some(kind));
    }
    // Pin the assigned values so a reorder of the enum cannot move them.
    assert_eq!(HardwareKind::WindowsTpm20.wire_id(), 0x01);
    assert_eq!(HardwareKind::MacSecureEnclave.wire_id(), 0x02);
    assert_eq!(HardwareKind::LinuxTpm20.wire_id(), 0x03);
    assert_eq!(HardwareKind::from_wire_id(0x00), None);
    assert_eq!(HardwareKind::from_wire_id(0xFF), None);
}

/// **Proves:** `Debug` reports the tier but redacts the inner store, and the
/// tier/reason `Display` strings are distinguishable prose.
///
/// **Why it matters:** the tier is exactly what an operator needs in a log, and
/// exactly what must not be a lie; the inner store must never be printed.
///
/// **Catches:** a derived `Debug` that prints the wrapped storage; a `Display`
/// that renders a degraded tier the same as a bound one.
#[test]
fn debug_redacts_storage_and_display_distinguishes_tiers() {
    let hw = backend_with(
        Some(FakeDevice::working(HardwareKind::WindowsTpm20, 1)),
        HardwarePolicy::Required,
    )
    .unwrap();
    let rendered = format!("{hw:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("Hardware"));

    let sw = backend_with(
        Some(FakeDevice::absent(HardwareKind::WindowsTpm20)),
        HardwarePolicy::Preferred,
    )
    .unwrap();
    assert!(hw.tier().to_string().contains("hardware-bound"));
    assert!(sw.tier().to_string().contains("software-wrapped"));
    assert_ne!(hw.tier().to_string(), sw.tier().to_string());
}

/// **Proves:** the decorator delegates `list`, `exists`, and `delete` to the
/// inner backend, in both tiers.
///
/// **Why it matters:** enumeration and deletion must not change behaviour just
/// because hardware binding is on; a keystore that vanishes from `list()` under
/// a TPM would look deleted.
///
/// **Catches:** a decorator that forgets a delegation or filters envelopes out
/// of a listing.
#[test]
fn enumeration_and_deletion_delegate_in_both_tiers() {
    for device in [
        FakeDevice::working(HardwareKind::WindowsTpm20, 1),
        FakeDevice::absent(HardwareKind::WindowsTpm20),
    ] {
        let be = backend_with(Some(device), HardwarePolicy::Optional).unwrap();
        let a = BackendKey::new("wallet/a");
        let b = BackendKey::new("other/b");
        be.write(&a, &v1_shaped_blob(1)).unwrap();
        be.write(&b, &v1_shaped_blob(2)).unwrap();

        assert!(be.exists(&a).unwrap());
        let listed: Vec<String> = be
            .list("wallet/")
            .unwrap()
            .into_iter()
            .map(|k| k.0)
            .collect();
        assert_eq!(listed, vec!["wallet/a".to_owned()]);

        be.delete(&a).unwrap();
        assert!(!be.exists(&a).unwrap());
        assert!(be.exists(&b).unwrap());
    }
}

// ---------------------------------------------------------------------------
// Reversible binding — losing the hardware must not strand a seed (#1502).
// ---------------------------------------------------------------------------

/// **Proves:** `unbind` returns a hardware-bound blob to the portable software
/// form, so a host that no longer has the sealing hardware can still open it.
///
/// **Why it matters:** hardware binding makes the trusted component a SECOND
/// required factor. A TPM is cleared by a firmware update, a board swap, or a
/// BIOS reset — ordinary events. Without a way back, the correct passphrase
/// stops being enough and the seed is gone. This is the escape hatch, and it
/// must be taken while the hardware still answers.
///
/// **Catches:** the obvious wrong implementation — writing the unwrapped bytes
/// through `self.write`, which in the hardware tier RE-WRAPS them, reporting
/// success while the blob stays bound. The fixture can see that because it
/// re-reads through a backend with NO provider (the machine whose TPM is gone),
/// not through the backend that did the unbinding.
#[test]
fn unbind_returns_the_blob_to_a_form_a_machine_without_the_hardware_can_open() {
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("identity");
    let blob = v1_shaped_blob(0x33);

    let bound = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::working(HardwareKind::WindowsTpm20, 7))),
        HardwarePolicy::Required,
    )
    .unwrap();
    bound.write(&key, &blob).unwrap();
    assert!(
        envelope::is_envelope(&inner.read(&key).unwrap()),
        "precondition: the blob really is hardware-bound"
    );

    let tier = bound
        .unbind(&key)
        .expect("unbind while the hardware answers");
    assert_eq!(
        tier,
        ProtectionTier::Software(DegradeReason::BlobNotWrapped)
    );

    // The machine whose hardware is gone. It shares the storage and has no
    // provider at all — exactly the post-TPM-clear situation.
    let stranded = HardwareBoundBackend::with_inner(inner.clone(), None, HardwarePolicy::Optional)
        .expect("a host with no hardware still opens");
    assert_eq!(
        stranded.read(&key).unwrap(),
        blob,
        "after unbind the sealed keystore must open without the hardware"
    );
    assert_eq!(
        stranded.blob_tier(&key).unwrap(),
        ProtectionTier::Software(DegradeReason::BlobNotWrapped),
        "and it reports the protection it actually has, not the one it had"
    );
}

/// **Proves:** `bind` migrates an existing unwrapped keystore UP to hardware,
/// and binding an already-bound blob is idempotent rather than double-wrapping.
///
/// **Why it matters:** every keystore written before this feature is unwrapped.
/// Without an explicit migration the only way to bind one is to rewrite it, and
/// a second `bind` that nested a second envelope would produce a blob whose
/// single unwrap yields another envelope — openable by nothing.
///
/// **Catches:** a `bind` that skips the already-an-envelope check.
#[test]
fn bind_migrates_a_legacy_blob_up_and_is_idempotent() {
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("identity");
    let blob = v1_shaped_blob(0x44);
    // A legacy blob, written before hardware binding existed.
    inner.write(&key, &blob).unwrap();

    let be = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(FakeDevice::working(HardwareKind::LinuxTpm20, 9))),
        HardwarePolicy::Required,
    )
    .unwrap();
    assert_eq!(
        be.blob_tier(&key).unwrap(),
        ProtectionTier::Software(DegradeReason::BlobNotWrapped),
        "precondition: a capable host does not retroactively protect old bytes"
    );

    let tier = be.bind(&key).expect("migrate up");
    assert_eq!(tier, ProtectionTier::Hardware(HardwareKind::LinuxTpm20));
    assert_eq!(be.read(&key).unwrap(), blob, "and it still opens here");

    // Idempotent: a second bind must not nest a second envelope.
    let again = be
        .bind(&key)
        .expect("binding an already-bound blob is a no-op");
    assert_eq!(again, ProtectionTier::Hardware(HardwareKind::LinuxTpm20));
    assert_eq!(
        be.read(&key).unwrap(),
        blob,
        "one unwrap must still reach the keystore, not a second envelope"
    );
}

/// **Proves:** when `bind` cannot prove the newly-sealed blob reopens, it
/// RESTORES the previous bytes and fails, rather than leaving storage holding a
/// blob nothing can open.
///
/// **Why it matters:** `bind` overwrites the only copy. If the wrap is not
/// actually recoverable, a bind that returned success would have destroyed the
/// seed while reporting that it had protected it. dig-app's 5.x migration
/// learned exactly this: read from the account's own vault, and be able to put
/// the prior seal back.
///
/// **Fixture:** a device that passes the constructor self-test and only then
/// stops unwrapping — the self-test's own round-trip is unwrap #1, so a device
/// failing from unwrap #2 is honest at construction and broken at verification.
/// A device that failed from the start would degrade to software at
/// construction and never reach `bind` at all, which is why the ordinary
/// `FailUnwrap` fixture cannot express this.
#[test]
fn a_bind_that_cannot_be_reopened_restores_the_previous_bytes() {
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("identity");
    let blob = v1_shaped_blob(0x55);
    inner.write(&key, &blob).unwrap();

    let be = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(
            FakeDevice::working(HardwareKind::WindowsTpm20, 3).failing_unwrap_after(1),
        )),
        HardwarePolicy::Required,
    )
    .expect("the device is honest at construction");

    let err = be
        .bind(&key)
        .expect_err("a seal that cannot be reopened must not be committed");
    assert!(
        matches!(err, KeystoreError::HardwareUnwrapFailed { .. }),
        "it reports the hardware failing to reopen its own seal: {err}"
    );
    assert_eq!(
        inner.read(&key).unwrap(),
        blob,
        "the previous, openable bytes are restored — bind is all-or-nothing"
    );
}

/// **Proves:** `unbind` leaves the stored blob untouched when the hardware can
/// no longer open it.
///
/// **Why it matters:** this is the too-late case — the TPM is already gone. The
/// blob is unrecoverable, and that is by design, but `unbind` must not make it
/// WORSE by overwriting the envelope with anything. If the hardware is restored
/// (a re-enrolled key, a swapped-back board), the bytes must still be there.
///
/// **Catches:** an implementation that truncates or writes before it has the
/// plaintext in hand.
#[test]
fn unbind_leaves_the_blob_intact_when_the_hardware_can_no_longer_open_it() {
    let inner = Arc::new(MemoryBackend::default());
    let key = BackendKey::new("identity");
    let blob = v1_shaped_blob(0x66);

    let device = FakeDevice::working(HardwareKind::MacSecureEnclave, 0x5E);
    let be = HardwareBoundBackend::with_inner(
        inner.clone(),
        Some(Arc::new(device.clone())),
        HardwarePolicy::Required,
    )
    .unwrap();
    be.write(&key, &blob).unwrap();
    let sealed = inner.read(&key).unwrap();

    // The trusted component is cleared: same device, different key material.
    device.rotate_device_key(0x99);

    let err = be
        .unbind(&key)
        .expect_err("the cleared hardware cannot open its own envelope");
    assert!(matches!(err, KeystoreError::HardwareUnwrapFailed { .. }));
    assert_eq!(
        inner.read(&key).unwrap(),
        sealed,
        "a failed unbind must not disturb the stored bytes"
    );
}

/// **Proves:** `unbind` fails when storage silently did not take the write.
///
/// **Why it matters:** `unbind` exists so a user can safely retire the trusted
/// component. Reporting "unbound" over a store that kept the envelope is the
/// one failure with a catastrophic follow-on action: the user, believing the
/// seed is portable, clears the TPM — and only then discovers it is not.
///
/// **Catches:** an implementation that trusts its own write. The fixture is a
/// store whose `write` succeeds and does nothing, which is what a full disk or
/// a read-only mount looks like from here.
#[test]
fn unbind_refuses_to_report_success_when_the_store_kept_the_envelope() {
    /// Storage that accepts writes and silently discards them.
    struct WriteDroppingStore(MemoryBackend);

    impl KeychainBackend for WriteDroppingStore {
        fn read(&self, key: &BackendKey) -> crate::Result<Vec<u8>> {
            self.0.read(key)
        }
        fn write(&self, _key: &BackendKey, _data: &[u8]) -> crate::Result<()> {
            Ok(()) // accepted, never stored
        }
        fn delete(&self, key: &BackendKey) -> crate::Result<()> {
            self.0.delete(key)
        }
        fn list(&self, prefix: &str) -> crate::Result<Vec<BackendKey>> {
            self.0.list(prefix)
        }
        fn exists(&self, key: &BackendKey) -> crate::Result<bool> {
            self.0.exists(key)
        }
    }

    let key = BackendKey::new("identity");
    let blob = v1_shaped_blob(0x77);
    let device = FakeDevice::working(HardwareKind::LinuxTpm20, 0x21);

    // Seal into staging storage first, then present that same envelope through a
    // store that will not accept the unbinding write.
    let staging = Arc::new(MemoryBackend::default());
    let sealer = HardwareBoundBackend::with_inner(
        staging.clone(),
        Some(Arc::new(device.clone())),
        HardwarePolicy::Required,
    )
    .unwrap();
    sealer.write(&key, &blob).unwrap();
    let sealed = staging.read(&key).unwrap();

    let real = MemoryBackend::default();
    real.write(&key, &sealed).unwrap();

    let be = HardwareBoundBackend::with_inner(
        Arc::new(WriteDroppingStore(real)),
        Some(Arc::new(device)),
        HardwarePolicy::Required,
    )
    .unwrap();

    let err = be
        .unbind(&key)
        .expect_err("a store that kept the envelope must not read as unbound");
    assert!(
        err.to_string().contains("still hardware-bound"),
        "the error says the blob is STILL bound, so the user does not retire the \
         trusted component on the strength of it: {err}"
    );
}

// ---------------------------------------------------------------------------
// Composition with the OS credential store (feature `os-keychain`).
// ---------------------------------------------------------------------------

/// **Proves:** a `HardwareBoundBackend` layered over a real
/// [`OsKeychainBackend`] round-trips a `DIGOP1` payload — the hardware
/// envelope it stores is a payload the OS-store write guard accepts.
///
/// **Why it matters:** `HardwareBoundBackend::write` seals into a `DIGHW1`
/// envelope and hands those bytes to its inner backend, and an
/// `OsKeychainBackend` is a legitimate inner. §10.5's write guard therefore
/// sees `DIGHW1`, never the caller's own magic. An allowlist covering only the
/// magics in `format.rs` would reject every hardware-bound write and break a
/// shipped composition — a failure no single-backend test can see, because the
/// two halves are each correct in isolation.
///
/// **Catches:** `DIGHW1` missing from the §10.5 allowlist; a guard that
/// inspects the caller's payload rather than the bytes actually stored.
#[cfg(feature = "os-keychain")]
#[test]
fn hardware_envelope_round_trips_through_the_os_keychain_backend() {
    use crate::backend::os_keychain::test_support::fake_backend;

    let be = HardwareBoundBackend::new(
        fake_backend(),
        Some(Arc::new(FakeDevice::working(
            HardwareKind::WindowsTpm20,
            0x5A,
        ))),
        HardwarePolicy::Required,
    )
    .unwrap();

    let key = BackendKey::new("identity");
    // A `DIGOP1` payload — the opaque container a caller seals in practice.
    let mut payload = b"DIGOP1".to_vec();
    payload.extend_from_slice(&[0x77; 64]);

    be.write(&key, &payload)
        .expect("a hardware-bound write must be storable in the OS credential store");
    assert_eq!(be.read(&key).unwrap(), payload);
}
