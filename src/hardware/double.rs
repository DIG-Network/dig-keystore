//! [`FakeDevice`] — a configurable [`HardwareProvider`] double.
//!
//! # Why a double, and what it does and does not prove
//!
//! Real TPM / Secure Enclave hardware is absent from CI (this repo's workflows
//! run `ubuntu-latest` only) and cannot be made to lie on demand. `FakeDevice`
//! exists to exercise the parts that *are* platform-independent: the tier
//! decision, the fail-closed rules, the envelope codec, and the cross-machine
//! binding property.
//!
//! It models non-exportability **structurally**: the device key lives only
//! inside the `FakeDevice` and is never written into an envelope, so a second
//! device with a different key cannot open the first device's blobs — exactly
//! the situation of a sealed blob copied to another machine. What the double
//! cannot prove is that a *real* platform key is non-exportable; that assertion
//! belongs against the platform itself (it is made by attempting an export and
//! requiring the platform to refuse).
//!
//! The double is deliberately **wide**. A double that can vary only one field
//! cannot express a multi-field lie, and the interesting failures here are
//! precisely providers that are inconsistent with themselves: one that probes
//! `Available` but cannot wrap, one that claims a hardware kind it does not
//! bind, one that reports `NonExportable` custody over a key held in process
//! memory.

use zeroize::Zeroizing;

use std::sync::Arc;

use parking_lot::Mutex;

use super::provider::{ContentKey, HardwareProvider, KeyCustody, CONTENT_KEY_LEN};
use super::tier::{HardwareKind, HardwareProbe};
use crate::cipher;
use crate::error::{KeystoreError, Result};

/// How a [`FakeDevice`] behaves when asked to wrap or unwrap.
///
/// Each variant is an adversary the tier self-test must refute. The vocabulary is
/// deliberately wide: **a fixture set that cannot express a given lie reports the
/// guard against it as safe**, so every clause of the self-test contract needs a
/// variant that violates exactly that clause.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WrapBehaviour {
    /// Correct: AES-256-GCM under the device key, round-trips.
    #[default]
    Honest,
    /// `wrap_key` errors — models hardware that probes present but cannot be used.
    FailWrap,
    /// `wrap_key` succeeds, `unwrap_key` errors.
    FailUnwrap,
    /// `wrap_key` returns the content key verbatim — models a "wrapping" that
    /// wraps nothing, leaving the key exportable with the blob.
    Passthrough,
    /// `unwrap_key` returns a *different* key rather than failing — models a
    /// provider whose round-trip silently does not reproduce the key.
    WrongKeyOnUnwrap,

    /// `wrap_key` returns an **empty** wrapped key while `unwrap_key` still
    /// reproduces the right one from an internal slot.
    ///
    /// Models a provider that emits nothing into the envelope but remembers the
    /// key out of band. It is the only way to violate *just* the
    /// "a wrap that returns nothing" clause of the self-test contract: a device
    /// that returned empty and then failed to unwrap would be refuted by the
    /// round-trip clause instead, leaving the empty-wrap guard untested. Such a
    /// provider would write envelopes carrying no wrapped key at all.
    EmptyWrapWithRecall,
}

/// A configurable stand-in for a hardware trusted component.
#[derive(Debug, Clone)]
pub struct FakeDevice {
    kind: HardwareKind,
    probe: HardwareProbe,
    custody: KeyCustody,
    behaviour: WrapBehaviour,
    /// Per-device key. Never leaves this struct and is never written into an
    /// envelope — this is what makes one device's blobs unopenable by another.
    ///
    /// Shared and mutable so a clone of the device observes a
    /// [`rotate_device_key`](FakeDevice::rotate_device_key) — the double's model
    /// of a trusted component being CLEARED while the same handle is held.
    device_key: Arc<Mutex<[u8; 32]>>,
    /// How many more `unwrap_key` calls succeed before the device stops
    /// unwrapping, or `None` for a device that always works.
    ///
    /// A device that is broken from the start is refuted by the constructor
    /// self-test and never reaches the operations under test, so expressing
    /// "honest at construction, broken afterwards" needs a budget rather than
    /// another [`WrapBehaviour`] variant. Shared like the key, for the same
    /// reason.
    unwraps_left: Arc<Mutex<Option<usize>>>,
    /// The last content key this device was asked to wrap.
    ///
    /// Serves two purposes: it lets a test assert that the plaintext content key
    /// does not appear in the stored envelope, and it lets
    /// [`WrapBehaviour::EmptyWrapWithRecall`] reproduce a key it never wrote out.
    /// Shared behind an `Arc` so a clone of the device observes the same slot.
    last_wrapped: Arc<Mutex<Option<[u8; CONTENT_KEY_LEN]>>>,
}

impl FakeDevice {
    /// An honest, working device of `kind`, keyed by `device_id`.
    ///
    /// Two devices with different `device_id`s stand for two different machines.
    pub fn working(kind: HardwareKind, device_id: u8) -> Self {
        Self {
            kind,
            probe: HardwareProbe::Available(kind),
            custody: KeyCustody::NonExportable,
            behaviour: WrapBehaviour::Honest,
            device_key: Arc::new(Mutex::new([device_id; 32])),
            unwraps_left: Arc::default(),
            last_wrapped: Arc::default(),
        }
    }

    /// The last content key this device was asked to wrap, if any.
    ///
    /// Test-only observability: it is what makes "the content key never appears
    /// in the stored bytes" an assertion about the actual key rather than about a
    /// value the test invented.
    pub fn last_wrapped_content_key(&self) -> Option<[u8; CONTENT_KEY_LEN]> {
        *self.last_wrapped.lock()
    }

    /// A host with definitively no hardware.
    pub fn absent(kind: HardwareKind) -> Self {
        Self {
            probe: HardwareProbe::Absent,
            ..Self::working(kind, 0)
        }
    }

    /// A host whose hardware could not be inspected.
    pub fn indeterminate(kind: HardwareKind, detail: &str) -> Self {
        Self {
            probe: HardwareProbe::indeterminate(detail),
            ..Self::working(kind, 0)
        }
    }

    /// Override the probe outcome.
    pub fn with_probe(mut self, probe: HardwareProbe) -> Self {
        self.probe = probe;
        self
    }

    /// Override the reported custody.
    pub fn with_custody(mut self, custody: KeyCustody) -> Self {
        self.custody = custody;
        self
    }

    /// Override the wrap/unwrap behaviour.
    pub fn with_behaviour(mut self, behaviour: WrapBehaviour) -> Self {
        self.behaviour = behaviour;
        self
    }

    /// Override the advertised kind independently of the probed kind, so the
    /// double can contradict itself.
    pub fn with_kind(mut self, kind: HardwareKind) -> Self {
        self.kind = kind;
        self
    }

    /// Replace this device's key material, as a TPM clear / re-enrolment does.
    ///
    /// Blobs sealed before the rotation become unopenable by this device, which
    /// is precisely what a user sees after a firmware update clears the TPM.
    /// Clones share the slot, so a backend already holding this provider sees
    /// the change.
    pub fn rotate_device_key(&self, device_id: u8) {
        *self.device_key.lock() = [device_id; 32];
    }

    /// Succeed at `n` more unwraps, then fail every one after that.
    ///
    /// Models a component that is healthy when inspected and unusable moments
    /// later. The constructor self-test spends exactly one unwrap, so
    /// `failing_unwrap_after(1)` yields a device that resolves a genuine
    /// hardware tier and then cannot reopen the next thing it seals.
    pub fn failing_unwrap_after(self, n: usize) -> Self {
        *self.unwraps_left.lock() = Some(n);
        self
    }

    /// Length of the per-wrap nonce prefixed to a wrapped blob.
    const NONCE_LEN: usize = 12;

    /// Draw a fresh nonce for one wrap.
    ///
    /// A fixed nonce would be wrong even in a double: every wrap encrypts a
    /// *different* freshly-generated content key under the same device key, so a
    /// constant nonce is AES-GCM nonce reuse across distinct plaintexts. The
    /// nonce is prefixed to the wrapped blob so `unwrap_key` can recover it.
    fn fresh_nonce() -> [u8; Self::NONCE_LEN] {
        let mut nonce = <[u8; Self::NONCE_LEN]>::default();
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        nonce
    }
}

impl HardwareProvider for FakeDevice {
    fn kind(&self) -> HardwareKind {
        self.kind
    }

    fn probe(&self) -> HardwareProbe {
        self.probe.clone()
    }

    fn custody(&self) -> KeyCustody {
        self.custody
    }

    fn wrap_key(&self, content_key: &ContentKey) -> Result<Vec<u8>> {
        *self.last_wrapped.lock() = Some(**content_key);
        match self.behaviour {
            WrapBehaviour::FailWrap => Err(KeystoreError::HardwareWrapFailed {
                detail: "fake device refuses to wrap".to_owned(),
            }),
            WrapBehaviour::Passthrough => Ok(content_key.to_vec()),
            // Emits nothing, but see `unwrap_key` — the key is remembered.
            WrapBehaviour::EmptyWrapWithRecall => Ok(Vec::new()),
            _ => {
                // nonce || AES-256-GCM(content key) under the device key.
                let nonce = Self::fresh_nonce();
                let device_key = *self.device_key.lock();
                let sealed = cipher::encrypt(&device_key, &nonce, content_key.as_slice(), b"")?;
                let mut out = Vec::with_capacity(nonce.len() + sealed.len());
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&sealed);
                Ok(out)
            }
        }
    }

    fn unwrap_key(&self, wrapped: &[u8]) -> Result<ContentKey> {
        // Spend the unwrap budget first: an exhausted device refuses regardless
        // of behaviour, which is what makes "healthy at construction, broken
        // afterwards" expressible.
        {
            let mut left = self.unwraps_left.lock();
            if let Some(remaining) = left.as_mut() {
                if *remaining == 0 {
                    return Err(KeystoreError::HardwareUnwrapFailed {
                        detail: "fake device stopped unwrapping".to_owned(),
                    });
                }
                *remaining -= 1;
            }
        }
        match self.behaviour {
            WrapBehaviour::FailUnwrap => {
                return Err(KeystoreError::HardwareUnwrapFailed {
                    detail: "fake device refuses to unwrap".to_owned(),
                })
            }
            WrapBehaviour::WrongKeyOnUnwrap => {
                // Any key OTHER than the one wrapped; derived, not a literal.
                let mut wrong = <[u8; CONTENT_KEY_LEN]>::default();
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut wrong);
                return Ok(Zeroizing::new(wrong));
            }
            WrapBehaviour::EmptyWrapWithRecall => {
                return self.last_wrapped.lock().map(Zeroizing::new).ok_or_else(|| {
                    KeystoreError::HardwareUnwrapFailed {
                        detail: "recall device has wrapped nothing yet".to_owned(),
                    }
                })
            }
            WrapBehaviour::Passthrough => {
                let bytes: [u8; CONTENT_KEY_LEN] =
                    wrapped
                        .try_into()
                        .map_err(|_| KeystoreError::HardwareUnwrapFailed {
                            detail: "passthrough device got a non-key blob".to_owned(),
                        })?;
                return Ok(Zeroizing::new(bytes));
            }
            _ => {}
        }

        // Split the prefixed nonce back off. A blob too short to carry one was
        // not produced by this device.
        if wrapped.len() <= Self::NONCE_LEN {
            return Err(KeystoreError::HardwareUnwrapFailed {
                detail: "wrapped blob is too short to carry a nonce".to_owned(),
            });
        }
        let (nonce, sealed) = wrapped.split_at(Self::NONCE_LEN);
        let nonce: [u8; Self::NONCE_LEN] = nonce.try_into().expect("checked length");

        // A blob sealed by a *different* device key fails here — the
        // cross-machine binding guarantee.
        let device_key = *self.device_key.lock();
        let plain = cipher::decrypt(&device_key, &nonce, sealed, b"").map_err(|_| {
            KeystoreError::HardwareUnwrapFailed {
                detail: "wrapped key was not sealed by this device".to_owned(),
            }
        })?;
        let bytes: [u8; CONTENT_KEY_LEN] =
            plain
                .as_slice()
                .try_into()
                .map_err(|_| KeystoreError::HardwareUnwrapFailed {
                    detail: "unwrapped key has the wrong length".to_owned(),
                })?;
        Ok(Zeroizing::new(bytes))
    }
}
