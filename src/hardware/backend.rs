//! [`HardwareBoundBackend`] — a [`KeychainBackend`] decorator that binds stored
//! blobs to the host's hardware trusted component.
//!
//! # A tier above, not a replacement
//!
//! This wraps any existing backend (file, OS credential store, memory). What it
//! stores is the *already sealed* keystore blob inside a hardware-wrapped
//! envelope, so the AES-256-GCM + Argon2id passphrase envelope stays the floor
//! on every path — a degraded host writes the same bytes it always wrote, never
//! a bare secret.
//!
//! # The tier is decided once, by use
//!
//! [`HardwareBoundBackend::new`] probes the provider **and then self-tests it**
//! (wrap a random key, unwrap it, require the round-trip) before it will report
//! [`ProtectionTier::Hardware`]. A probe is a claim; the self-test is what makes
//! the claim refutable. Resolving at construction also means "is this keystore
//! hardware-bound?" is a settled fact rather than a failure that surfaces
//! mid-`unlock`.

use std::sync::Arc;

use super::envelope::{self, Envelope};
use super::provider::{ContentKey, HardwareProvider};
use super::tier::{DegradeReason, HardwareKind, HardwarePolicy, HardwareProbe, ProtectionTier};
use crate::backend::{BackendKey, Exclusivity, KeychainBackend};
use crate::error::{KeystoreError, Result};

/// A [`KeychainBackend`] that hardware-binds every blob it stores, degrading to
/// the underlying software envelope when the host has no usable hardware.
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use dig_keystore::backend::{BackendKey, FileBackend, KeychainBackend};
/// use dig_keystore::hardware::{HardwareBoundBackend, HardwarePolicy};
///
/// let inner = FileBackend::new("/var/lib/dig/keys");
/// // No provider available in this build: opens, and says so honestly.
/// let backend = HardwareBoundBackend::new(inner, None, HardwarePolicy::Optional)?;
///
/// // What the HOST can do — the tier a new write would get.
/// println!("host: {}", backend.tier());
///
/// // What protects THIS key — the only answer fit to show a user, because a
/// // capable host can still hold a keystore that was never wrapped.
/// let key = BackendKey::new("identity");
/// let tier = backend.blob_tier(&key)?;
/// if tier.is_hardware_bound() {
///     println!("this key is {tier}");
/// } else {
///     // Never claim protection this key does not have.
///     println!("this key is {tier}");
/// }
/// # Ok::<(), dig_keystore::KeystoreError>(())
/// ```
pub struct HardwareBoundBackend {
    /// The storage this decorates.
    inner: Arc<dyn KeychainBackend>,
    /// The self-tested provider — present only when [`tier`](Self::tier) is
    /// [`ProtectionTier::Hardware`], so the two can never disagree.
    provider: Option<Arc<dyn HardwareProvider>>,
    /// The truthful, settled protection tier.
    tier: ProtectionTier,
}

impl HardwareBoundBackend {
    /// Decorate `inner`, resolving the protection tier once.
    ///
    /// Pass `provider = None` to store through `inner` unchanged while reporting
    /// [`DegradeReason::NotRequested`].
    ///
    /// # Errors
    ///
    /// Fails closed rather than silently degrading, per `policy`:
    /// - [`HardwarePolicy::Required`] — any outcome short of self-tested hardware
    ///   is [`KeystoreError::HardwareRequired`].
    /// - [`HardwarePolicy::Preferred`] (default) — a *confident* absence degrades,
    ///   but an [`Indeterminate`](HardwareProbe::Indeterminate) probe is
    ///   [`KeystoreError::HardwareProbeIndeterminate`]: "I could not determine
    ///   whether this host has hardware" must not be downgraded into "it has
    ///   none", which would quietly strip protection from a machine that has it.
    /// - [`HardwarePolicy::Optional`] — always opens, always reports the reason.
    pub fn new<B: KeychainBackend>(
        inner: B,
        provider: Option<Arc<dyn HardwareProvider>>,
        policy: HardwarePolicy,
    ) -> Result<Self> {
        Self::with_inner(Arc::new(inner), provider, policy)
    }

    /// As [`new`](Self::new), for an already shared backend.
    pub fn with_inner(
        inner: Arc<dyn KeychainBackend>,
        provider: Option<Arc<dyn HardwareProvider>>,
        policy: HardwarePolicy,
    ) -> Result<Self> {
        let tier = resolve_tier(provider.as_deref(), policy)?;
        // Hold the provider only where the tier actually claims hardware, so a
        // degraded backend cannot accidentally reach for it later.
        let provider = if tier.is_hardware_bound() {
            provider
        } else {
            None
        };
        Ok(Self {
            inner,
            provider,
            tier,
        })
    }

    /// What this **host** is bound to — the tier every *newly written* blob gets.
    ///
    /// This is a statement about the machine, not about any particular stored
    /// key. On a hardware-capable host it reports `Hardware` even if a given
    /// keystore predates hardware binding and is still a bare §3 blob, because a
    /// capable host does not retroactively protect bytes already at rest.
    ///
    /// **Before telling a user that a specific key is hardware-protected, ask
    /// [`blob_tier`](Self::blob_tier) instead.** Rendering "protected by your
    /// TPM" from this method would claim copy-resistance that an unwrapped
    /// legacy blob does not have.
    pub fn tier(&self) -> &ProtectionTier {
        &self.tier
    }

    /// What protects **the key material stored at `key`**, read from the blob
    /// itself.
    ///
    /// This is the question a UI actually has, and it is not the same as
    /// [`tier`](Self::tier): a hardware-capable host can hold a keystore written
    /// before hardware binding existed, which is protected by the passphrase
    /// envelope alone and *does* open on another machine. Answering from the
    /// stored bytes is what keeps that distinction honest.
    ///
    /// The tier reported is the blob's own, independent of this host: a blob
    /// sealed by an Apple Secure Enclave reads as `Hardware(MacSecureEnclave)`
    /// even on Windows. Whether *this* host can open it is a separate question,
    /// answered by [`read`](KeychainBackend::read).
    ///
    /// # Errors
    ///
    /// - The inner backend's error if `key` cannot be read (e.g. `NotFound`).
    /// - [`KeystoreError::MalformedEnvelope`] if the blob claims to be an
    ///   envelope but is structurally invalid.
    /// - [`KeystoreError::UnknownHardwareClass`] if it was sealed by hardware
    ///   this build cannot name.
    ///
    /// Both error cases **fail closed**: a wrapped blob is never reported as
    /// software-protected just because this build cannot fully classify it.
    /// Guessing in either direction is what this method exists to avoid.
    pub fn blob_tier(&self, key: &BackendKey) -> Result<ProtectionTier> {
        let bytes = self.inner.read(key)?;

        // Not an envelope — the passphrase envelope is all that protects it,
        // whatever this host is capable of.
        if !envelope::is_envelope(&bytes) {
            return Ok(ProtectionTier::Software(DegradeReason::BlobNotWrapped));
        }

        let env = envelope::decode(&bytes)?;
        match env.hardware_kind() {
            Some(kind) => Ok(ProtectionTier::Hardware(kind)),
            None => Err(KeystoreError::UnknownHardwareClass {
                wire_id: env.hardware_wire_id,
            }),
        }
    }

    /// The underlying storage, for callers that need it directly.
    pub fn inner(&self) -> &Arc<dyn KeychainBackend> {
        &self.inner
    }

    /// Return the key at `key` to the portable software form, so it opens on a
    /// host that no longer has this hardware. Returns the tier the blob is in
    /// afterwards.
    ///
    /// # Why this exists
    ///
    /// Hardware binding makes the trusted component a **second required
    /// factor**. A TPM is cleared by a firmware update, a mainboard swap or a
    /// BIOS reset — routine events — and after one the correct passphrase is no
    /// longer enough: the sealed blob is unopenable, by design and permanently.
    /// `unbind` is the way back, and it **must be taken while the hardware still
    /// answers**. There is no recovery afterwards; that is what non-exportable
    /// custody means.
    ///
    /// Unbinding does not expose a secret. What it stores is the AES-256-GCM +
    /// Argon2id passphrase envelope that was always the floor (`SPEC.md` §3) —
    /// the same bytes a host with no hardware writes. It gives up cross-machine
    /// binding, nothing else.
    ///
    /// Nothing is written until the plaintext is in hand, and the result is
    /// verified from storage before this reports success: telling a user their
    /// seed is portable when it is not is the one failure here with a
    /// catastrophic follow-on action, since they may then clear the TPM.
    ///
    /// # Errors
    ///
    /// - [`KeystoreError::NotHardwareBound`] — the blob is wrapped but this
    ///   backend has no provider to open it (the hardware is already gone).
    /// - [`KeystoreError::HardwareUnwrapFailed`] — the hardware would not open
    ///   it. The stored bytes are left exactly as they were.
    /// - [`KeystoreError::HardwareStillBound`] — the write did not take.
    pub fn unbind(&self, key: &BackendKey) -> Result<ProtectionTier> {
        let bytes = self.inner.read(key)?;
        if !envelope::is_envelope(&bytes) {
            return Ok(ProtectionTier::Software(DegradeReason::BlobNotWrapped));
        }

        let provider = self
            .provider
            .as_deref()
            .ok_or_else(|| KeystoreError::NotHardwareBound {
                tier: self.tier.to_string(),
            })?;

        // Unwrap BEFORE writing anything: a failure here must leave the envelope
        // untouched, so hardware that comes back (a swapped-back board, a
        // re-enrolled key) still finds the blob it sealed.
        let plain = self.unwrap_blob(provider, &bytes)?;

        // Write through `inner`, NOT through `self.write` — which, in the
        // hardware tier, would seal these bytes straight back into a new
        // envelope and report a successful unbind that changed nothing.
        self.inner.write(key, &plain)?;

        // Confirm from storage. A store that accepts a write and keeps the old
        // bytes (a full disk, a read-only mount) would otherwise leave the user
        // believing it is safe to retire the trusted component.
        if envelope::is_envelope(&self.inner.read(key)?) {
            return Err(KeystoreError::HardwareStillBound { key: key.0.clone() });
        }
        Ok(ProtectionTier::Software(DegradeReason::BlobNotWrapped))
    }

    /// Bind the key at `key` to this host's hardware, migrating a blob written
    /// before hardware binding existed. Returns the tier the blob is in
    /// afterwards.
    ///
    /// Already-bound blobs are left alone: sealing an envelope inside a second
    /// envelope would produce a blob whose unwrap yields another envelope, which
    /// nothing can open.
    ///
    /// **This is the operation that can strand a seed**, because it overwrites
    /// the only copy with bytes only this hardware can open. So the new blob is
    /// read back from storage and reopened through the hardware BEFORE the call
    /// reports success, and the previous bytes are restored if it cannot be. See
    /// [`unbind`](Self::unbind) for the way back out.
    ///
    /// # Errors
    ///
    /// - [`KeystoreError::NotHardwareBound`] — this backend resolved a software
    ///   tier, so there is no hardware to bind to.
    /// - [`KeystoreError::HardwareWrapFailed`] / [`KeystoreError::HardwareUnwrapFailed`]
    ///   — the seal could not be made, or could not be proven reopenable. The
    ///   previous bytes are restored in both cases.
    pub fn bind(&self, key: &BackendKey) -> Result<ProtectionTier> {
        let bytes = self.inner.read(key)?;
        let provider = self
            .provider
            .as_deref()
            .ok_or_else(|| KeystoreError::NotHardwareBound {
                tier: self.tier.to_string(),
            })?;

        if envelope::is_envelope(&bytes) {
            return Ok(ProtectionTier::Hardware(provider.kind()));
        }

        let sealed = self.wrap_blob(provider, &bytes)?;
        self.inner.write(key, &sealed)?;

        // Prove the migration from STORAGE, not from the value just computed: a
        // seal this hardware cannot reopen has destroyed the only copy, and a
        // success returned over that is the worst outcome this module has.
        match self.reopens_to(provider, key, &bytes) {
            Ok(()) => Ok(ProtectionTier::Hardware(provider.kind())),
            Err(e) => {
                // Put the openable bytes back. The restore is best-effort, but
                // its failure must not mask the reason the bind was rejected.
                let _ = self.inner.write(key, &bytes);
                Err(e)
            }
        }
    }

    /// Whether the blob now stored at `key` unwraps, through the hardware, to
    /// exactly `expected`.
    fn reopens_to(
        &self,
        provider: &dyn HardwareProvider,
        key: &BackendKey,
        expected: &[u8],
    ) -> Result<()> {
        let stored = self.inner.read(key)?;
        let reopened = self.unwrap_blob(provider, &stored)?;
        if reopened != expected {
            return Err(KeystoreError::HardwareUnwrapFailed {
                detail: "the newly sealed blob did not reopen to the original bytes".to_owned(),
            });
        }
        Ok(())
    }

    /// Seal `blob` into a hardware envelope. Only reachable in the hardware tier.
    fn wrap_blob(&self, provider: &dyn HardwareProvider, blob: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand_core::OsRng;
        let content_key = envelope::random_content_key(&mut rng);
        let nonce = envelope::random_nonce(&mut rng);
        let wrapped_key = provider.wrap_key(&content_key)?;
        envelope::encode(provider.kind(), &content_key, &wrapped_key, &nonce, blob)
    }

    /// Open a hardware envelope, requiring the hardware that sealed it.
    fn unwrap_blob(&self, provider: &dyn HardwareProvider, bytes: &[u8]) -> Result<Vec<u8>> {
        let env = envelope::decode(bytes)?;
        require_matching_hardware(&env, provider.kind())?;
        let content_key: ContentKey = provider.unwrap_key(&env.wrapped_key)?;
        Ok(env.open(&content_key)?.to_vec())
    }
}

/// Reject an envelope sealed by hardware other than ours before spending a
/// hardware round-trip on it.
///
/// Covers the unrecognised-wire-id case as well as a known-but-different class:
/// both mean "not openable by this host's component", which is a different fact
/// from a corrupt file.
fn require_matching_hardware(env: &Envelope, ours: HardwareKind) -> Result<()> {
    match env.hardware_kind() {
        Some(kind) if kind == ours => Ok(()),
        Some(kind) => Err(KeystoreError::HardwareKindMismatch {
            expected: ours.label(),
            found: kind.label(),
        }),
        // Not a hardware refusal and not corruption — a class this build cannot
        // name. Reported as such so `HardwareUnwrapFailed` keeps meaning exactly
        // "the hardware refused".
        None => Err(KeystoreError::UnknownHardwareClass {
            wire_id: env.hardware_wire_id,
        }),
    }
}

/// Decide the protection tier from a provider's probe, its custody claim, and a
/// live self-test — then apply `policy` to any negative outcome.
fn resolve_tier(
    provider: Option<&dyn HardwareProvider>,
    policy: HardwarePolicy,
) -> Result<ProtectionTier> {
    let Some(provider) = provider else {
        return degrade(DegradeReason::NotRequested, policy);
    };

    match provider.probe() {
        HardwareProbe::Absent => degrade(DegradeReason::NoHardwarePresent, policy),

        // "Could not determine" is its own outcome, and the only one that is an
        // error under the default policy.
        HardwareProbe::Indeterminate { detail } => {
            if policy.allows_indeterminate_degrade() {
                degrade(DegradeReason::ProbeIndeterminate { detail }, policy)
            } else {
                Err(KeystoreError::HardwareProbeIndeterminate { detail })
            }
        }

        HardwareProbe::Available(kind) => match verify_hardware(provider, kind) {
            Ok(()) => Ok(ProtectionTier::Hardware(kind)),
            Err(detail) => degrade(DegradeReason::HardwareUnusable { detail }, policy),
        },
    }
}

/// Refute or confirm a provider's "hardware is available" claim.
///
/// Three ways the claim fails, all of which must land on
/// [`DegradeReason::HardwareUnusable`] rather than a hardware tier:
/// a provider that disagrees with itself about which component it binds to; a
/// wrapping key that is not actually non-exportable (which buys none of the
/// cross-machine binding the tier promises); and a wrap/unwrap round-trip that
/// does not reproduce the key.
fn verify_hardware(
    provider: &dyn HardwareProvider,
    probed: HardwareKind,
) -> std::result::Result<(), String> {
    if provider.kind() != probed {
        return Err(format!(
            "provider binds {} but probed {}",
            provider.kind().label(),
            probed.label()
        ));
    }

    if !provider.custody().is_hardware_grade() {
        return Err(format!(
            "wrapping key custody is {:?}, not NonExportable",
            provider.custody()
        ));
    }

    let mut rng = rand_core::OsRng;
    let probe_key = envelope::random_content_key(&mut rng);
    let wrapped = provider
        .wrap_key(&probe_key)
        .map_err(|e| format!("self-test wrap failed: {e}"))?;
    if wrapped.is_empty() {
        return Err("self-test wrap produced no wrapped key".to_owned());
    }
    if wrapped.as_slice() == probe_key.as_slice() {
        return Err("self-test wrap returned the content key verbatim".to_owned());
    }
    let recovered = provider
        .unwrap_key(&wrapped)
        .map_err(|e| format!("self-test unwrap failed: {e}"))?;
    if recovered.as_slice() != probe_key.as_slice() {
        return Err("self-test round-trip did not reproduce the key".to_owned());
    }
    Ok(())
}

/// Apply `policy` to a negative outcome: degrade with the reason, or fail closed.
fn degrade(reason: DegradeReason, policy: HardwarePolicy) -> Result<ProtectionTier> {
    if policy.allows_degrade() {
        Ok(ProtectionTier::Software(reason))
    } else {
        Err(KeystoreError::HardwareRequired { reason })
    }
}

impl std::fmt::Debug for HardwareBoundBackend {
    /// Redacted: reports the tier (which is not sensitive and is the point of
    /// the type) but never the inner store or any key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareBoundBackend")
            .field("tier", &self.tier)
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl KeychainBackend for HardwareBoundBackend {
    /// Read a blob, unwrapping it when it carries a hardware envelope.
    ///
    /// A blob **without** the envelope prefix is returned untouched, which is
    /// what lets every keystore written before this feature — and any future
    /// inner format — keep opening (§5.1).
    ///
    /// A blob **with** an envelope that this host cannot open is an error, never
    /// the raw envelope bytes: an envelope copied to a machine without the
    /// sealing hardware must fail loudly rather than hand back ciphertext that a
    /// caller would then try to parse as a keystore.
    fn read(&self, key: &BackendKey) -> Result<Vec<u8>> {
        let bytes = self.inner.read(key)?;
        if !envelope::is_envelope(&bytes) {
            return Ok(bytes);
        }
        match self.provider.as_deref() {
            Some(provider) => self.unwrap_blob(provider, &bytes),
            None => Err(KeystoreError::NotHardwareBound {
                tier: self.tier.to_string(),
            }),
        }
    }

    /// Write a blob, sealing it into a hardware envelope in the hardware tier
    /// and passing the software-sealed bytes straight through otherwise.
    fn write(&self, key: &BackendKey, data: &[u8]) -> Result<()> {
        match self.provider.as_deref() {
            Some(provider) => {
                let sealed = self.wrap_blob(provider, data)?;
                self.inner.write(key, &sealed)
            }
            None => self.inner.write(key, data),
        }
    }

    /// Establish a blob, sealing it into a hardware envelope first when a
    /// provider is in use — the same transformation [`write`](Self::write)
    /// applies, so a record established here and one written there are the same
    /// shape.
    ///
    /// Exclusivity is entirely the inner backend's, and so is the reported
    /// claim: wrapping changes the bytes, never who wins a race for the name.
    fn write_new(&self, key: &BackendKey, data: &[u8]) -> Result<()> {
        match self.provider.as_deref() {
            Some(provider) => {
                let sealed = self.wrap_blob(provider, data)?;
                self.inner.write_new(key, &sealed)
            }
            None => self.inner.write_new(key, data),
        }
    }

    fn write_new_exclusivity(&self) -> Exclusivity {
        self.inner.write_new_exclusivity()
    }

    fn delete(&self, key: &BackendKey) -> Result<()> {
        self.inner.delete(key)
    }

    fn list(&self, prefix: &str) -> Result<Vec<BackendKey>> {
        self.inner.list(prefix)
    }

    fn exists(&self, key: &BackendKey) -> Result<bool> {
        self.inner.exists(key)
    }
}
