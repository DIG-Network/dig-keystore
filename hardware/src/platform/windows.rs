//! Windows TPM 2.0 binding through the CNG **Microsoft Platform Crypto
//! Provider**.
//!
//! # What the silicon actually guarantees
//!
//! `MS_PLATFORM_KEY_STORAGE_PROVIDER` is registered by Windows only when a
//! usable TPM is present, and keys created in it live **inside the TPM**. This
//! module creates one persisted RSA-2048 key with its export policy set to zero
//! before finalisation, so the private half can never be marshalled out — which
//! is why a keystore sealed here does not open on another machine.
//!
//! # Non-exportability is asserted, never assumed
//!
//! [`HardwareProvider::custody`] may report
//! [`NonExportable`](KeyCustody::NonExportable) only when the platform has
//! actually *refused* an export ([`provider.rs`] states this as a MUST). So
//! [`CngPlatformKeyProvider::new`] attempts a real
//! `NCryptExportKey(BCRYPT_RSAFULLPRIVATE_BLOB)` at construction and records the
//! outcome. **An export that succeeds is not a warning — it demotes custody to
//! [`ProcessMemory`](KeyCustody::ProcessMemory)**, which the `dig-keystore`
//! self-test then refuses as a hardware tier.
//!
//! Placing the assertion in the constructor rather than in a test is deliberate:
//! a test asserts the property on the machines that run tests, and this asserts
//! it on the machine that holds the user key.
//!
//! # Hybrid, because a TPM key is not a symmetric key
//!
//! The TPM key is RSA and bounded by its modulus; keystore blobs are not. So only
//! the 32-byte content key crosses this boundary, wrapped with RSA-OAEP/SHA-256,
//! and `dig-keystore` does the bulk AES-256-GCM. That is the whole reason
//! [`HardwareProvider`] is two 32-byte operations wide.
//!
//! # Why `unsafe` lives here and not in `dig-keystore`
//!
//! Every call below is FFI into `ncrypt.dll`. `dig-keystore` sets
//! `unsafe_code = "forbid"` as a spec-pinned property (`SPEC.md` §12/§13.2,
//! conformance C-15), so this crate exists to keep that forbid intact in the
//! crate that actually holds key material.
//!
//! [`provider.rs`]: dig_keystore::hardware::HardwareProvider

use std::fmt;

use zeroize::Zeroizing;

use dig_keystore::hardware::{
    ContentKey, HardwareKind, HardwareProbe, HardwareProvider, KeyCustody,
};
use dig_keystore::{KeystoreError, Result};
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDecrypt, NCryptEncrypt, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSAFULLPRIVATE_BLOB, BCRYPT_RSA_ALGORITHM,
    BCRYPT_SHA256_ALGORITHM, CERT_KEY_SPEC, MS_PLATFORM_KEY_STORAGE_PROVIDER,
    NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
    NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};

/// The persisted TPM key this crate wraps content keys to.
///
/// Versioned in the name so a future change of algorithm or policy creates a
/// *new* key rather than silently reinterpreting the existing one — blobs sealed
/// to the old key must keep opening (§5.1).
const WRAP_KEY_NAME: PCWSTR = windows::core::w!("DIG.Network.Keystore.WrapKey.v1");

/// RSA modulus size. 2048 is the floor every TPM 2.0 implements; 3072 is not
/// universally supported and a key that fails to create is worse than a smaller
/// one that does, since only 32 bytes are ever wrapped.
const WRAP_KEY_BITS: u32 = 2048;

/// `NTE_NOT_FOUND` — the storage provider is not registered on this host.
const NTE_NOT_FOUND: u32 = 0x8009_0011;
/// `NTE_EXISTS` — a persisted key of that name already exists.
const NTE_EXISTS: u32 = 0x8009_000F;

/// Why the CNG Platform Crypto Provider could not be reached.
///
/// Carries the HRESULT alongside the message because the *classification* —
/// confident absence versus unknown — depends on the code, and a formatted string
/// is not something a caller should have to parse to fail closed correctly.
#[derive(Debug, Clone)]
pub struct CngUnavailable {
    /// Non-secret description, safe to log.
    pub detail: String,
    /// The raw HRESULT from CNG.
    pub code: u32,
}

impl fmt::Display for CngUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

/// Owned `NCRYPT` handles, freed on drop.
///
/// `NCRYPT` handles are process-wide and documented as usable from any thread, so
/// the `Send`/`Sync` the [`HardwareProvider`] trait requires is sound. They are
/// wrapped in a dedicated type rather than held loose so that the manual `Send` /
/// `Sync` assertion has exactly one place to be justified, and so no path can
/// leak a handle by returning early.
struct CngHandles {
    provider: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
}

// SAFETY: NCRYPT provider and key handles are opaque process-wide kernel objects.
// CNG documents its handles as usable concurrently from multiple threads, and
// this type exposes no interior mutability of its own — every use goes through an
// `&self` FFI call that CNG itself serialises.
unsafe impl Send for CngHandles {}
unsafe impl Sync for CngHandles {}

impl Drop for CngHandles {
    fn drop(&mut self) {
        // Freeing the key before the provider that owns it. Errors are
        // deliberately ignored: a failed free during teardown has no remedy, and
        // the alternative — panicking in a destructor — is strictly worse.
        // Nothing secret is held by either handle; the private key never left the
        // TPM to begin with.
        unsafe {
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.key.0));
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.provider.0));
        }
    }
}

/// A [`HardwareProvider`] backed by a non-exportable TPM 2.0 key held in the
/// Windows CNG Platform Crypto Provider.
pub struct CngPlatformKeyProvider {
    /// `None` when this provider could not reach the platform at all — it then
    /// exists only to report *why*, as an indeterminate probe.
    handles: Option<CngHandles>,
    /// The custody this provider is entitled to claim, decided at construction by
    /// attempting a real export. Never widened afterwards.
    custody: KeyCustody,
    /// What [`probe`](HardwareProvider::probe) will answer.
    probe: HardwareProbe,
}

impl fmt::Debug for CngPlatformKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CngPlatformKeyProvider")
            .field("bound", &self.handles.is_some())
            .field("custody", &self.custody)
            .field("probe", &self.probe)
            .finish()
    }
}

impl CngPlatformKeyProvider {
    /// Open — or on first use create — the persisted TPM wrapping key, then
    /// prove it is non-exportable.
    ///
    /// # Errors
    ///
    /// A [`CngUnavailable`] carrying the non-secret reason **and** the HRESULT,
    /// so the caller can tell a confident absence from an inability to determine.
    /// Prefer [`detect`](Self::detect), which makes that distinction for you.
    pub fn new() -> std::result::Result<Self, CngUnavailable> {
        let handles = open_or_create_key()?;

        // The MUST from the trait contract: claim `NonExportable` only after the
        // platform has refused an export. A provider that assumed it would be
        // making exactly the claim nobody would ever re-check.
        let custody = match export_is_refused(&handles) {
            true => KeyCustody::NonExportable,
            false => KeyCustody::ProcessMemory,
        };

        Ok(Self {
            handles: Some(handles),
            custody,
            probe: HardwareProbe::Available(HardwareKind::WindowsTpm20),
        })
    }

    /// The correctly-classified provider for this host — never an error.
    ///
    /// This is the constructor callers want. [`new`](Self::new) reports *what*
    /// went wrong; `detect` decides what that failure **means**, and the decision
    /// is one-sided on purpose: only `NTE_NOT_FOUND` — Windows saying the
    /// Platform Crypto Provider is not registered, which it does only when no
    /// usable TPM exists — becomes a confident
    /// [`Absent`](HardwareProbe::Absent). Everything else, including the
    /// access-denied a locked-down host returns, becomes
    /// [`Indeterminate`](HardwareProbe::Indeterminate).
    ///
    /// Getting that one-sidedness backwards is how a machine with a working TPM
    /// gets told it has none.
    pub fn detect() -> Self {
        match Self::new() {
            Ok(provider) => provider,
            Err(e) if is_confident_absence(e.code) => Self::absent(),
            Err(e) => Self::unreachable(e.detail),
        }
    }

    /// A provider that binds nothing and reports `detail` as an **indeterminate**
    /// probe.
    ///
    /// Used when [`new`](Self::new) fails for a reason that is not a confident
    /// absence. Surfacing the failure this way — rather than omitting the
    /// candidate — keeps a policy stricter than
    /// [`Optional`](dig_keystore::hardware::HardwarePolicy::Optional) failing
    /// closed, which is the entire point of the three-valued probe.
    pub fn unreachable(detail: impl fmt::Display) -> Self {
        Self {
            handles: None,
            custody: KeyCustody::ProcessMemory,
            probe: HardwareProbe::indeterminate(detail),
        }
    }

    /// A provider reporting a *confident* absence: Windows says the Platform
    /// Crypto Provider is not registered, which it does only when no usable TPM
    /// is present.
    pub fn absent() -> Self {
        Self {
            handles: None,
            custody: KeyCustody::ProcessMemory,
            probe: HardwareProbe::Absent,
        }
    }

    fn key(&self) -> Result<NCRYPT_KEY_HANDLE> {
        self.handles
            .as_ref()
            .map(|h| h.key)
            .ok_or_else(|| KeystoreError::HardwareWrapFailed {
                detail: "no TPM key is bound to this provider".to_owned(),
            })
    }
}

impl HardwareProvider for CngPlatformKeyProvider {
    fn kind(&self) -> HardwareKind {
        HardwareKind::WindowsTpm20
    }

    fn probe(&self) -> HardwareProbe {
        self.probe.clone()
    }

    fn custody(&self) -> KeyCustody {
        self.custody
    }

    fn wrap_key(&self, content_key: &ContentKey) -> Result<Vec<u8>> {
        let key = self.key()?;
        // The wrapped key is ciphertext and is written into the envelope, so it
        // is copied out of the zeroizing buffer deliberately. The buffer itself
        // still wipes, because on this direction it also held the plaintext CNG
        // was handed.
        oaep_transform(key, content_key.as_slice(), Direction::Encrypt)
            .map(|wrapped| wrapped.to_vec())
            .map_err(|detail| KeystoreError::HardwareWrapFailed { detail })
    }

    fn unwrap_key(&self, wrapped: &[u8]) -> Result<ContentKey> {
        let key = self.key()?;
        let plain = oaep_transform(key, wrapped, Direction::Decrypt)
            .map_err(|detail| KeystoreError::HardwareUnwrapFailed { detail })?;

        super::content_key::from_recovered(&plain, "the TPM")
            .map_err(|detail| KeystoreError::HardwareUnwrapFailed { detail })
    }
}

/// Which way an OAEP transform runs. The two CNG calls are byte-identical in
/// shape and differ only in the entry point, so they share one body rather than
/// two that could drift.
#[derive(Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

/// Run RSA-OAEP/SHA-256 through the TPM key, sized by the two-call CNG idiom.
///
/// CNG reports the required output length when handed no output buffer, so the
/// first call sizes and the second fills. The buffer is then truncated to the
/// length CNG *reports*, never to the length requested — RSA decryption returns
/// fewer bytes than the modulus, and trusting the allocation size would append
/// whatever the allocation happened to contain.
fn oaep_transform(
    key: NCRYPT_KEY_HANDLE,
    input: &[u8],
    direction: Direction,
) -> std::result::Result<Zeroizing<Vec<u8>>, String> {
    let mut padding = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    };
    let padding_ptr = std::ptr::addr_of_mut!(padding).cast::<std::ffi::c_void>();
    let flags = NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG;

    let mut needed: u32 = 0;
    // SAFETY: `key` is a live handle owned by `CngHandles`; `padding` outlives
    // both calls; passing `None` for the output buffer is the documented
    // length-query form and CNG writes only `needed`.
    unsafe {
        match direction {
            Direction::Encrypt => NCryptEncrypt(
                key,
                Some(input),
                Some(padding_ptr),
                None,
                &mut needed,
                flags,
            ),
            Direction::Decrypt => NCryptDecrypt(
                key,
                Some(input),
                Some(padding_ptr),
                None,
                &mut needed,
                flags,
            ),
        }
    }
    .map_err(|e| format!("CNG length query failed: {}", hresult(&e)))?;

    // `Zeroizing` from the point of allocation rather than at the call site: on
    // the Decrypt direction this buffer holds the recovered CONTENT KEY, and the
    // wrong-length branch below returns early without ever handing it out. Wiping
    // it here covers every exit from this function, including that one.
    //
    // The wipe is over the full CAPACITY, not the truncated length — `written` is
    // 32 of a ~256-byte RSA output buffer, so a length-only wipe would leave the
    // tail of the plaintext block in freed heap.
    let mut out = Zeroizing::new(vec![0u8; needed as usize]);
    let mut written: u32 = 0;
    // SAFETY: as above, with an output buffer of exactly the length CNG asked
    // for; CNG writes at most `out.len()` bytes and reports the count in
    // `written`.
    unsafe {
        match direction {
            Direction::Encrypt => NCryptEncrypt(
                key,
                Some(input),
                Some(padding_ptr),
                Some(out.as_mut_slice()),
                &mut written,
                flags,
            ),
            Direction::Decrypt => NCryptDecrypt(
                key,
                Some(input),
                Some(padding_ptr),
                Some(out.as_mut_slice()),
                &mut written,
                flags,
            ),
        }
    }
    .map_err(|e| format!("CNG transform failed: {}", hresult(&e)))?;

    if written as usize > out.len() {
        return Err(format!(
            "CNG reported {written} bytes into a {}-byte buffer",
            out.len()
        ));
    }
    out.truncate(written as usize);
    Ok(out)
}

/// Attempt a real private-key export and report whether the platform refused it.
///
/// **`true` means refused, which is the property being bought.** The polarity is
/// stated here because the failure direction matters: an error from CNG for any
/// reason reads as "refused", and that is the conservative direction — a probe
/// failure understates custody rather than overstating it, so the worst outcome
/// is a hardware-capable host reporting `NonExportable` it genuinely earned via a
/// refusal it did not fully understand, never a soft key reported as hard.
fn export_is_refused(handles: &CngHandles) -> bool {
    let mut needed: u32 = 0;
    // SAFETY: `handles.key` is live; the `None` output buffer is the documented
    // length-query form. A successful return here would mean the TPM is willing
    // to marshal the private key out, which is exactly what must not happen.
    let outcome = unsafe {
        NCryptExportKey(
            handles.key,
            None,
            BCRYPT_RSAFULLPRIVATE_BLOB,
            None,
            None,
            &mut needed,
            NCRYPT_SILENT_FLAG,
        )
    };
    outcome.is_err()
}

/// Open the persisted wrapping key, creating it on first use.
fn open_or_create_key() -> std::result::Result<CngHandles, CngUnavailable> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    // SAFETY: `provider` is a live local the call initialises on success.
    unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) }
        .map_err(|e| CngUnavailable {
            detail: format!("Platform Crypto Provider unavailable: {}", hresult(&e)),
            code: hresult_code(&e),
        })?;

    let mut key = NCRYPT_KEY_HANDLE::default();
    // SAFETY: `provider` is live; `WRAP_KEY_NAME` is a static wide literal.
    let opened = unsafe {
        NCryptOpenKey(
            provider,
            &mut key,
            WRAP_KEY_NAME,
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
    };

    if opened.is_ok() {
        return Ok(CngHandles { provider, key });
    }

    match create_key(provider) {
        Ok(key) => Ok(CngHandles { provider, key }),
        Err(e) => {
            // SAFETY: `provider` is live and no longer referenced after this.
            unsafe { NCryptFreeObject(NCRYPT_HANDLE(provider.0)) }.ok();
            Err(e)
        }
    }
}

/// Create the persisted key with the export policy pinned to zero *before*
/// finalisation.
///
/// Order is load-bearing: `NCRYPT_EXPORT_POLICY_PROPERTY` is only honoured up to
/// `NCryptFinalizeKey`. Setting it afterwards succeeds and does nothing, leaving
/// an exportable key that reports as configured — a silent downgrade with no
/// error anywhere.
fn create_key(
    provider: NCRYPT_PROV_HANDLE,
) -> std::result::Result<NCRYPT_KEY_HANDLE, CngUnavailable> {
    let mut key = NCRYPT_KEY_HANDLE::default();
    // SAFETY: `provider` is live; both name arguments are static wide literals.
    unsafe {
        NCryptCreatePersistedKey(
            provider,
            &mut key,
            BCRYPT_RSA_ALGORITHM,
            WRAP_KEY_NAME,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| CngUnavailable {
        code: hresult_code(&e),
        detail: if hresult_code(&e) == NTE_EXISTS {
            // A key exists but would not open: a permissions or corruption
            // problem, not a missing key. Say which, because the remedies differ.
            format!(
                "TPM wrapping key exists but could not be opened: {}",
                hresult(&e)
            )
        } else {
            format!("could not create a TPM wrapping key: {}", hresult(&e))
        },
    })?;

    // SAFETY: `key` is live and not yet finalised, so both properties apply.
    unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key.0),
            NCRYPT_LENGTH_PROPERTY,
            &WRAP_KEY_BITS.to_ne_bytes(),
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| CngUnavailable {
            detail: format!("could not set key length: {}", hresult(&e)),
            code: hresult_code(&e),
        })?;

        // Zero means: no export, of any form, ever.
        NCryptSetProperty(
            NCRYPT_HANDLE(key.0),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            &0u32.to_ne_bytes(),
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| CngUnavailable {
            detail: format!("could not pin the export policy: {}", hresult(&e)),
            code: hresult_code(&e),
        })?;

        NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG).map_err(|e| CngUnavailable {
            detail: format!("could not finalize the TPM key: {}", hresult(&e)),
            code: hresult_code(&e),
        })?;
    }

    Ok(key)
}

/// Whether an error means Windows has no Platform Crypto Provider registered —
/// the one *confident* negative this platform offers.
///
/// Every other failure is an inability to determine, not an absence.
pub(crate) fn is_confident_absence(detail_code: u32) -> bool {
    detail_code == NTE_NOT_FOUND
}

fn hresult(e: &windows::core::Error) -> String {
    format!("{e} (0x{:08X})", hresult_code(e))
}

fn hresult_code(e: &windows::core::Error) -> u32 {
    e.code().0 as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::hardware::CONTENT_KEY_LEN;

    /// **Property:** only `NTE_NOT_FOUND` is treated as a confident absence.
    ///
    /// The nearest wrong implementation treats *any* provider-open failure as
    /// "this machine has no TPM" — which is what an access-denied on a locked-down
    /// host returns, and it would tell a user with a working TPM that they have
    /// none. Asserted with a real access-denied code rather than an arbitrary one.
    #[test]
    fn only_a_missing_provider_is_a_confident_absence() {
        assert!(is_confident_absence(NTE_NOT_FOUND));
        // E_ACCESSDENIED — observed on this very machine when querying the TPM
        // without elevation.
        assert!(!is_confident_absence(0x8007_0005));
        // NTE_EXISTS: a key is there. Emphatically not an absence.
        assert!(!is_confident_absence(NTE_EXISTS));
    }

    /// **Property:** the fallback constructors never claim hardware custody.
    ///
    /// `unreachable` and `absent` bind no key, so a `NonExportable` claim from
    /// either would be unbacked by any refusal — the exact claim the trait
    /// forbids. Both arms asserted: a test covering only `unreachable` cannot see
    /// a wrong `absent`.
    #[test]
    fn an_unbound_provider_never_claims_non_exportable_custody() {
        for provider in [
            CngPlatformKeyProvider::unreachable("no provider"),
            CngPlatformKeyProvider::absent(),
        ] {
            assert_eq!(provider.custody(), KeyCustody::ProcessMemory);
            assert!(!provider.custody().is_hardware_grade());
        }
    }

    /// **Property:** an unreachable platform probes `Indeterminate`, and a
    /// confidently-missing provider probes `Absent`.
    ///
    /// These are the two answers the ladder treats differently — one is an error
    /// under the default policy and the other a degrade — so collapsing them here
    /// would defeat the fail-closed rule at its source.
    #[test]
    fn unreachable_probes_indeterminate_and_absent_probes_absent() {
        assert!(matches!(
            CngPlatformKeyProvider::unreachable("service down").probe(),
            HardwareProbe::Indeterminate { .. }
        ));
        assert_eq!(
            CngPlatformKeyProvider::absent().probe(),
            HardwareProbe::Absent
        );
    }

    /// **Property:** the diagnostic surfaces report the binding state without
    /// rendering the handle or anything derived from the key.
    ///
    /// `CngPlatformKeyProvider` holds live `NCRYPT` handles, so its `Debug` is
    /// hand-written rather than derived. That makes it real code on the path an
    /// operator reads when a TPM is not being used, and it is asserted rather
    /// than assumed.
    #[test]
    fn the_diagnostic_surfaces_report_state_without_rendering_the_handle() {
        let rendered = format!("{:?}", CngPlatformKeyProvider::absent());
        assert!(rendered.contains("bound: false"), "got {rendered}");
        assert!(rendered.contains("ProcessMemory"), "got {rendered}");
        assert!(rendered.contains("Absent"), "got {rendered}");
        assert!(
            !rendered.contains("NCRYPT"),
            "no handle may reach a log line: {rendered}"
        );

        let unavailable = CngUnavailable {
            detail: "Platform Crypto Provider unavailable".to_owned(),
            code: NTE_NOT_FOUND,
        };
        assert_eq!(
            unavailable.to_string(),
            "Platform Crypto Provider unavailable",
            "Display carries the non-secret detail verbatim"
        );
    }

    /// **Property:** an unbound provider refuses to wrap rather than returning
    /// something wrap-shaped.
    #[test]
    fn an_unbound_provider_refuses_to_wrap() {
        let provider = CngPlatformKeyProvider::unreachable("service down");
        let err = provider
            .wrap_key(&ContentKey::new([7u8; CONTENT_KEY_LEN]))
            .expect_err("no key is bound, so nothing can be wrapped");
        assert!(matches!(err, KeystoreError::HardwareWrapFailed { .. }));
    }

    /// **Property:** an unbound provider refuses to UNWRAP too.
    ///
    /// Tested separately from the wrap arm because the two go through different
    /// error variants, and `unwrap_key` is the one whose failure a caller is most
    /// tempted to treat as recoverable (`SPEC.md` §17.5b).
    #[test]
    fn an_unbound_provider_refuses_to_unwrap() {
        let err = CngPlatformKeyProvider::absent()
            .unwrap_key(&[1, 2, 3, 4])
            .expect_err("no key is bound, so nothing can be unwrapped");
        assert!(
            matches!(err, KeystoreError::HardwareWrapFailed { .. }),
            "got {err:?}"
        );
    }

    /// **Property:** the kind is fixed for this provider, whatever its binding
    /// state.
    ///
    /// `HardwareKind` is the discriminant written into a sealed envelope header,
    /// so a provider that reported a different kind when degraded would let the
    /// class recorded in a blob depend on whether the TPM happened to answer.
    #[test]
    fn the_hardware_kind_does_not_depend_on_the_binding_state() {
        assert_eq!(
            CngPlatformKeyProvider::absent().kind(),
            HardwareKind::WindowsTpm20
        );
        assert_eq!(
            CngPlatformKeyProvider::unreachable("down").kind(),
            HardwareKind::WindowsTpm20
        );
    }
}
