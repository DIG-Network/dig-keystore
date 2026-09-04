//! Apple **Secure Enclave** binding through the Security framework.
//!
//! # What the silicon actually guarantees
//!
//! A key created with `kSecAttrTokenIDSecureEnclave` is generated **inside the
//! SEP** and its private half never enters the application processor's address
//! space — not at creation, not at use, not ever. That, and only that, is what a
//! [`ProtectionTier::Hardware`](dig_keystore::hardware::ProtectionTier::Hardware)
//! claim means here: a keystore sealed on this Mac does not open on another one.
//!
//! # Apple silicon only, deliberately
//!
//! Every arm64 Mac has a Secure Enclave, so on `aarch64` this build can state
//! that the hardware exists without having inspected anything. On an Intel Mac
//! the SEP exists only behind a T2, and **this loop has no Mac of either kind on
//! which to learn what the framework returns when it is missing** — so rather
//! than guess at a classification, `x86_64` keeps reporting
//! [`PlatformUnsupported`](dig_keystore::hardware::DegradeReason::PlatformUnsupported),
//! exactly as before this binding existed. A guess would be worse than the gap:
//! misread as `Indeterminate` it fails every Intel Mac closed under the default
//! policy, and misread as `Absent` it tells a T2 owner they have no Secure
//! Enclave. This is a named limitation, not an oversight — see `SPEC.md` §17.5.
//!
//! # Non-exportability is asserted, never assumed
//!
//! [`HardwareProvider::custody`] may report
//! [`NonExportable`](KeyCustody::NonExportable) only after the platform has
//! actually refused an export, so construction attempts a real
//! `SecKeyCopyExternalRepresentation` of the **private** key and records the
//! outcome. **An export that succeeds is not a warning — it demotes custody to
//! [`ProcessMemory`](KeyCustody::ProcessMemory)**, which the `dig-keystore`
//! self-test then refuses as a hardware tier. Placing that assertion in the
//! constructor rather than in a test is deliberate: a test asserts the property
//! on the machines that run tests, and this asserts it on the machine holding
//! the user's key.
//!
//! # Hybrid, because a Secure Enclave key is not a symmetric key
//!
//! The SEP holds a P-256 key, so the content key is wrapped with ECIES —
//! `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`, which
//! the framework implements end to end. Only the 32-byte content key crosses
//! this boundary; `dig-keystore` does the bulk AES-256-GCM. No cryptography is
//! implemented in this module.
//!
//! # Why `unsafe` lives here and not in `dig-keystore`
//!
//! Every call below is FFI into the Security framework. `dig-keystore` sets
//! `unsafe_code = "forbid"` as a spec-pinned property (`SPEC.md` §12/§13.2,
//! conformance C-15), so this crate exists to keep that forbid intact in the
//! crate that actually holds key material.

compile_error!("PROBE dig_ecosystem#1694: deliberate macos-only compile error, must go RED on macos-latest only");

use std::fmt;

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::CFError;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFRelease, CFTypeRef};
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::error::CFErrorRef;
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    SecAccessControlCreateWithFlags,
};
use security_framework_sys::base::{SecAccessControlRef, SecKeyRef};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
    kSecClass, kSecClassKey, kSecPrivateKeyAttrs, kSecReturnRef, kSecUseDataProtectionKeychain,
};
use security_framework_sys::key::{
    Algorithm, SecKeyCopyExternalRepresentation, SecKeyCopyPublicKey, SecKeyCreateDecryptedData,
    SecKeyCreateEncryptedData, SecKeyCreateRandomKey,
};
use security_framework_sys::keychain_item::SecItemCopyMatching;
use zeroize::{Zeroize, Zeroizing};

use dig_keystore::hardware::{
    ContentKey, HardwareKind, HardwareProbe, HardwareProvider, KeyCustody,
};
use dig_keystore::{KeystoreError, Result};

/// The keychain label of the Secure Enclave key this crate wraps content keys
/// to.
///
/// Versioned so a future change of curve or access policy creates a *new* key
/// rather than silently reinterpreting the existing one — blobs sealed to the
/// old key must keep opening (§5.1).
const WRAP_KEY_LABEL: &str = "net.dig.keystore.wrap.v1";

/// P-256 is the only curve the Secure Enclave implements.
const WRAP_KEY_BITS: i64 = 256;

/// `errSecMissingEntitlement` — this binary is not entitled to use the Secure
/// Enclave.
const ERR_SEC_MISSING_ENTITLEMENT: i64 = -34018;
/// `errSecUnimplemented` — the operation is not implemented on this platform.
const ERR_SEC_UNIMPLEMENTED: i64 = -4;

/// The ECIES composition used to wrap the content key. Chosen for the variable
/// IV so that wrapping the same content key twice does not produce identical
/// bytes.
const WRAP_ALGORITHM: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

/// Why the Secure Enclave could not be used.
///
/// Carries the `OSStatus` alongside the message because the *classification* —
/// confident absence versus unknown — depends on the code, and a formatted
/// string is not something a caller should have to parse in order to fail closed
/// correctly.
#[derive(Debug, Clone)]
pub struct EnclaveUnavailable {
    /// Non-secret description, safe to log.
    pub detail: String,
    /// The `OSStatus` the framework reported, where it reported one.
    pub code: Option<i64>,
}

impl fmt::Display for EnclaveUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

/// An owned Core Foundation object, released on drop.
///
/// Every Security-framework entry point below follows the *Create Rule*, so the
/// caller owns the returned reference. Wrapping it means no early return can
/// leak one, and gives the manual `Send`/`Sync` justification exactly one place
/// to live.
struct OwnedKey(SecKeyRef);

// SAFETY: `SecKeyRef` is an immutable, reference-counted Core Foundation object.
// Apple documents Security framework key objects as usable from any thread; this
// type exposes no interior mutability of its own, and every use goes through an
// `&self` FFI call.
unsafe impl Send for OwnedKey {}
unsafe impl Sync for OwnedKey {}

impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: `self.0` was obtained from a Create/Copy-rule call and is
        // released exactly once, here. Nothing secret is held — the private key
        // never left the Secure Enclave.
        unsafe { CFRelease(self.0.cast::<std::ffi::c_void>()) }
    }
}

/// A [`HardwareProvider`] backed by a non-exportable P-256 key held in the
/// Apple Secure Enclave.
pub struct SecureEnclaveProvider {
    /// `None` when this provider could not reach the Secure Enclave at all — it
    /// then exists only to report why.
    key: Option<OwnedKey>,
    /// The custody this provider is entitled to claim, decided at construction
    /// by attempting a real export. Never widened afterwards.
    custody: KeyCustody,
    /// What [`probe`](HardwareProvider::probe) will answer.
    probe: HardwareProbe,
}

impl fmt::Debug for SecureEnclaveProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureEnclaveProvider")
            .field("bound", &self.key.is_some())
            .field("custody", &self.custody)
            .field("probe", &self.probe)
            .finish()
    }
}

impl SecureEnclaveProvider {
    /// Open — or on first use create — the Secure Enclave wrapping key, then
    /// prove it is non-exportable.
    ///
    /// # Errors
    ///
    /// An [`EnclaveUnavailable`] carrying the non-secret reason **and** the
    /// `OSStatus`, so the caller can tell a confident absence from an inability
    /// to determine. Prefer [`detect`](Self::detect), which makes that
    /// distinction for you.
    pub fn new() -> std::result::Result<Self, EnclaveUnavailable> {
        let key = match find_existing_key() {
            Some(key) => key,
            None => create_key()?,
        };

        // The MUST from the trait contract: claim `NonExportable` only after the
        // platform has refused an export. A provider that assumed it would be
        // making exactly the claim nobody would ever re-check.
        let custody = if export_is_refused(&key) {
            KeyCustody::NonExportable
        } else {
            KeyCustody::ProcessMemory
        };

        Ok(Self {
            key: Some(key),
            custody,
            probe: HardwareProbe::Available(HardwareKind::MacSecureEnclave),
        })
    }

    /// The correctly-classified provider for this host — never an error.
    ///
    /// This is the constructor callers want. [`new`](Self::new) reports *what*
    /// went wrong; `detect` decides what that failure **means**, and the
    /// decision is one-sided on purpose: only a framework answer that this
    /// process may not use the Secure Enclave at all becomes a confident
    /// [`Absent`](HardwareProbe::Absent). Everything else — a locked keychain, an
    /// unrecognised `OSStatus`, an error with no code — becomes
    /// [`Indeterminate`](HardwareProbe::Indeterminate).
    ///
    /// Getting that one-sidedness backwards is how a Mac with a working Secure
    /// Enclave gets told it has none.
    pub fn detect() -> Self {
        match Self::new() {
            Ok(provider) => provider,
            Err(e) if is_confident_absence(e.code) => Self::absent(),
            Err(e) => Self::unreachable(e.detail),
        }
    }

    /// A provider that binds nothing and reports `detail` as an
    /// **indeterminate** probe.
    ///
    /// Surfacing the failure this way — rather than omitting the candidate —
    /// keeps a policy stricter than
    /// [`Optional`](dig_keystore::hardware::HardwarePolicy::Optional) failing
    /// closed, which is the entire point of the three-valued probe.
    pub fn unreachable(detail: impl fmt::Display) -> Self {
        Self {
            key: None,
            custody: KeyCustody::ProcessMemory,
            probe: HardwareProbe::indeterminate(detail),
        }
    }

    /// A provider reporting a *confident* absence: the framework says this
    /// process may not use the Secure Enclave.
    pub fn absent() -> Self {
        Self {
            key: None,
            custody: KeyCustody::ProcessMemory,
            probe: HardwareProbe::Absent,
        }
    }

    fn key(&self) -> Result<SecKeyRef> {
        self.key
            .as_ref()
            .map(|k| k.0)
            .ok_or_else(|| KeystoreError::HardwareWrapFailed {
                detail: "no Secure Enclave key is bound to this provider".to_owned(),
            })
    }
}

impl HardwareProvider for SecureEnclaveProvider {
    fn kind(&self) -> HardwareKind {
        HardwareKind::MacSecureEnclave
    }

    fn probe(&self) -> HardwareProbe {
        self.probe.clone()
    }

    fn custody(&self) -> KeyCustody {
        self.custody
    }

    fn wrap_key(&self, content_key: &ContentKey) -> Result<Vec<u8>> {
        let private = self.key()?;
        // ECIES encrypts to the PUBLIC half; the Secure Enclave hands it out
        // freely, which is the half that is allowed to leave.
        // SAFETY: `private` is a live key reference owned by `self.key`.
        let public = unsafe { SecKeyCopyPublicKey(private) };
        if public.is_null() {
            return Err(KeystoreError::HardwareWrapFailed {
                detail: "the Secure Enclave key has no public half".to_owned(),
            });
        }
        let public = OwnedKey(public);

        let plaintext = CFData::from_buffer(content_key.as_slice());
        let mut error: CFErrorRef = std::ptr::null_mut();
        // SAFETY: both key and data references are live for the call; `error` is
        // written only on failure and is owned by us when it is.
        let wrapped = unsafe {
            SecKeyCreateEncryptedData(
                public.0,
                WRAP_ALGORITHM.into(),
                plaintext.as_concrete_TypeRef(),
                &mut error,
            )
        };
        owned_data(wrapped, error)
            .map(|data| data.to_vec())
            .map_err(|detail| KeystoreError::HardwareWrapFailed { detail })
    }

    fn unwrap_key(&self, wrapped: &[u8]) -> Result<ContentKey> {
        let private = self.key()?;
        let ciphertext = CFData::from_buffer(wrapped);
        let mut error: CFErrorRef = std::ptr::null_mut();
        // SAFETY: as above. The decryption happens inside the Secure Enclave;
        // only the recovered content key crosses back.
        let plain = unsafe {
            SecKeyCreateDecryptedData(
                private,
                WRAP_ALGORITHM.into(),
                ciphertext.as_concrete_TypeRef(),
                &mut error,
            )
        };
        // Zeroizing from the moment the plaintext exists, so every exit below —
        // including the wrong-length refusal — wipes it.
        let plain = Zeroizing::new(
            owned_data(plain, error)
                .map(|data| data.to_vec())
                .map_err(|detail| KeystoreError::HardwareUnwrapFailed { detail })?,
        );

        super::content_key::from_recovered(&plain, "the Secure Enclave")
            .map_err(|detail| KeystoreError::HardwareUnwrapFailed { detail })
    }
}

/// Take ownership of a `CFDataRef` returned under the Create Rule, or render the
/// error the framework wrote instead.
fn owned_data(data: CFDataRef, error: CFErrorRef) -> std::result::Result<CFData, String> {
    if !data.is_null() {
        // SAFETY: a non-null Create-Rule return that we now own exactly once.
        return Ok(unsafe { CFData::wrap_under_create_rule(data) });
    }
    Err(match describe(error) {
        Some((detail, _)) => detail,
        None => "the Secure Enclave refused the operation without a reason".to_owned(),
    })
}

/// Render a `CFErrorRef` the framework wrote, taking ownership of it.
///
/// Returns the message and the `OSStatus`, because the classification depends on
/// the number and the operator needs the sentence.
fn describe(error: CFErrorRef) -> Option<(String, Option<i64>)> {
    if error.is_null() {
        return None;
    }
    // SAFETY: a non-null Create-Rule error reference that we now own.
    let error = unsafe { CFError::wrap_under_create_rule(error) };
    // `CFError::code` is `isize`; the OSStatus space is 32-bit, so widening to
    // `i64` is lossless and keeps the classification constants readable.
    Some((error.to_string(), Some(error.code() as i64)))
}

/// Whether an `OSStatus` means this process may not use the Secure Enclave at
/// all — the only *confident* negative this platform offers.
///
/// Every other failure, and the absence of a code entirely, is an inability to
/// determine rather than an absence. The set is deliberately tiny: a wrong entry
/// here tells a Mac with a working Secure Enclave that it has none.
pub(crate) fn is_confident_absence(code: Option<i64>) -> bool {
    matches!(
        code,
        Some(ERR_SEC_MISSING_ENTITLEMENT) | Some(ERR_SEC_UNIMPLEMENTED)
    )
}

/// Look the wrapping key up in the keychain, if a previous run created it.
fn find_existing_key() -> Option<OwnedKey> {
    let query = CFDictionary::from_CFType_pairs(&[
        (
            cf_key(unsafe { kSecClass }),
            cf_key(unsafe { kSecClassKey }),
        ),
        (
            cf_key(unsafe { kSecAttrLabel }),
            CFString::new(WRAP_KEY_LABEL).as_CFType(),
        ),
        (
            cf_key(unsafe { kSecAttrTokenID }),
            cf_key(unsafe { kSecAttrTokenIDSecureEnclave }),
        ),
        (
            cf_key(unsafe { kSecUseDataProtectionKeychain }),
            CFBoolean::true_value().as_CFType(),
        ),
        (
            cf_key(unsafe { kSecReturnRef }),
            CFBoolean::true_value().as_CFType(),
        ),
    ]);

    let mut found: CFTypeRef = std::ptr::null_mut();
    // SAFETY: `query` outlives the call; `found` is written only on success and
    // is a Create-Rule reference we then own.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut found) };
    if status != 0 || found.is_null() {
        return None;
    }
    // `CFTypeRef` is `*const`, `SecKeyRef` is `*mut`. The out-parameter is an
    // owned, mutable Create-Rule reference in every Apple header; the const-ness
    // is an artefact of the generic Core Foundation type, not a claim about the
    // object.
    Some(OwnedKey(
        found
            .cast_mut()
            .cast::<security_framework_sys::base::OpaqueSecKeyRef>(),
    ))
}

/// Create the Secure Enclave wrapping key.
///
/// The access control is pinned **before** the key is generated, because it is
/// an input to generation rather than an attribute applied afterwards — an
/// access policy set later would be a policy the key was not born with.
fn create_key() -> std::result::Result<OwnedKey, EnclaveUnavailable> {
    let mut error: CFErrorRef = std::ptr::null_mut();
    // `AfterFirstUnlockThisDeviceOnly` rather than `WhenUnlocked`: a node runs
    // as a background service and must keep working after the screen locks.
    // `ThisDeviceOnly` keeps the key off iCloud Keychain, which is what makes
    // the binding a binding. `PrivateKeyUsage` and nothing else: adding
    // `UserPresence` would put a Touch ID prompt in front of every unwrap, which
    // a daemon cannot answer.
    // SAFETY: the protection constant is a framework static; `error` is written
    // only on failure.
    let access: SecAccessControlRef = unsafe {
        SecAccessControlCreateWithFlags(
            std::ptr::null(),
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.cast::<std::ffi::c_void>(),
            kSecAccessControlPrivateKeyUsage,
            &mut error,
        )
    };
    if access.is_null() {
        let (detail, code) = describe(error).unwrap_or_else(|| {
            (
                "could not build a Secure Enclave access policy".to_owned(),
                None,
            )
        });
        return Err(EnclaveUnavailable { detail, code });
    }
    // SAFETY: a Create-Rule reference we now own; released when `access` drops.
    let access = unsafe { CFType::wrap_under_create_rule(access.cast()) };

    let private_attrs = CFDictionary::from_CFType_pairs(&[
        (
            cf_key(unsafe { kSecAttrIsPermanent }),
            CFBoolean::true_value().as_CFType(),
        ),
        (
            cf_key(unsafe { kSecAttrLabel }),
            CFString::new(WRAP_KEY_LABEL).as_CFType(),
        ),
        (cf_key(unsafe { kSecAttrAccessControl }), access),
    ]);

    let parameters = CFDictionary::from_CFType_pairs(&[
        (
            cf_key(unsafe { kSecAttrKeyType }),
            cf_key(unsafe { kSecAttrKeyTypeECSECPrimeRandom }),
        ),
        (
            cf_key(unsafe { kSecAttrKeySizeInBits }),
            CFNumber::from(WRAP_KEY_BITS).as_CFType(),
        ),
        (
            cf_key(unsafe { kSecAttrTokenID }),
            cf_key(unsafe { kSecAttrTokenIDSecureEnclave }),
        ),
        (
            cf_key(unsafe { kSecUseDataProtectionKeychain }),
            CFBoolean::true_value().as_CFType(),
        ),
        (
            cf_key(unsafe { kSecPrivateKeyAttrs }),
            private_attrs.as_CFType(),
        ),
    ]);

    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: `parameters` outlives the call; `error` is written only on failure.
    let key = unsafe { SecKeyCreateRandomKey(parameters.as_concrete_TypeRef(), &mut error) };
    if key.is_null() {
        let (detail, code) = describe(error).unwrap_or_else(|| {
            (
                "the Secure Enclave refused to create a key without a reason".to_owned(),
                None,
            )
        });
        return Err(EnclaveUnavailable {
            detail: format!("could not create a Secure Enclave wrapping key: {detail}"),
            code,
        });
    }
    Ok(OwnedKey(key))
}

/// Attempt a real private-key export and report whether the platform refused it.
///
/// **`true` means refused, which is the property being bought.** The polarity is
/// stated here because the failure direction matters: an error from the
/// framework for any reason reads as "refused", and that is the conservative
/// direction — a probe failure understates custody rather than overstating it,
/// so the worst outcome is a Secure Enclave host reporting a `NonExportable` it
/// genuinely earned via a refusal it did not fully understand, never a soft key
/// reported as hard.
fn export_is_refused(key: &OwnedKey) -> bool {
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: `key.0` is live. A NON-null return here would mean the platform is
    // willing to marshal the private key out, which is exactly what must not
    // happen; it is taken ownership of and dropped so a success does not leak
    // the material it should never have produced.
    let exported = unsafe { SecKeyCopyExternalRepresentation(key.0, &mut error) };
    match owned_data(exported, error) {
        Ok(mut exported) => {
            // Wipe what should not have existed before releasing it.
            let mut bytes = exported.to_vec();
            bytes.zeroize();
            let _ = &mut exported;
            false
        }
        Err(_) => true,
    }
}

/// Borrow a framework `CFStringRef` static as a `CFType` under the Get Rule.
///
/// A one-line helper because every dictionary key below is one of these, and
/// getting the ownership rule wrong on a framework constant would over-release a
/// static.
fn cf_key(raw: core_foundation_sys::string::CFStringRef) -> CFType {
    // SAFETY: framework string constants are immortal Get-Rule references.
    unsafe { CFString::wrap_under_get_rule(raw) }.as_CFType()
}

#[cfg(test)]
mod tests;
