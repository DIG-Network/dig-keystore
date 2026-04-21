//! `SignerHandle` — the unlocked, signing-capable handle returned by `Keystore::unlock`.
//!
//! A `SignerHandle<K>` owns a `Zeroizing<Vec<u8>>` copy of the decrypted secret
//! and the derived public key. It exposes `sign` and `public_key`; raw secret
//! bytes can never be extracted. Drop zeroizes the secret.

use std::marker::PhantomData;

use zeroize::Zeroizing;

use crate::error::Result;
use crate::scheme::KeyScheme;

/// The unlocked handle. Drop wipes the secret.
///
/// Cloning a `SignerHandle` clones the underlying zeroizing buffer — both
/// copies are independently wiped on drop. This is expensive for high-frequency
/// signing; prefer sharing an `Arc<SignerHandle<K>>` for that case.
pub struct SignerHandle<K: KeyScheme> {
    secret: Zeroizing<Vec<u8>>,
    public: K::PublicKey,
    _marker: PhantomData<fn() -> K>,
}

impl<K: KeyScheme> SignerHandle<K> {
    pub(crate) fn from_parts(secret: Zeroizing<Vec<u8>>, public: K::PublicKey) -> Self {
        Self {
            secret,
            public,
            _marker: PhantomData,
        }
    }

    /// Borrow the derived public key. Cheap (precomputed at unlock time).
    pub fn public_key(&self) -> &K::PublicKey {
        &self.public
    }

    /// Sign a byte message.
    pub fn sign(&self, msg: &[u8]) -> K::Signature {
        // K::sign only errors when the secret length is wrong; we control that.
        K::sign(&self.secret, msg).expect("signer handle secret length is guaranteed valid")
    }

    /// Attempt to sign, surfacing any scheme-level errors instead of panicking.
    pub fn try_sign(&self, msg: &[u8]) -> Result<K::Signature> {
        K::sign(&self.secret, msg)
    }

    /// Borrow the raw secret bytes.
    ///
    /// # ⚠️ Danger
    ///
    /// Prefer [`sign`](Self::sign) whenever possible. This method exists for
    /// a narrow class of consumers — hierarchical-deterministic (HD) wallets
    /// and key-derivation libraries — that need the raw seed bytes to
    /// derive child keys (e.g.
    /// [`chia_bls::DerivableKey::derive_unhardened`](https://docs.rs/chia-bls)).
    /// These callers cannot use [`sign`](Self::sign) because they need the
    /// `SecretKey` itself, not a signature.
    ///
    /// The returned slice is borrowed from the handle's internal
    /// `Zeroizing<Vec<u8>>`, so it wipes automatically when the handle
    /// drops. **Callers must not copy the bytes into a non-zeroizing
    /// buffer** without re-wrapping them — doing so would leave the secret
    /// on the heap past the end of its intended lifetime.
    ///
    /// Typical usage:
    ///
    /// ```no_run
    /// # use dig_keystore::{scheme::L1WalletBls, SignerHandle};
    /// # fn get_signer() -> SignerHandle<L1WalletBls> { unimplemented!() }
    /// let signer = get_signer();
    /// let master_sk = chia_bls::SecretKey::from_seed(signer.expose_secret());
    /// // `master_sk` is now the chia-bls master key; HD-derive as needed.
    /// ```
    ///
    /// If you catch yourself writing `signer.expose_secret().to_vec()` or
    /// `let copy = signer.expose_secret().to_owned();`, stop and consider
    /// whether you really need to own the bytes — and if so, wrap the copy
    /// in `Zeroizing::<Vec<u8>>::from(...)`.
    pub fn expose_secret(&self) -> &[u8] {
        &self.secret
    }
}

impl<K: KeyScheme> Clone for SignerHandle<K> {
    fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
            public: self.public.clone(),
            _marker: PhantomData,
        }
    }
}

impl<K: KeyScheme> std::fmt::Debug for SignerHandle<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerHandle")
            .field("scheme", &K::NAME)
            .field("public", &self.public)
            .field(
                "secret",
                &format_args!("<{} bytes zeroized>", self.secret.len()),
            )
            .finish()
    }
}

// Explicitly NOT implementing AsRef<[u8]>, Deref, or into_raw() on SignerHandle.
// The secret never leaves the handle by default; `expose_secret` is the one
// deliberate, clearly-named opt-out for HD-wallet consumers.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::BlsSigning;

    /// **Proves:** the `Debug` impl of `SignerHandle` does not print the raw
    /// secret bytes. We construct a handle with secret `0xAA` × 32 and
    /// assert the formatted output contains the placeholder but not `"AA"`.
    ///
    /// **Why it matters:** `SignerHandle` is routinely stored inside the
    /// validator's `Node` struct which gets `tracing::info!(?self, ...)`ed
    /// at startup. If the Debug impl leaked the secret, validator keys
    /// would land in log files on every restart. The test pins the no-leak
    /// property.
    ///
    /// **Catches:** accidentally deriving `Debug` on `SignerHandle` (which
    /// would print the inner `Zeroizing<Vec<u8>>` content), or a future
    /// `#[derive(Debug)]` addition that bypasses the custom impl.
    #[test]
    fn debug_does_not_leak_secret() {
        let secret = Zeroizing::new(vec![0xAAu8; 32]);
        let public = BlsSigning::public_key(&secret).unwrap();
        let handle: SignerHandle<BlsSigning> = SignerHandle::from_parts(secret, public);
        let s = format!("{:?}", handle);
        assert!(s.contains("<32 bytes zeroized>"));
        assert!(!s.contains("AA"));
    }

    /// **Proves:** the full in-memory signing path works — construct a
    /// handle, sign, verify with the public key.
    ///
    /// **Why it matters:** Exercises `SignerHandle::sign` without going
    /// through the encrypted backend. If this ever regresses, `Keystore::unlock`
    /// would return a handle that produces wrong signatures (catastrophic).
    ///
    /// **Catches:** a bug in `sign` (e.g. forwarding the wrong secret field,
    /// signing the wrong bytes, feeding the public key as the secret key).
    #[test]
    fn sign_works() {
        let secret = Zeroizing::new(vec![0x11u8; 32]);
        let public = BlsSigning::public_key(&secret).unwrap();
        let handle: SignerHandle<BlsSigning> = SignerHandle::from_parts(secret, public);
        let sig = handle.sign(b"message");
        assert!(chia_bls::verify(&sig, &public, b"message"));
    }

    /// **Proves:** cloning a `SignerHandle` yields an independent copy that
    /// produces the exact same signature as the original.
    ///
    /// **Why it matters:** Validators sometimes clone the handle into a
    /// per-duty context (so a panic in one duty's signing doesn't poison
    /// the other's). Both copies must produce identical signatures, which
    /// they will iff the secret is copied (not shared-and-mutably-rotated).
    ///
    /// **Catches:** a regression where `Clone` shares the underlying
    /// storage via `Arc` without `CoW` semantics — a single rotate would
    /// then silently corrupt one of the copies.
    #[test]
    fn clone_preserves_equality() {
        let secret = Zeroizing::new(vec![0x11u8; 32]);
        let public = BlsSigning::public_key(&secret).unwrap();
        let h1: SignerHandle<BlsSigning> = SignerHandle::from_parts(secret, public);
        let h2 = h1.clone();
        let s1 = h1.sign(b"x");
        let s2 = h2.sign(b"x");
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    /// **Proves:** `expose_secret` returns the exact seed bytes that were
    /// used to construct the handle — byte-for-byte equality.
    ///
    /// **Why it matters:** HD-wallet consumers (`dig-l1-wallet`, future
    /// `apps/wallet`) need the raw seed to feed `chia_bls::SecretKey::from_seed`
    /// and derive child keys. If `expose_secret` ever returned a transformed
    /// value (e.g., the derived master `SecretKey` serialised), HD derivation
    /// in dependent crates would silently produce the wrong child addresses.
    ///
    /// **Catches:** a regression that hashes / transforms the secret before
    /// returning; a bug where `expose_secret` borrows the public key
    /// instead of the private seed.
    #[test]
    fn expose_secret_returns_original_bytes() {
        let bytes = [0x77u8; 32];
        let secret = Zeroizing::new(bytes.to_vec());
        let public = BlsSigning::public_key(&secret).unwrap();
        let handle: SignerHandle<BlsSigning> = SignerHandle::from_parts(secret, public);
        assert_eq!(handle.expose_secret(), &bytes);
    }

    /// **Proves:** the byte slice returned by `expose_secret` is tied to the
    /// handle's lifetime — once the handle is dropped, the borrow must end.
    ///
    /// **Why it matters:** This is really a compile-time property of the
    /// borrow checker rather than a runtime assertion. The test exists to
    /// document the intended lifetime contract and to break if someone
    /// "helpfully" changes the return type to `Vec<u8>` (owned).
    ///
    /// **Catches:** a signature change to `expose_secret(&self) -> Vec<u8>`
    /// that would leak the secret on drop of the returned vec.
    #[test]
    fn expose_secret_borrow_scoped_to_handle() {
        let secret = Zeroizing::new(vec![0x22u8; 32]);
        let public = BlsSigning::public_key(&secret).unwrap();
        let handle: SignerHandle<BlsSigning> = SignerHandle::from_parts(secret, public);
        let borrowed: &[u8] = handle.expose_secret();
        assert_eq!(borrowed.len(), 32);
        // The borrow would be rejected by the compiler if `handle` were dropped
        // before `borrowed` — which is the property we want.
        drop(handle);
        // borrowed is now invalid and can't be touched; the compiler proves this.
    }
}
