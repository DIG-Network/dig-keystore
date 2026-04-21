//! `L1WalletBls` — the DIG / Chia L1 wallet BLS signing key scheme.
//!
//! Chia L1 wallets use BLS12-381 signatures. The stored secret is a 32-byte
//! seed; HD derivation (`m/12381/8444/2/{index}`) happens in the wallet layer
//! above this crate. For the keystore, we only need to round-trip the master
//! seed and expose the master key's public key / signature operations.
//!
//! On-disk file magic is `DIGLW1`.

use chia_bls::{PublicKey, SecretKey, Signature};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{KeystoreError, Result};
use crate::scheme::KeyScheme;

/// DIG/Chia L1 wallet master BLS key (the root of wallet HD derivation).
///
/// Callers typically unlock this, take the derived [`chia_bls::SecretKey`], and
/// use `chia_bls::DerivableKey::derive_unhardened` / `derive_hardened` at the
/// wallet layer. The keystore does not itself perform HD derivation.
#[derive(Debug, Clone, Copy)]
pub struct L1WalletBls;

impl KeyScheme for L1WalletBls {
    type PublicKey = PublicKey;
    type Signature = Signature;

    const MAGIC: [u8; 6] = *b"DIGLW1";
    const NAME: &'static str = "L1WalletBls";
    const SCHEME_ID: u16 = 0x0003;
    const SECRET_LEN: usize = 32;

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Zeroizing<Vec<u8>> {
        let mut seed = Zeroizing::new(vec![0u8; Self::SECRET_LEN]);
        rng.fill_bytes(&mut seed);
        seed
    }

    fn public_key(secret: &[u8]) -> Result<Self::PublicKey> {
        let sk = secret_to_secret_key(secret)?;
        Ok(sk.public_key())
    }

    fn sign(secret: &[u8], msg: &[u8]) -> Result<Self::Signature> {
        let sk = secret_to_secret_key(secret)?;
        Ok(chia_bls::sign(&sk, msg))
    }
}

fn secret_to_secret_key(secret: &[u8]) -> Result<SecretKey> {
    if secret.len() != L1WalletBls::SECRET_LEN {
        return Err(KeystoreError::InvalidPlaintext {
            expected: L1WalletBls::SECRET_LEN,
            got: secret.len(),
        });
    }
    Ok(SecretKey::from_seed(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** `L1WalletBls::MAGIC` and `L1WalletBls::SCHEME_ID` differ
    /// from those of [`crate::scheme::BlsSigning`].
    ///
    /// **Why it matters:** Type confusion between a validator signing key
    /// and a wallet master seed is the single most dangerous regression this
    /// crate could ship. If the two schemes ever shared a magic or a scheme
    /// id, `Keystore::<BlsSigning>::load` would silently accept a wallet
    /// file (or vice versa) and the two code paths would use each other's
    /// keys. This test is the tripwire.
    ///
    /// **Catches:** copy-paste of the `MAGIC` / `SCHEME_ID` constants from
    /// `BlsSigning` without editing them for the new scheme.
    #[test]
    fn magic_differs_from_bls_signing() {
        use crate::scheme::BlsSigning;
        assert_ne!(L1WalletBls::MAGIC, BlsSigning::MAGIC);
        assert_ne!(L1WalletBls::SCHEME_ID, BlsSigning::SCHEME_ID);
    }

    /// **Proves:** the full sign→verify round-trip works for `L1WalletBls` —
    /// a signature produced by `sign` verifies under the pubkey derived
    /// from the same seed via the public [`chia_bls::verify`].
    ///
    /// **Why it matters:** Mirror of
    /// [`super::bls_signing::tests::sign_verifies_via_chia_bls`] but for
    /// the wallet scheme. Cheap sanity check that both schemes share the
    /// same working `chia-bls` integration.
    ///
    /// **Catches:** a scheme-specific bug where e.g. `public_key` derives
    /// via the Chia wallet's HD path but `sign` uses the raw master key
    /// (or vice versa) — their outputs would mismatch and `verify` would
    /// return `false`.
    #[test]
    fn roundtrip_sign_verify() {
        let seed = [42u8; 32];
        let pk = L1WalletBls::public_key(&seed).unwrap();
        let sig = L1WalletBls::sign(&seed, b"hi").unwrap();
        assert!(chia_bls::verify(&sig, &pk, b"hi"));
    }
}
