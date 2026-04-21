//! `BlsSigning` — the DIG L2 validator BLS signing key scheme.
//!
//! Stored as a 32-byte seed. On unlock, derives a [`chia_bls::SecretKey`] via
//! [`chia_bls::SecretKey::from_seed`], which is the standard Chia BLS12-381
//! EIP-2333-compatible derivation.
//!
//! This is the scheme every DIG validator uses for its L2 signing key. The
//! on-disk file magic is `DIGVK1`.

use chia_bls::{PublicKey, SecretKey, Signature};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{KeystoreError, Result};
use crate::scheme::KeyScheme;

/// DIG validator BLS signing key (G1 pubkey / G2 signature on BLS12-381).
///
/// See [`crate::scheme`] for how this plugs into [`crate::Keystore`].
#[derive(Debug, Clone, Copy)]
pub struct BlsSigning;

impl KeyScheme for BlsSigning {
    type PublicKey = PublicKey;
    type Signature = Signature;

    const MAGIC: [u8; 6] = *b"DIGVK1";
    const NAME: &'static str = "BlsSigning";
    const SCHEME_ID: u16 = 0x0001;
    const SECRET_LEN: usize = 32;

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Zeroizing<Vec<u8>> {
        let mut seed = Zeroizing::new(vec![0u8; Self::SECRET_LEN]);
        rng.fill_bytes(&mut seed);
        seed
    }

    fn public_key(secret: &[u8]) -> Result<Self::PublicKey> {
        let sk = secret_to_bls_secret_key(secret)?;
        let pk = sk.public_key();
        Ok(pk)
    }

    fn sign(secret: &[u8], msg: &[u8]) -> Result<Self::Signature> {
        let sk = secret_to_bls_secret_key(secret)?;
        Ok(chia_bls::sign(&sk, msg))
    }
}

/// Derive a `chia_bls::SecretKey` from exactly-32 bytes of seed material.
pub(crate) fn secret_to_bls_secret_key(secret: &[u8]) -> Result<SecretKey> {
    if secret.len() != BlsSigning::SECRET_LEN {
        return Err(KeystoreError::InvalidPlaintext {
            expected: BlsSigning::SECRET_LEN,
            got: secret.len(),
        });
    }
    // `SecretKey::from_seed` accepts any byte length, but for interop with other
    // Chia tooling we fix at 32 bytes.
    Ok(SecretKey::from_seed(secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn generate_is_32_bytes() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
        let seed = BlsSigning::generate(&mut rng);
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn public_key_deterministic() {
        let seed = [7u8; 32];
        let pk1 = BlsSigning::public_key(&seed).unwrap();
        let pk2 = BlsSigning::public_key(&seed).unwrap();
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn sign_verifies_via_chia_bls() {
        let seed = [11u8; 32];
        let pk = BlsSigning::public_key(&seed).unwrap();
        let msg = b"hello";
        let sig = BlsSigning::sign(&seed, msg).unwrap();
        assert!(chia_bls::verify(&sig, &pk, msg));
    }

    #[test]
    fn sign_different_messages_produce_different_signatures() {
        let seed = [11u8; 32];
        let s1 = BlsSigning::sign(&seed, b"msg1").unwrap();
        let s2 = BlsSigning::sign(&seed, b"msg2").unwrap();
        assert_ne!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let pk1 = BlsSigning::public_key(&[1u8; 32]).unwrap();
        let pk2 = BlsSigning::public_key(&[2u8; 32]).unwrap();
        assert_ne!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn wrong_seed_length_errors() {
        let err = BlsSigning::public_key(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, KeystoreError::InvalidPlaintext { expected: 32, got: 16 }));
    }
}
