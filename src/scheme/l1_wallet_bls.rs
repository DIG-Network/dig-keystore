//! `L1WalletBls` — the DIG / Chia L1 wallet BLS signing key scheme.
//!
//! Chia L1 wallets use BLS12-381 signatures. The stored secret is the
//! wallet's **master secret key's raw 32-byte scalar**
//! (`chia_bls::SecretKey::to_bytes()`) — already the result of the
//! Chia-standard `mnemonic -> mnemonic.to_seed("") -> SecretKey::from_seed(seed)`
//! derivation performed **once**, upstream, by the wallet layer (e.g.
//! `dig-l1-wallet::keystore::mnemonic::derive_master_key_from_mnemonic`). HD
//! account derivation (`m/12381/8444/2/{index}` via `master_to_wallet_unhardened`
//! / `_hardened`, then `.derive_synthetic()`) also happens in that wallet
//! layer. This crate only round-trips the already-derived master key and
//! exposes its public key / signature operations — it performs no further
//! derivation of its own.
//!
//! Reconstruction uses [`chia_bls::SecretKey::from_bytes`], which
//! deserializes the canonical scalar directly. It must NEVER run
//! [`chia_bls::SecretKey::from_seed`] on these bytes — that would derive a
//! **second**, different key from what is already a derived master key, so
//! the result would not match `dig-l1-wallet` / Sage / the Chia reference
//! wallet for the same mnemonic. (This was a real bug — see `dig_ecosystem`
//! issues #64 / #57 — fixed by switching reconstruction from `from_seed` to
//! `from_bytes`; see the
//! `public_key_matches_chia_standard_master_key_for_all_zero_mnemonic` test
//! below for the regression test.)
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
        // Fresh entropy is run through `from_seed` ONCE (the same EIP-2333
        // keygen the Chia-standard `mnemonic -> master key` step uses) so the
        // stored bytes are always a canonical in-range BLS12-381 scalar. Raw
        // random 32 bytes are NOT guaranteed to be < the scalar field order
        // (roughly half would be rejected by `from_bytes` in
        // `secret_to_secret_key`), so this derivation step is required, not
        // cosmetic — it produces the master key whose `to_bytes()` becomes
        // the stored secret, matching what `secret_to_secret_key` expects.
        let mut entropy = Zeroizing::new(vec![0u8; Self::SECRET_LEN]);
        rng.fill_bytes(&mut entropy);
        let master_sk = SecretKey::from_seed(&entropy);
        Zeroizing::new(master_sk.to_bytes().to_vec())
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

/// Deserialize the stored secret as an **already-derived** master key's raw
/// canonical scalar bytes.
///
/// Uses [`SecretKey::from_bytes`], NOT [`SecretKey::from_seed`] — per the
/// module docs, the stored secret is the final master key, so this function
/// must not re-derive it. Re-running `from_seed` here was the
/// double-derivation bug in `dig_ecosystem` issues #64 / #57: it treated an
/// already-derived scalar as fresh entropy and derived a second, different
/// key from it.
fn secret_to_secret_key(secret: &[u8]) -> Result<SecretKey> {
    if secret.len() != L1WalletBls::SECRET_LEN {
        return Err(KeystoreError::InvalidPlaintext {
            expected: L1WalletBls::SECRET_LEN,
            got: secret.len(),
        });
    }
    let bytes: [u8; 32] = secret
        .try_into()
        .expect("length checked above to equal SECRET_LEN (32)");
    SecretKey::from_bytes(&bytes).map_err(|e| KeystoreError::InvalidSeed(e.to_string()))
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

    /// **Proves:** both `public_key` and `sign` reject a secret whose length is
    /// not [`L1WalletBls::SECRET_LEN`], returning
    /// [`KeystoreError::InvalidPlaintext`] with the expected/got lengths — and
    /// do so **without panicking** (the [`crate::scheme::KeyScheme`] contract
    /// forbids panicking on malformed input).
    ///
    /// **Why it matters:** A wrong-length seed reaching `SecretKey::from_seed`
    /// is exactly the kind of malformed input that could come from a corrupt
    /// keystore file or a truncated import. The scheme must surface it as a typed
    /// error the keystore layer can report, not crash the validator/wallet
    /// binary.
    ///
    /// **Catches:** removing the length guard in `secret_to_secret_key` (which
    /// would let `from_seed` panic or silently accept the wrong-length seed),
    /// or reporting the wrong `expected`/`got` lengths.
    #[test]
    fn wrong_length_secret_rejected() {
        let short = [0u8; 16]; // not SECRET_LEN (32)

        let pk_err = L1WalletBls::public_key(&short).unwrap_err();
        match pk_err {
            KeystoreError::InvalidPlaintext { expected, got } => {
                assert_eq!(expected, L1WalletBls::SECRET_LEN);
                assert_eq!(got, 16);
            }
            other => panic!("expected InvalidPlaintext, got {other:?}"),
        }

        let sign_err = L1WalletBls::sign(&short, b"x").unwrap_err();
        assert!(matches!(
            sign_err,
            KeystoreError::InvalidPlaintext { got: 16, .. }
        ));
    }

    /// **Proves:** `L1WalletBls::public_key`/`sign`, given a wallet's already-derived
    /// master secret key bytes, reconstruct the SAME key — not a second, different
    /// key produced by re-deriving (`SecretKey::from_seed`) on bytes that are
    /// already a derived scalar.
    ///
    /// Regression for `dig_ecosystem` issues #64 / #57 ("L1WalletBls scheme
    /// double-derives"). This test computes the Chia-standard master key
    /// completely independently of `L1WalletBls` — via the well-known
    /// all-zero-entropy 24-word BIP-39 mnemonic ("abandon" ×11 + "about") and
    /// Chia's empty-passphrase convention (`mnemonic.to_seed("")` then
    /// `SecretKey::from_seed(seed)` **once**) — exactly the chain
    /// `dig-l1-wallet::keystore::mnemonic::derive_master_key_from_mnemonic` uses.
    /// It then stores that master key's raw canonical scalar bytes
    /// (`to_bytes()`) as the `L1WalletBls` secret (`SECRET_LEN` is 32 bytes,
    /// which only fits an already-derived scalar — the raw 64-byte BIP-39 seed
    /// cannot fit) and asserts `public_key`/`sign` operate on THAT key.
    ///
    /// Before the fix, `secret_to_secret_key` ran `SecretKey::from_seed` on
    /// these already-derived bytes a SECOND time, producing a different
    /// pubkey — this assertion fails under the old code and passes under the
    /// `SecretKey::from_bytes`-based fix.
    ///
    /// **Catches:** re-introducing any re-derivation (`from_seed`,
    /// `derive_hardened`/`derive_unhardened`, HKDF, hashing, …) inside
    /// `secret_to_secret_key`.
    #[test]
    fn public_key_matches_chia_standard_master_key_for_all_zero_mnemonic() {
        use bip39::{Language, Mnemonic};

        // The canonical all-zero-entropy 24-word BIP-39 mnemonic.
        let mnemonic = Mnemonic::parse_in_normalized(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon about",
        )
        .expect("well-known valid BIP-39 test vector");

        // Chia convention: empty passphrase.
        let bip39_seed = mnemonic.to_seed("");

        // The Chia-standard master key: `from_seed` applied EXACTLY ONCE.
        let expected_master_sk = SecretKey::from_seed(&bip39_seed);
        let expected_pk = expected_master_sk.public_key();

        // What an `L1WalletBls` keystore persists is the master key's raw
        // canonical scalar bytes, not the (64-byte, too-long-to-fit) BIP-39
        // seed itself — HD derivation already happened once, above.
        let stored_secret = expected_master_sk.to_bytes();

        let got_pk = L1WalletBls::public_key(&stored_secret).unwrap();
        assert_eq!(
            got_pk, expected_pk,
            "L1WalletBls::public_key must reconstruct the SAME master key \
             derived via `from_seed` once — not re-derive by hashing its raw \
             bytes through `from_seed` again"
        );

        // Golden fixed hex — pins the exact value so a future dependency bump
        // (bip39/chia-bls) can't silently move both sides of the comparison
        // above together and mask a regression.
        assert_eq!(
            hex::encode(got_pk.to_bytes()),
            "82ae65efe846b15a92c51b7ad6c32589fd79d38263d3cbefbeeba08be8e90d8bc335a\
             1e2fcc66a10b8c817c06232285a"
        );

        let msg = b"dig-keystore l1_wallet_bls golden vector";
        let sig = L1WalletBls::sign(&stored_secret, msg).unwrap();
        assert!(
            chia_bls::verify(&sig, &expected_pk, msg),
            "signature produced from the stored master-key bytes must verify \
             under the SAME (non-re-derived) master key's pubkey"
        );
    }
}
