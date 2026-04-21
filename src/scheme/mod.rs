//! Key schemes: the typed layer that defines how raw secret bytes become
//! usable keys, public keys, and signatures.
//!
//! # Concept
//!
//! A *scheme* answers three questions for any key family:
//!
//! 1. **What is stored?** — Typically a 32-byte seed; sometimes a full keypair
//!    or curve scalar.
//! 2. **How is a public key derived?** — Pure function of the stored bytes.
//! 3. **How is a signature produced?** — Pure function of the stored bytes and
//!    a message.
//!
//! Each [`KeyScheme`] implementation also pins two on-disk identifiers:
//!
//! - A 6-byte **magic prefix** (e.g., `b"DIGVK1"`) — the first bytes of every
//!   file of this scheme. Human-readable for support ("what is this file?"),
//!   machine-enforceable for type safety.
//! - A 2-byte **scheme id** (e.g., `0x0001`) — included in the header to
//!   guard against MAGIC-collisions if we ever need to distinguish minor
//!   variants without bumping the magic.
//!
//! # Supplied schemes
//!
//! | Scheme | Magic | ID | Curve | Role |
//! |---|---|---|---|---|
//! | [`BlsSigning`] | `DIGVK1` | 0x0001 | BLS12-381 G1/G2 | DIG L2 validator signing key |
//! | [`L1WalletBls`] | `DIGLW1` | 0x0003 | BLS12-381 G1/G2 | Chia L1 wallet master seed |
//!
//! Additional schemes (e.g., `L1WalletSecp256k1` for hypothetical Ethereum L1
//! wallets, or hardware-signer wrappers) can be added by implementing the
//! trait in a fresh module.
//!
//! # Why separate types and not a runtime enum
//!
//! A runtime enum (`enum KeyType { Bls, L1Wallet, ... }`) would force every
//! caller into a `match` at every sign call. The trait-based approach:
//!
//! - Makes `Keystore<BlsSigning>` and `Keystore<L1WalletBls>` distinct types;
//!   you cannot accidentally feed a validator key where a wallet key was
//!   expected at compile time.
//! - Lets each scheme choose its own `PublicKey` and `Signature` associated
//!   types. `BlsSigning` produces `chia_bls::Signature`; a future secp256k1
//!   scheme would produce `k256::ecdsa::Signature`.
//! - Keeps the cryptographic code of each scheme localised for auditing.
//!
//! # References
//!
//! - [`chia-bls` crate](https://crates.io/crates/chia-bls) 0.26 — BLS12-381
//!   primitives used by all shipped schemes.
//! - [IETF draft-irtf-cfrg-bls-signature-05](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05)
//!   — the augmented BLS scheme (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_`)
//!   `chia-bls::sign` implements.
//! - [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333) — master-key
//!   derivation from a seed (what `SecretKey::from_seed` follows).

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::error::Result;

mod bls_signing;
mod l1_wallet_bls;

pub use bls_signing::BlsSigning;
pub use l1_wallet_bls::L1WalletBls;

/// Trait implemented by every supported key scheme.
///
/// Implementors define:
/// - how to generate fresh secret bytes (typically a 32-byte seed);
/// - how to derive a public key from the secret bytes;
/// - how to sign a byte message with the secret bytes;
/// - the 6-byte on-disk magic prefix and 2-byte scheme id.
///
/// # Contract
///
/// - `public_key` and `sign` must be **pure functions** of the secret bytes
///   and message — no external state, no RNG calls. Determinism is required so
///   signatures are reproducible across runs given identical inputs.
/// - `generate` must use the provided `CryptoRng` — no `OsRng::default()`
///   shortcuts, so tests can inject a deterministic RNG.
/// - Implementors must not panic on malformed input. Return an
///   [`Err`](crate::error::KeystoreError) instead.
///
/// # Safety
///
/// Implementations are expected to handle secret bytes through zeroizing
/// wrappers and never log / Debug-print them. The [`crate::Keystore`]
/// orchestration and [`crate::SignerHandle`] guarantee that secret bytes
/// passed to `public_key` / `sign` live inside a [`Zeroizing`] buffer for the
/// duration of the call.
pub trait KeyScheme: Send + Sync + 'static {
    /// Public key type returned by [`public_key`](Self::public_key).
    ///
    /// For BLS schemes, this is `chia_bls::PublicKey` (48-byte G1 compressed).
    type PublicKey: Clone + core::fmt::Debug + Send + Sync;

    /// Signature type returned by [`sign`](Self::sign).
    ///
    /// For BLS schemes, this is `chia_bls::Signature` (96-byte G2 compressed).
    type Signature: Clone + Send + Sync;

    /// 6-byte file magic. Must be unique per scheme.
    ///
    /// Recognized values: `DIGVK1` (validator key), `DIGLW1` (L1 wallet).
    /// New schemes must register their magic in [`crate::format::is_known_magic`]
    /// so the decoder accepts it.
    const MAGIC: [u8; 6];

    /// Human-readable name for error messages (e.g., `"BlsSigning"`).
    ///
    /// Shown to users in [`crate::KeystoreError::SchemeMismatch`] so they can
    /// tell why e.g. loading a wallet file as a validator key fails.
    const NAME: &'static str;

    /// Scheme id stored in the file header.
    ///
    /// Allocation:
    /// - `0x0001` — [`BlsSigning`]
    /// - `0x0002` — *(reserved)* `L1WalletSecp256k1` (not implemented)
    /// - `0x0003` — [`L1WalletBls`]
    const SCHEME_ID: u16;

    /// Length (in bytes) of the canonical secret.
    ///
    /// [`crate::Keystore::create`] passes exactly this many bytes from
    /// [`generate`](Self::generate) into the encryption layer; [`crate::Keystore::unlock`]
    /// validates the decrypted plaintext length equals this constant.
    const SECRET_LEN: usize;

    /// Generate fresh secret bytes.
    ///
    /// Must return **exactly** [`SECRET_LEN`](Self::SECRET_LEN) bytes.
    /// Implementations fill the buffer from `rng` — the caller-supplied RNG
    /// is used directly, not a hidden `OsRng`, so tests with deterministic
    /// seeds work.
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Zeroizing<Vec<u8>>;

    /// Derive the public key from the given secret bytes.
    ///
    /// Returns [`Err`](crate::error::KeystoreError) if `secret.len() != SECRET_LEN`,
    /// or if the bytes are malformed for the scheme (e.g., invalid secp256k1
    /// scalar). BLS schemes accept any 32 bytes.
    fn public_key(secret: &[u8]) -> Result<Self::PublicKey>;

    /// Sign `msg` using the given secret bytes.
    ///
    /// Returns [`Err`](crate::error::KeystoreError) if `secret.len() != SECRET_LEN`.
    /// For BLS schemes, the underlying call is
    /// [`chia_bls::sign`](https://docs.rs/chia-bls/latest/chia_bls/fn.sign.html),
    /// which uses Chia's augmented scheme (AUG) — each signature incorporates
    /// the signer's pubkey into the signed message to foreclose rogue-key
    /// attacks.
    fn sign(secret: &[u8], msg: &[u8]) -> Result<Self::Signature>;
}
