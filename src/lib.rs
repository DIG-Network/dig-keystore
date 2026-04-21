//! # dig-keystore
//!
//! Encrypted secret-key storage for DIG Network binaries.
//!
//! Provides a typed `Keystore<K: KeyScheme>` over an encrypted on-disk blob. The
//! storage layer is abstracted behind a `KeychainBackend` trait; `FileBackend`
//! ships for filesystem persistence, `MemoryBackend` ships under the `testing`
//! feature for dependent crates' tests. Hardware-signer backends (Ledger /
//! YubiHSM) plug into the same trait in future releases.
//!
//! ## File format
//!
//! `DIGVK1` (BLS signing) and `DIGLW1` (L1 wallet BLS). See
//! [`docs/resources/SPEC.md`](../../docs/resources/SPEC.md) for the byte-level
//! layout. Encryption is AES-256-GCM; key derivation is Argon2id (default 64
//! MiB / 3 iterations / 4 lanes).
//!
//! ## Security properties
//!
//! - AES-256-GCM authenticated encryption (tag integrity)
//! - Argon2id memory-hard KDF
//! - `Zeroizing<...>` wrappers on passwords, seeds, and derived keys
//! - Outer CRC32 for fast fail on bit-rot
//! - Atomic file writes (tmp + rename)
//!
//! ## Minimal example
//!
//! ```no_run
//! use std::sync::Arc;
//! use dig_keystore::{
//!     Keystore, Password, KdfParams,
//!     scheme::BlsSigning,
//!     backend::{FileBackend, BackendKey, KeychainBackend},
//! };
//!
//! # fn main() -> dig_keystore::Result<()> {
//! let backend: Arc<dyn KeychainBackend> = Arc::new(FileBackend::new("/var/dig/keys"));
//! let key = BackendKey::new("validator_bls");
//! let password = Password::from("correct horse battery staple");
//!
//! // Create
//! let ks = Keystore::<BlsSigning>::create(
//!     backend.clone(),
//!     key.clone(),
//!     password.clone(),
//!     None,                          // generate a fresh seed
//!     KdfParams::default(),
//! )?;
//!
//! // Unlock + sign
//! let signer = ks.unlock(password)?;
//! let sig = signer.sign(b"message");
//! let pk = signer.public_key();
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
mod cipher;
mod error;
mod format;
mod kdf;
mod keystore;
mod password;
pub mod scheme;
mod signer;

// Re-exports — the public surface.

pub use backend::{BackendKey, KeychainBackend};
#[cfg(feature = "file-backend")]
pub use backend::FileBackend;
#[cfg(feature = "testing")]
pub use backend::MemoryBackend;

pub use error::{KeystoreError, Result};
pub use format::{KdfId, KdfParams, KeystoreHeader, CipherId, FORMAT_VERSION_V1};
pub use keystore::Keystore;
pub use password::Password;
pub use scheme::{KeyScheme, BlsSigning, L1WalletBls};
pub use signer::SignerHandle;

// chia-bls re-exports so consumers don't need a direct dependency for simple cases.
pub mod bls {
    //! Convenience re-exports of the `chia-bls` types used by the BLS schemes.
    pub use chia_bls::{PublicKey, SecretKey, Signature};
    pub use chia_bls::{sign, verify};
}

#[cfg(feature = "testing")]
pub mod testing {
    //! Testing helpers for dependent crates — only compiled under the `testing` feature.
    //!
    //! Exports [`MemoryBackend`] and a constant [`TEST_PASSWORD`] so that
    //! dependent crates can stand up disposable keystores in their own tests
    //! without re-deriving Argon2 + AES-GCM boilerplate.

    pub use crate::backend::MemoryBackend;

    /// A fixed, well-known password for test fixtures.
    pub const TEST_PASSWORD: &str = "dig-keystore-test-password";
}
