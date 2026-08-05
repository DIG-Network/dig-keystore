//! # dig-keystore
//!
//! Encrypted secret-key storage for DIG Network binaries.
//!
//! ## Feature tiers
//!
//! The crate splits into a machine-key **core** and a user-key **custody**
//! tier. The core seals arbitrary bytes under a password and stores them; it
//! has no notion of whose key it is. Custody models a *user's* identity key:
//! the typed `Keystore<K: KeyScheme>`, its schemes, and the `SignerHandle<K>`
//! you get by unlocking one.
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `file-backend` | yes | `FileBackend` (filesystem storage) |
//! | `os-keychain` | no | `OsKeychainBackend` (Windows / macOS credential store) |
//! | `custody` | **no** | `Keystore`, `SignerHandle`, `scheme::*` |
//! | `hd-derivation` | **no** | `SignerHandle::expose_secret` (implies `custody`) |
//! | `password-strength` | no | `Password::strength` |
//! | `testing` | no | `MemoryBackend` + `TEST_PASSWORD` for dependents' tests |
//!
//! `custody` is off by default so that a consumer needing only machine-key
//! sealing — the DIG node engine, whose identity-agnostic boundary is
//! dig_ecosystem #908 — cannot name the custody API. See `SPEC.md` §18,
//! **including the honest limits of that under Cargo feature unification**.
//!
//! The core surface is [`opaque`] (seal/open arbitrary-length secrets),
//! [`backend`], and the format/KDF/cipher types. Storage is abstracted behind
//! the `KeychainBackend` trait; hardware-signer backends (Ledger / YubiHSM)
//! plug into the same trait in future releases.
//!
//! ## File format
//!
//! `DIGVK1` (BLS signing) and `DIGLW1` (L1 wallet BLS) for typed custody
//! keystores, `DIGOP1` for opaque secrets. See `SPEC.md` §3 for the byte-level
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
//! Requires the `custody` feature:
//!
//! ```toml
//! dig-keystore = { version = "0.7", features = ["custody"] }
//! ```
#![cfg_attr(
    feature = "custody",
    doc = r#"
```no_run
use std::sync::Arc;
use dig_keystore::{
    Keystore, Password, KdfParams,
    scheme::BlsSigning,
    backend::{FileBackend, BackendKey, KeychainBackend},
};

# fn main() -> dig_keystore::Result<()> {
let backend: Arc<dyn KeychainBackend> = Arc::new(FileBackend::new("/var/dig/keys"));
let key = BackendKey::new("validator_bls");
let password = Password::from("correct horse battery staple");

// Create
let ks = Keystore::<BlsSigning>::create(
    backend.clone(),
    key.clone(),
    password.clone(),
    None,                          // generate a fresh seed
    KdfParams::default(),
)?;

// Unlock + sign
let signer = ks.unlock(password)?;
let sig = signer.sign(b"message");
let pk = signer.public_key();
# Ok(())
# }
```
"#
)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
mod cipher;
#[cfg(feature = "custody")]
mod custody;
mod error;
mod format;
pub mod hardware;
mod kdf;
pub mod opaque;
mod password;

// Re-exports — the public surface.

#[cfg(feature = "file-backend")]
pub use backend::FileBackend;
pub use backend::MemoryBackend;
#[cfg(feature = "os-keychain")]
pub use backend::OsKeychainBackend;
pub use backend::{BackendKey, KeychainBackend};

pub use error::{KeystoreError, Result};
pub use format::{CipherId, KdfId, KdfParams, KeystoreHeader, FORMAT_VERSION_V1};
pub use hardware::{
    DegradeReason, HardwareBoundBackend, HardwareKind, HardwarePolicy, HardwareProbe,
    HardwareProvider, KeyCustody, ProtectionTier,
};
pub use password::Password;

// The user-custody surface, behind the non-default `custody` feature. A
// consumer that only needs machine-key sealing cannot name these types at all
// unless something in its resolved graph turns the feature on — see `SPEC.md`
// §18 for the feature tiers and the honest limits of that guarantee.
#[cfg(feature = "custody")]
pub use custody::keystore::Keystore;
#[cfg(feature = "custody")]
pub use custody::scheme;
#[cfg(feature = "custody")]
pub use custody::scheme::{BlsSigning, KeyScheme, L1WalletBls};
#[cfg(feature = "custody")]
pub use custody::signer::SignerHandle;

// chia-bls re-exports so consumers don't need a direct dependency for simple cases.
pub mod bls {
    //! Convenience re-exports of the `chia-bls` types used by the BLS schemes.
    pub use chia_bls::{sign, verify};
    pub use chia_bls::{PublicKey, SecretKey, Signature};
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
