//! Error types for `dig-keystore`.
//!
//! All fallible public operations return [`Result<T>`] (= `Result<T, KeystoreError>`).
//! The variants are designed to let callers distinguish:
//!
//! - **User error** — wrong password, wrong scheme type parameter → reshow a prompt.
//! - **Corruption / tampering** — CRC mismatch, auth-tag failure → refuse and
//!   alert the operator (possible attack).
//! - **Configuration error** — KDF params out of bounds, unsupported algorithm.
//! - **I/O error** — underlying backend could not read / write.
//!
//! Each variant carries enough context to be actionable. `Arc<std::io::Error>`
//! is used for the backend case so `KeystoreError` can implement `Clone`
//! (useful when passing errors through async channels or broadcasting via
//! `watch::Sender`).

use std::sync::Arc;
use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, KeystoreError>;

/// Errors produced by keystore operations.
///
/// The enum is [`Clone`] so errors can be fanned out through broadcast channels
/// or bubbled through async traits. The only non-Clone primitive (`std::io::Error`)
/// is wrapped in `Arc` to preserve clonability.
#[derive(Error, Debug, Clone)]
pub enum KeystoreError {
    /// An underlying backend I/O operation failed.
    ///
    /// This is the catch-all for filesystem errors from [`crate::FileBackend`]
    /// as well as any future backend (OS keyring / HSM). The wrapped
    /// [`std::io::Error`] preserves the original [`ErrorKind`](std::io::ErrorKind)
    /// for callers who want to distinguish e.g. `NotFound` from `PermissionDenied`.
    #[error("backend I/O error: {0}")]
    Backend(#[source] Arc<std::io::Error>),

    /// The file's magic prefix did not match any known scheme.
    ///
    /// First 6 bytes of a keystore file carry `DIGVK1`, `DIGLW1`, etc. If the
    /// caller pointed at a non-keystore file (or a future-version file this
    /// build doesn't understand), decode fails here before any cryptography.
    #[error("unknown magic; not a DIG keystore file (saw {saw:?})")]
    UnknownMagic {
        /// The magic bytes that were actually read.
        saw: [u8; 6],
    },

    /// The file's format version is newer or older than this library understands.
    ///
    /// Format version is stored as a big-endian `u16` right after the magic.
    /// This library recognizes [`crate::FORMAT_VERSION_V1`] only.
    #[error("unsupported format version {found}")]
    UnsupportedFormat {
        /// The format version byte read from the file.
        found: u16,
    },

    /// The file's key-scheme id does not match the type parameter used to open it.
    ///
    /// If the caller opens `Keystore::<BlsSigning>::load(...)` but the file on
    /// disk is `L1WalletBls` (scheme id `0x0003`), we refuse. This guards
    /// against accidentally interpreting wallet master seeds as validator
    /// signing seeds, which would produce perfectly-valid-looking BLS
    /// signatures that bind to the wrong domain.
    #[error(
        "key scheme mismatch: expected {expected:#06x} ({expected_name:?}), file is {found:#06x}"
    )]
    SchemeMismatch {
        /// The scheme expected by the caller (`K::SCHEME_ID`).
        expected: u16,
        /// Human-readable expected name (e.g., `"BlsSigning"`).
        expected_name: &'static str,
        /// The scheme id actually stored in the file.
        found: u16,
    },

    /// The CRC32 checksum at the end of the file did not match.
    ///
    /// CRC is computed over every byte of the file except the trailing 4. A
    /// mismatch indicates disk corruption, partial write, or deliberate
    /// tampering. It is NOT a cryptographic integrity check (AES-GCM's tag
    /// is) — CRC is only a fast-fail so we don't burn ~0.5 s on Argon2 for a
    /// file that's clearly garbage.
    #[error("CRC32 check failed (stored {stored:#010x}, computed {computed:#010x})")]
    CrcMismatch {
        /// The CRC32 read from the file.
        stored: u32,
        /// The CRC32 computed over the preceding bytes.
        computed: u32,
    },

    /// AES-GCM authentication tag failed.
    ///
    /// This is the single error produced for any cryptographic decryption
    /// failure: wrong password, tampered ciphertext, tampered header (AAD
    /// mismatch), or truncated payload. We intentionally do NOT distinguish
    /// these variants at the error level to avoid side-channel leaks.
    #[error("AES-GCM authentication failed (wrong password or tampered file)")]
    DecryptFailed,

    /// Argon2 or AES-GCM rejected the provided parameters.
    ///
    /// Thrown when [`crate::KdfParams`] has out-of-bounds values (e.g.,
    /// `memory_kib < 8192`) or when the underlying `argon2` crate returns an
    /// error (rare — usually only on invalid output size).
    #[error("invalid KDF params: {0}")]
    InvalidKdfParams(&'static str),

    /// The file advertised an unsupported KDF algorithm.
    ///
    /// Currently only `0x01 = Argon2id` is recognized. Non-`0x01` values are
    /// reserved for future algorithms (scrypt, bcrypt, balloon).
    #[error("unsupported KDF id {0:#04x}")]
    UnsupportedKdf(u8),

    /// The file advertised an unsupported symmetric cipher.
    ///
    /// Currently only `0x01 = AES-256-GCM` is recognized. Non-`0x01` values
    /// are reserved for e.g. ChaCha20-Poly1305.
    #[error("unsupported cipher id {0:#04x}")]
    UnsupportedCipher(u8),

    /// `Keystore::create` was called for a path that already exists.
    ///
    /// Deliberate: overwriting a keystore file is almost always an operator
    /// error. Callers that really want to replace a keystore should
    /// [`crate::Keystore::delete`] first, or simply [`crate::Keystore::change_password`]
    /// + [`crate::Keystore::rotate_kdf`] which rotate in place.
    #[error("key path already exists: {0:?}")]
    AlreadyExists(String),

    /// The decrypted plaintext has the wrong length for the key scheme.
    ///
    /// Each [`crate::KeyScheme`] declares a fixed [`SECRET_LEN`](crate::KeyScheme::SECRET_LEN).
    /// If `unlock` decrypts successfully but the plaintext length disagrees
    /// with the scheme (e.g., file was encrypted under v1 with a 32-byte seed
    /// and this build expects 48), we reject. Normally impossible once the
    /// scheme id check has passed; included for defence in depth.
    #[error("invalid plaintext length: expected {expected}, got {got}")]
    InvalidPlaintext {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length read.
        got: usize,
    },

    /// The provided seed bytes were malformed (e.g., not a valid BLS seed).
    ///
    /// Rarely thrown — `chia-bls::SecretKey::from_seed` accepts any byte
    /// length — but reserved for schemes where the raw bytes must pass a
    /// scheme-specific validity check (e.g., `secp256k1` scalar bounds).
    #[error("invalid seed bytes: {0}")]
    InvalidSeed(String),

    /// The file's length header claims a payload larger than the file bytes.
    ///
    /// Indicates a truncated file (disk full mid-write, network transfer cut,
    /// etc). Should be rare since we write files atomically via rename, but
    /// guard anyway.
    #[error("file truncated (header claims {claimed} byte payload, only {available} bytes available)")]
    Truncated {
        /// Bytes claimed by the header.
        claimed: usize,
        /// Bytes actually available.
        available: usize,
    },
}

impl From<std::io::Error> for KeystoreError {
    /// Wrap an I/O error as a backend error.
    ///
    /// Used liberally through the `?` operator in [`crate::FileBackend`] and
    /// other `std::io`-backed code paths.
    fn from(err: std::io::Error) -> Self {
        KeystoreError::Backend(Arc::new(err))
    }
}
