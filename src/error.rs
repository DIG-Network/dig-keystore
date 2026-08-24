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
///
/// `#[non_exhaustive]`: this catalog grows as the crate gains capability (six
/// variants arrived with hardware binding alone), so downstream `match`es must
/// carry a wildcard arm rather than break on every addition.
#[non_exhaustive]
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
    /// `Keystore::delete` first, or simply `Keystore::change_password`
    /// + `Keystore::rotate_kdf` which rotate in place.
    #[error("key path already exists: {0:?}")]
    AlreadyExists(String),

    /// The decrypted plaintext has the wrong length for the key scheme.
    ///
    /// Each `KeyScheme` declares a fixed `SECRET_LEN`.
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
    #[error(
        "file truncated (header claims {claimed} byte payload, only {available} bytes available)"
    )]
    Truncated {
        /// Bytes claimed by the header.
        claimed: usize,
        /// Bytes actually available.
        available: usize,
    },

    /// The caller required hardware binding, and this host cannot provide it.
    ///
    /// Raised by [`HardwarePolicy::Required`](crate::hardware::HardwarePolicy)
    /// rather than degrading. The
    /// [`DegradeReason`](crate::hardware::DegradeReason) says which negative
    /// outcome occurred — "no TPM on this machine" and "the TPM is present but
    /// unusable" lead a caller to different remedies.
    #[error("hardware binding required but unavailable: {reason}")]
    HardwareRequired {
        /// Why hardware binding could not be established.
        reason: crate::hardware::DegradeReason,
    },

    /// The host could not be inspected, so hardware availability is **unknown**.
    ///
    /// Deliberately distinct from a confident "no hardware present": collapsing
    /// the two would turn an inspection failure into a confident negative, and a
    /// transient probe failure would then silently strip hardware protection
    /// from a machine that has it. Under the default
    /// [`Preferred`](crate::hardware::HardwarePolicy::Preferred) policy this
    /// fails closed instead of degrading.
    #[error("could not determine hardware availability: {detail}")]
    HardwareProbeIndeterminate {
        /// Non-secret detail of the probe failure.
        detail: String,
    },

    /// The hardware component refused to wrap a content key.
    #[error("hardware wrap failed: {detail}")]
    HardwareWrapFailed {
        /// Non-secret detail of the failing operation.
        detail: String,
    },

    /// The hardware component could not unwrap a stored content key.
    ///
    /// This variant means exactly one thing: **the hardware refused**. Structural
    /// problems with the blob ([`MalformedEnvelope`](Self::MalformedEnvelope))
    /// and unnameable hardware
    /// ([`UnknownHardwareClass`](Self::UnknownHardwareClass)) are deliberately
    /// *not* reported here, so this variant keeps that meaning.
    ///
    /// # It does NOT say which situation occurred (`SPEC.md` §17.5b)
    ///
    /// Two situations with opposite consequences both produce this error:
    ///
    /// - a sealed blob presented to a **different machine** — the wrapping key is
    ///   non-exportable, so the copy cannot be opened. Recoverable: the sealing
    ///   machine still holds the key. This refusal is the guarantee, not a
    ///   malfunction.
    /// - the **sealing machine itself, after its key was destroyed** by a TPM
    ///   clear, a firmware update or a mainboard swap. The blob is permanently
    ///   unopenable by anyone, and for a wallet seed that is funds loss.
    ///
    /// They are indistinguishable from the error because the envelope records a
    /// hardware *class* and carries no device identity. So a caller **MUST NOT**
    /// infer recoverability from this variant, and a user-facing surface **MUST
    /// NOT** present a reassuring message on it — that is precisely the error the
    /// irreversible case returns. Say that this host cannot open the blob and
    /// that the machine which sealed it may be able to *if its trusted component
    /// is intact*; the distinction is only resolvable out of band.
    #[error("hardware unwrap failed: {detail}")]
    HardwareUnwrapFailed {
        /// Non-secret detail of the failing operation.
        detail: String,
    },

    /// A hardware envelope is structurally invalid.
    ///
    /// A malformed blob, not a hardware refusal. Notably covers an envelope
    /// declaring a zero-length wrapped key — which asserts that no hardware key
    /// protects it, and so must never decode as a hardware envelope.
    #[error("malformed hardware envelope: {detail}")]
    MalformedEnvelope {
        /// Non-secret detail of the structural violation.
        detail: String,
    },

    /// A hardware envelope records a hardware class this build cannot name.
    ///
    /// A **forward-compatibility** case, not corruption: a newer writer may have
    /// sealed with hardware this build has no name for. Reported rather than
    /// guessed, so an unknown class can never be silently treated as a known one
    /// — or as unprotected.
    #[error("blob was sealed by an unrecognised hardware class (wire id {wire_id:#04x})")]
    UnknownHardwareClass {
        /// The hardware-kind wire id read from the blob.
        wire_id: u8,
    },

    /// A hardware-wrapped blob was found on a host with no hardware tier.
    ///
    /// Reported instead of returning the envelope bytes, so a copied blob fails
    /// loudly rather than being mistaken for a corrupt keystore.
    #[error("blob is hardware-bound but this host is not ({tier})")]
    NotHardwareBound {
        /// The tier this host actually has.
        tier: String,
    },

    /// An unbind reported by storage as taken, but the stored blob is still a
    /// hardware envelope.
    ///
    /// Its own variant rather than a generic write error because of what the
    /// caller does next: a user unbinds in order to safely retire the trusted
    /// component, so "unbound" over a blob that is still bound is the one
    /// message here that provokes a destructive action. The wording says STILL
    /// BOUND for that reason.
    #[error("unbind did not take: the blob at {key} is still hardware-bound")]
    HardwareStillBound {
        /// The backend key whose blob is still wrapped.
        key: String,
    },

    /// A hardware-wrapped blob was sealed by a different class of hardware.
    ///
    /// Distinct from [`HardwareUnwrapFailed`](Self::HardwareUnwrapFailed), which
    /// is another *device* of the same class: this is another *kind* of
    /// component (a blob from a Mac read on Windows), which is a migration case
    /// rather than a copied-blob case.
    #[error("blob was sealed by {found}, this host has {expected}")]
    HardwareKindMismatch {
        /// The hardware class this host binds to.
        expected: &'static str,
        /// The hardware class recorded in the blob.
        found: &'static str,
    },

    /// A path holding sealed key material is readable or writable by someone
    /// other than its owner, and the backend could not restrict it.
    ///
    /// `FileBackend` requests owner-only permissions on its root directory and
    /// on every blob it writes, then **verifies** the result rather than
    /// trusting the request (`SPEC.md` §10.3, conformance C-14). This error is
    /// what that verification returns when the bits are still permissive — for
    /// example on a filesystem that does not implement POSIX modes, where
    /// `chmod` reports success and changes nothing.
    ///
    /// It is deliberately fatal rather than a warning. The alternative is a
    /// `write` that reports success while leaving a keystore blob group- or
    /// world-readable, which makes the backend's own documented guarantee a
    /// falsehood. Callers that genuinely accept that exposure should choose a
    /// different root, not a quieter backend.
    #[error("{path} has mode {mode:04o}, which grants access beyond its owner; choose a keystore root on a filesystem that honours POSIX modes")]
    InsecurePermissions {
        /// The offending path.
        path: String,
        /// The permission bits actually observed after the request.
        mode: u32,
    },

    /// The keystore root is not a directory the backend is willing to own.
    ///
    /// `FileBackend` refuses a root that is a **symbolic link**, or that
    /// exists as a non-directory, rather than following it. This is the one
    /// case that is deliberately *not* repaired: a permissive mode is a drift
    /// the backend can correct in one syscall and then verify, but a symlink
    /// is a statement about *where the keystore lives*, and the backend has no
    /// basis for deciding that some other directory is the intended one. Both
    /// `fs::set_permissions` and `fs::metadata` follow links, so following one
    /// would mean chmodding a directory chosen by whoever planted the link and
    /// then sealing an account master seed inside it.
    ///
    /// Callers that genuinely want the link's target as their root should pass
    /// the resolved path, making that choice explicit at the call site.
    #[error("{path} is not usable as a keystore root: {reason}")]
    UnsafeRoot {
        /// The offending path, exactly as configured.
        path: String,
        /// Why the path cannot hold a keystore.
        reason: &'static str,
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
