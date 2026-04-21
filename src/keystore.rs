//! The typed [`Keystore`] — the crate's primary entry point.
//!
//! # Responsibilities
//!
//! [`Keystore<K>`] is the orchestration layer that composes [`crate::format`],
//! [`crate::kdf`], [`crate::cipher`], [`crate::scheme`], and [`crate::backend`]
//! into a user-friendly API. It is a thin type; the cryptographic weight
//! lives in the modules it calls:
//!
//! ```text
//!                        Keystore<K>  (this module)
//!                       /    |    \
//!               create/     |      \ unlock/
//!          change_password  |       rotate_kdf
//!                  ▼        ▼        ▼
//!     ┌─────────────────────────────────────────┐
//!     │ kdf::derive_key   (Argon2id)            │  ← 0.5s bottleneck
//!     │ cipher::encrypt   (AES-256-GCM)         │
//!     │ cipher::decrypt   (AES-256-GCM)         │
//!     │ format::encode_file / decode_file       │
//!     │ KeyScheme::public_key / sign            │
//!     │ KeychainBackend::read / write / delete  │
//!     └─────────────────────────────────────────┘
//! ```
//!
//! # Lifecycle
//!
//! ```text
//!   create(password, seed?) ──► encrypted file on backend ──► Keystore
//!                                                                 │
//!                                                   load(backend, path) ──► Keystore
//!                                                                 │
//!                      unlock(password) ──► SignerHandle<K>       │
//!                      change_password(old, new)                  │
//!                      rotate_kdf(password, new_params)           │
//!                      delete(self) ──► file removed              │
//! ```
//!
//! # Threading / concurrency
//!
//! `Keystore<K>` is `Send + Sync`. Internally it holds
//! `Arc<dyn KeychainBackend>` (shareable across threads) and a
//! `parking_lot::Mutex<Option<K::PublicKey>>` for the cached public key.
//! `unlock` re-reads the file on every call, so a concurrent
//! `change_password` is picked up automatically.
//!
//! # Why re-read on unlock
//!
//! Every `unlock` reads the full file, checks CRC + magic + scheme, decrypts.
//! This is ~0.5s (dominated by Argon2id) and incurs a filesystem read, but:
//!
//! - Makes concurrent password rotation safe without an explicit lock.
//! - Catches any external tampering since the last unlock (paranoid but cheap).
//! - Avoids a subtle invariant: "in-memory header agrees with disk header".
//!
//! If a binary unlocks hundreds of times per second (unusual — validator
//! duty loops unlock once at startup), share the returned
//! [`SignerHandle`](crate::SignerHandle) via `Arc` instead of re-unlocking.

use std::marker::PhantomData;
use std::sync::Arc;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::backend::{BackendKey, KeychainBackend};
use crate::cipher;
use crate::error::{KeystoreError, Result};
use crate::format::{encode_file, decode_file, KdfParams, KeystoreHeader, FORMAT_VERSION_V1, CipherId};
use crate::kdf;
use crate::password::Password;
use crate::scheme::KeyScheme;
use crate::signer::SignerHandle;

/// A typed, encrypted keystore.
///
/// Holds metadata — the on-disk header — but never the plaintext secret until
/// [`unlock`](Keystore::unlock) is called. `unlock` returns a
/// [`SignerHandle<K>`](SignerHandle) that owns a zeroizing copy of the secret.
///
/// # Type parameter
///
/// `K` is the key scheme (see [`crate::scheme`]): typically [`BlsSigning`](crate::BlsSigning)
/// for validator keys, [`L1WalletBls`](crate::L1WalletBls) for Chia L1 wallet keys.
pub struct Keystore<K: KeyScheme> {
    backend: Arc<dyn KeychainBackend>,
    path: BackendKey,
    header: KeystoreHeader,
    // Optional cached public key — only populated if the keystore has been
    // unlocked at least once in this process. Allows metadata queries (e.g.,
    // `dig-validator keys show`) to avoid re-prompting for a password.
    cached_public: parking_lot::Mutex<Option<K::PublicKey>>,
    _marker: PhantomData<fn() -> K>,
}

impl<K: KeyScheme> Keystore<K> {
    // ---------------------------------------------------------------------
    // Constructors
    // ---------------------------------------------------------------------

    /// Create a new keystore on `backend` at `path`.
    ///
    /// - If `plaintext` is `Some`, those bytes are used as the secret (length
    ///   must equal [`K::SECRET_LEN`](KeyScheme::SECRET_LEN)). Callers who
    ///   already hold a seed (e.g., from a BIP-39 mnemonic) pass it here.
    /// - If `plaintext` is `None`, a fresh secret is generated via
    ///   [`K::generate`](KeyScheme::generate) with an OS-seeded RNG.
    ///
    /// Fails with [`KeystoreError::AlreadyExists`] if a blob already exists at
    /// `path` — this refuses to silently overwrite an existing key.
    pub fn create(
        backend: Arc<dyn KeychainBackend>,
        path: BackendKey,
        password: Password,
        plaintext: Option<Zeroizing<Vec<u8>>>,
        kdf_params: KdfParams,
    ) -> Result<Self> {
        Self::create_with_rng(
            backend,
            path,
            password,
            plaintext,
            kdf_params,
            &mut rand_core::OsRng,
        )
    }

    /// Like [`create`](Self::create) but uses a caller-supplied RNG. Primarily
    /// for deterministic test fixtures; **do not** use a predictable RNG for
    /// production keys.
    pub fn create_with_rng<R: RngCore + CryptoRng>(
        backend: Arc<dyn KeychainBackend>,
        path: BackendKey,
        password: Password,
        plaintext: Option<Zeroizing<Vec<u8>>>,
        kdf_params: KdfParams,
        rng: &mut R,
    ) -> Result<Self> {
        if backend.exists(&path)? {
            return Err(KeystoreError::AlreadyExists(path.as_str().to_string()));
        }

        // Resolve the secret we are encrypting.
        let secret: Zeroizing<Vec<u8>> = match plaintext {
            Some(p) => {
                if p.len() != K::SECRET_LEN {
                    return Err(KeystoreError::InvalidPlaintext {
                        expected: K::SECRET_LEN,
                        got: p.len(),
                    });
                }
                p
            }
            None => K::generate(rng),
        };

        // Confirm the scheme accepts these bytes (derives a valid public key).
        let public = K::public_key(&secret)?;

        // Random salt + nonce.
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

        // Provisional header so we can use it as AAD.
        let mut header = KeystoreHeader {
            magic: K::MAGIC,
            format_version: FORMAT_VERSION_V1,
            scheme_id: K::SCHEME_ID,
            kdf: kdf_params,
            cipher: CipherId::Aes256Gcm,
            salt,
            nonce,
            payload_len: 0, // filled in after we know ciphertext length
        };
        // The payload_len field is part of the AAD — we must finalise it
        // before computing the tag. We know the plaintext length and the AES-GCM
        // tag is a fixed 16 bytes, so the payload length is deterministic.
        header.payload_len = (secret.len() + cipher::TAG_SIZE) as u32;

        let enc_key = kdf::derive_key(password.as_bytes(), &header.salt, &header.kdf)?;
        let header_bytes = header.encode();
        let ciphertext_and_tag =
            cipher::encrypt(&enc_key, &header.nonce, &secret, &header_bytes)?;
        debug_assert_eq!(
            ciphertext_and_tag.len() as u32,
            header.payload_len,
            "ciphertext length invariant violated"
        );

        let file_bytes = encode_file(&header, &ciphertext_and_tag);
        backend.write(&path, &file_bytes)?;

        Ok(Self {
            backend,
            path,
            header,
            cached_public: parking_lot::Mutex::new(Some(public)),
            _marker: PhantomData,
        })
    }

    /// Load an existing keystore. Does NOT decrypt — reads and validates the
    /// header, verifies CRC32, and returns a handle that `unlock` can use.
    pub fn load(backend: Arc<dyn KeychainBackend>, path: BackendKey) -> Result<Self> {
        let bytes = backend.read(&path)?;
        let (header, _ciphertext_and_tag, _header_bytes) = decode_file(&bytes)?;

        // Check magic matches the requested scheme.
        if header.magic != K::MAGIC {
            return Err(KeystoreError::SchemeMismatch {
                expected: K::SCHEME_ID,
                expected_name: K::NAME,
                found: header.scheme_id,
            });
        }
        if header.scheme_id != K::SCHEME_ID {
            return Err(KeystoreError::SchemeMismatch {
                expected: K::SCHEME_ID,
                expected_name: K::NAME,
                found: header.scheme_id,
            });
        }

        Ok(Self {
            backend,
            path,
            header,
            cached_public: parking_lot::Mutex::new(None),
            _marker: PhantomData,
        })
    }

    // ---------------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------------

    /// Header metadata (magic, scheme id, KDF params, etc).
    pub fn header(&self) -> KeystoreHeader {
        self.header
    }

    /// Backend key this keystore was loaded from.
    pub fn path(&self) -> &BackendKey {
        &self.path
    }

    /// If the keystore has been unlocked in this process, returns the cached
    /// public key. Otherwise `None`.
    pub fn cached_public_key(&self) -> Option<K::PublicKey> {
        self.cached_public.lock().clone()
    }

    // ---------------------------------------------------------------------
    // Core operations
    // ---------------------------------------------------------------------

    /// Decrypt with `password` and return a [`SignerHandle`] holding the
    /// zeroizing secret + derived public key.
    ///
    /// # Errors
    ///
    /// - [`KeystoreError::DecryptFailed`] for a wrong password or a tampered file.
    /// - [`KeystoreError::CrcMismatch`] / [`KeystoreError::Truncated`] for a corrupt file.
    /// - [`KeystoreError::InvalidPlaintext`] if the decrypted secret has the wrong length.
    pub fn unlock(&self, password: Password) -> Result<SignerHandle<K>> {
        // Re-read the file so concurrent rotations are picked up.
        let bytes = self.backend.read(&self.path)?;
        let (header, ciphertext_and_tag, header_bytes) = decode_file(&bytes)?;

        if header.magic != K::MAGIC || header.scheme_id != K::SCHEME_ID {
            return Err(KeystoreError::SchemeMismatch {
                expected: K::SCHEME_ID,
                expected_name: K::NAME,
                found: header.scheme_id,
            });
        }

        let enc_key = kdf::derive_key(password.as_bytes(), &header.salt, &header.kdf)?;
        let plaintext = cipher::decrypt(
            &enc_key,
            &header.nonce,
            &ciphertext_and_tag,
            &header_bytes,
        )?;

        if plaintext.len() != K::SECRET_LEN {
            return Err(KeystoreError::InvalidPlaintext {
                expected: K::SECRET_LEN,
                got: plaintext.len(),
            });
        }

        let public = K::public_key(&plaintext)?;
        *self.cached_public.lock() = Some(public.clone());
        Ok(SignerHandle::from_parts(plaintext, public))
    }

    /// Re-encrypt the secret under a new password. The secret itself does not
    /// change; only the encryption key derived from the password. A fresh
    /// salt + nonce are generated so the output ciphertext differs even with
    /// the same password.
    pub fn change_password(&mut self, old: Password, new: Password) -> Result<()> {
        self.change_password_with_rng(old, new, &mut rand_core::OsRng)
    }

    /// Like [`change_password`](Self::change_password) but uses a caller-supplied RNG.
    pub fn change_password_with_rng<R: RngCore + CryptoRng>(
        &mut self,
        old: Password,
        new: Password,
        rng: &mut R,
    ) -> Result<()> {
        // Decrypt with the old password.
        let bytes = self.backend.read(&self.path)?;
        let (_header, ciphertext_and_tag, header_bytes) = decode_file(&bytes)?;
        let old_key = kdf::derive_key(old.as_bytes(), &self.header.salt, &self.header.kdf)?;
        let plaintext = cipher::decrypt(
            &old_key,
            &self.header.nonce,
            &ciphertext_and_tag,
            &header_bytes,
        )?;

        // Re-encrypt with the new password under a fresh salt + nonce.
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

        let mut new_header = self.header;
        new_header.salt = salt;
        new_header.nonce = nonce;
        new_header.payload_len = (plaintext.len() + cipher::TAG_SIZE) as u32;

        let new_key = kdf::derive_key(new.as_bytes(), &salt, &new_header.kdf)?;
        let new_header_bytes = new_header.encode();
        let new_ct = cipher::encrypt(&new_key, &nonce, &plaintext, &new_header_bytes)?;
        let new_file = encode_file(&new_header, &new_ct);
        self.backend.write(&self.path, &new_file)?;

        self.header = new_header;
        Ok(())
    }

    /// Rotate the KDF parameters (e.g., bump to `KdfParams::STRONG`). Uses the
    /// same password throughout; the on-disk file is re-encrypted under a new
    /// salt + nonce.
    pub fn rotate_kdf(&mut self, password: Password, new_params: KdfParams) -> Result<()> {
        self.rotate_kdf_with_rng(password, new_params, &mut rand_core::OsRng)
    }

    /// Like [`rotate_kdf`](Self::rotate_kdf) but uses a caller-supplied RNG.
    pub fn rotate_kdf_with_rng<R: RngCore + CryptoRng>(
        &mut self,
        password: Password,
        new_params: KdfParams,
        rng: &mut R,
    ) -> Result<()> {
        let bytes = self.backend.read(&self.path)?;
        let (_header, ciphertext_and_tag, header_bytes) = decode_file(&bytes)?;
        let old_key = kdf::derive_key(password.as_bytes(), &self.header.salt, &self.header.kdf)?;
        let plaintext = cipher::decrypt(
            &old_key,
            &self.header.nonce,
            &ciphertext_and_tag,
            &header_bytes,
        )?;

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

        let mut new_header = self.header;
        new_header.kdf = new_params;
        new_header.salt = salt;
        new_header.nonce = nonce;
        new_header.payload_len = (plaintext.len() + cipher::TAG_SIZE) as u32;

        let new_key = kdf::derive_key(password.as_bytes(), &salt, &new_params)?;
        let new_header_bytes = new_header.encode();
        let new_ct = cipher::encrypt(&new_key, &nonce, &plaintext, &new_header_bytes)?;
        let new_file = encode_file(&new_header, &new_ct);
        self.backend.write(&self.path, &new_file)?;

        self.header = new_header;
        Ok(())
    }

    /// Remove the encrypted blob.
    pub fn delete(self) -> Result<()> {
        self.backend.delete(&self.path)
    }
}

impl<K: KeyScheme> std::fmt::Debug for Keystore<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keystore")
            .field("scheme", &K::NAME)
            .field("path", &self.path)
            .field("kdf", &self.header.kdf)
            .finish()
    }
}
