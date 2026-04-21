# dig-keystore

Encrypted secret-key storage for [DIG Network](https://github.com/DIG-Network) binaries. Typed `Keystore<K>`, AES-256-GCM + Argon2id, `Zeroizing` memory hygiene, filesystem-atomic writes. The single audit surface for "where validator and wallet keys live" in the DIG workspace.

Builds on [`chia-bls` 0.26](https://crates.io/crates/chia-bls) for BLS12-381 keys / signatures; see [`CRATES_SUMMARY.md`](../dig-network/CRATES_SUMMARY.md) for the full DIG + Chia stack.

- **Format version:** `0x0001` (see [`docs/resources/SPEC.md`](docs/resources/SPEC.md))
- **Default KDF:** Argon2id, 64 MiB / 3 iterations / 4 lanes
- **Default cipher:** AES-256-GCM (96-bit nonce, 128-bit tag)
- **MSRV:** 1.70

---

## Table of contents

1. [Install](#install)
2. [At-a-glance](#at-a-glance)
3. [Quick reference](#quick-reference)
4. [`Keystore<K>`](#keystorek)
5. [`SignerHandle<K>`](#signerhandlek)
6. [`KeyScheme` trait](#keyscheme-trait)
7. [Shipped schemes](#shipped-schemes)
8. [`KeychainBackend` trait](#keychainbackend-trait)
9. [Shipped backends](#shipped-backends)
10. [`Password`](#password)
11. [`BackendKey`](#backendkey)
12. [`KdfParams`](#kdfparams) / [`KdfId`](#kdfid) / [`CipherId`](#cipherid)
13. [`KeystoreHeader`](#keystoreheader)
14. [`KeystoreError`](#keystoreerror)
15. [`Result<T>`](#resultt)
16. [`bls` re-exports](#bls-re-exports)
17. [`testing` module](#testing-module-feature-testing)
18. [Feature flags](#feature-flags)
19. [File format](#file-format)
20. [Security properties](#security-properties)
21. [Common call sequences](#common-call-sequences)
22. [Performance](#performance)
23. [Testing](#testing)
24. [License](#license)

---

## Install

```toml
[dependencies]
dig-keystore = "0.1"
```

Default features include `file-backend`. Enable `testing` to get `MemoryBackend` and `TEST_PASSWORD` for dependent crates' tests.

---

## At-a-glance

| Type | Kind | One-line role |
|---|---|---|
| [`Keystore<K>`](#keystorek) | struct | the encrypted-file handle — `create`, `load`, `unlock`, `change_password`, `rotate_kdf`, `delete` |
| [`SignerHandle<K>`](#signerhandlek) | struct | the unlocked handle — `sign`, `public_key` — never exposes raw secret |
| [`KeyScheme`](#keyscheme-trait) | trait | turn secret bytes into pubkey + signature; defines on-disk magic + scheme id |
| [`BlsSigning`](#blssigning-digvk1) | unit struct impl KeyScheme | DIG L2 validator BLS key (magic `DIGVK1`) |
| [`L1WalletBls`](#l1walletbls-diglw1) | unit struct impl KeyScheme | Chia L1 wallet master seed (magic `DIGLW1`) |
| [`KeychainBackend`](#keychainbackend-trait) | trait | abstract byte-blob KV — `read` / `write` / `delete` / `list` |
| [`FileBackend`](#filebackend) | struct impl KeychainBackend | filesystem with atomic tmp-then-rename writes |
| [`MemoryBackend`](#memorybackend-feature-testing) | struct impl KeychainBackend | in-process `HashMap` (testing only) |
| [`Password`](#password) | struct | `Zeroizing<Vec<u8>>` wrapper; `Debug` never leaks |
| [`BackendKey`](#backendkey) | struct | opaque string key for a blob inside a backend |
| [`KdfParams`](#kdfparams) | struct | Argon2id memory / iterations / lanes |
| [`KeystoreHeader`](#keystoreheader) | struct | parsed 53-byte on-disk header |
| [`KdfId`](#kdfid), [`CipherId`](#cipherid) | enums | algorithm tags in the header |
| [`KeystoreError`](#keystoreerror) | enum | every failure variant |
| [`Result<T>`](#resultt) | alias | `Result<T, KeystoreError>` |
| [`bls::*`](#bls-re-exports) | module | re-exports of `chia_bls::{PublicKey, SecretKey, Signature, sign, verify}` |

---

## Quick reference

```rust,no_run
use std::sync::Arc;
use dig_keystore::{
    Keystore, Password, KdfParams,
    scheme::BlsSigning,
    backend::{FileBackend, BackendKey, KeychainBackend},
};

let backend: Arc<dyn KeychainBackend> = Arc::new(FileBackend::new("/var/dig/keys"));
let key = BackendKey::new("validator");
let password = Password::from("correct horse battery staple");

// Create (generates a fresh 32-byte seed).
let ks = Keystore::<BlsSigning>::create(
    backend.clone(),
    key.clone(),
    password.clone(),
    None,
    KdfParams::default(),
)?;

// Unlock and sign.
let signer = ks.unlock(password)?;
let signature = signer.sign(b"block-header");
let pubkey    = signer.public_key();

// Reload later.
let ks2 = Keystore::<BlsSigning>::load(backend, key)?;
# Ok::<(), dig_keystore::KeystoreError>(())
```

---

## `Keystore<K>`

```rust
pub struct Keystore<K: KeyScheme> { /* … */ }
```

The main type. Parameterised over a [`KeyScheme`] — typically [`BlsSigning`] for validator keys, [`L1WalletBls`] for Chia L1 wallet master seeds. Holds the parsed on-disk header and a handle to its backing store; **never** holds the plaintext secret in memory between `unlock` calls.

### `Keystore::create`

Create a new encrypted keystore blob on the backend.

```rust
pub fn create(
    backend: Arc<dyn KeychainBackend>,
    path: BackendKey,
    password: Password,
    plaintext: Option<Zeroizing<Vec<u8>>>,
    kdf_params: KdfParams,
) -> Result<Self>
```

**Inputs**

| Name | Type | Constraints / semantics |
|---|---|---|
| `backend` | `Arc<dyn KeychainBackend>` | Where the blob lives. Shared — cloning the `Arc` is the normal way to share a backend across threads. |
| `path` | [`BackendKey`] | Blob identifier. Must be filesystem-safe ASCII. |
| `password` | [`Password`] | The unlocking secret. Consumed (so Zeroizing drop fires). Any byte length ≥ 0. |
| `plaintext` | `Option<Zeroizing<Vec<u8>>>` | `Some(bytes)` → encrypt those bytes (must have length `K::SECRET_LEN`). `None` → generate a fresh secret via `K::generate(OsRng)`. |
| `kdf_params` | [`KdfParams`] | Argon2id cost. See [`KdfParams::DEFAULT`] / `STRONG` / `FAST_TEST`. |

**Output:** `Result<Keystore<K>>` — on success, the in-memory handle is populated with the just-written header. [`cached_public_key`](#keystorecached_public_key) is populated as a side-effect.

**Errors** (all `KeystoreError`)

| Variant | When |
|---|---|
| `AlreadyExists(path)` | A blob already exists at `path`. Refuses to overwrite. |
| `InvalidPlaintext { expected, got }` | Caller supplied `plaintext` of wrong length. |
| `InvalidKdfParams(_)` | `kdf_params` out of bounds (memory < 8 MiB, iterations < 1, lanes < 1, or upper caps exceeded). |
| `InvalidSeed(_)` | The chosen scheme rejected the seed bytes (rare; BLS schemes accept any 32 bytes). |
| `Backend(io)` | Backend `write` failed (disk full, permission denied, etc.). |

**Side effects**

- Calls `backend.exists(&path)` and `backend.write(&path, bytes)`.
- On `FileBackend`, creates the root directory (if missing) with mode `0700` and the file with mode `0600` on Unix.
- Writes `HEADER_SIZE + K::SECRET_LEN + TAG_SIZE + 4` bytes (for `BlsSigning` / `L1WalletBls`: 105 bytes).

---

### `Keystore::create_with_rng`

Like [`create`](#keystorecreate) but accepts a caller-supplied RNG for deterministic tests.

```rust
pub fn create_with_rng<R: RngCore + CryptoRng>(
    backend: Arc<dyn KeychainBackend>,
    path: BackendKey,
    password: Password,
    plaintext: Option<Zeroizing<Vec<u8>>>,
    kdf_params: KdfParams,
    rng: &mut R,
) -> Result<Self>
```

**Use when**: writing property tests or KATs. `rng` is used for both the generated seed (if `plaintext` is `None`) **and** the per-file salt + nonce. Production callers use [`create`](#keystorecreate) which internally picks `OsRng`.

**Security note:** never pass a predictable RNG for production keys — the Argon2id salt and AES-GCM nonce must be fresh random bytes to retain the crate's security properties.

---

### `Keystore::load`

Parse an existing keystore file. Does **not** decrypt.

```rust
pub fn load(
    backend: Arc<dyn KeychainBackend>,
    path: BackendKey,
) -> Result<Self>
```

**Inputs**

| Name | Type | Semantics |
|---|---|---|
| `backend` | `Arc<dyn KeychainBackend>` | Must contain a blob at `path`. |
| `path` | [`BackendKey`] | Identifier of an existing blob. |

**Output:** `Result<Keystore<K>>` — on success the header is parsed and validated; `cached_public_key` is `None` (no decryption happened, pubkey not known yet).

**Errors**

| Variant | When |
|---|---|
| `Backend(io)` (kind `NotFound`) | No blob exists at `path`. |
| `Truncated { claimed, available }` | File shorter than `HEADER_SIZE + TAG_SIZE + FOOTER_SIZE`. |
| `CrcMismatch { stored, computed }` | Outer CRC-32 does not match — disk bit-rot or tamper. |
| `UnknownMagic { saw }` | First 6 bytes are not a recognized scheme magic. |
| `UnsupportedFormat { found }` | `FORMAT_VERSION` is not `0x0001`. |
| `UnsupportedKdf(id)` | KDF id byte is not `0x01`. |
| `UnsupportedCipher(id)` | Cipher id byte is not `0x01`. |
| `SchemeMismatch { expected, found, … }` | File was created for a different scheme (e.g., loading `DIGLW1` as `BlsSigning`). |

---

### `Keystore::unlock`

Decrypt the file with the given password; return a `SignerHandle<K>`.

```rust
pub fn unlock(&self, password: Password) -> Result<SignerHandle<K>>
```

**Inputs**

| Name | Type | Semantics |
|---|---|---|
| `password` | [`Password`] | Must exactly match the password used at `create` time. |

**Output:** `Result<SignerHandle<K>>` — on success, the handle owns a `Zeroizing<Vec<u8>>` copy of the decrypted secret and the derived public key. `cached_public_key` on `self` is populated as a side-effect.

**Errors**

| Variant | When |
|---|---|
| `Backend(io)` | Re-reading the file failed (file was deleted between `load` and `unlock`). |
| `Truncated` / `CrcMismatch` / `UnknownMagic` / etc. | File became corrupted / swapped since `load`. |
| `SchemeMismatch` | File's scheme id differs from `K::SCHEME_ID`. |
| `DecryptFailed` | **Wrong password**, tampered header (AAD check), or tampered ciphertext. All three collapse into this one variant to avoid side-channel distinctions. |
| `InvalidPlaintext { expected, got }` | Decrypted plaintext length ≠ `K::SECRET_LEN` (defence-in-depth; normally unreachable once scheme-id matches). |

**Side effects**

- Re-reads the file from the backend on every call (picks up concurrent `change_password` / `rotate_kdf`).
- Derives an AES-256 key via Argon2id (~0.5 s with default params).
- Updates `self.cached_public_key` on success.

---

### `Keystore::change_password`

Re-encrypt the stored secret under a new password.

```rust
pub fn change_password(
    &mut self,
    old: Password,
    new: Password,
) -> Result<()>
```

Also: `change_password_with_rng<R: RngCore + CryptoRng>(&mut self, old: Password, new: Password, rng: &mut R) -> Result<()>` for deterministic tests.

**Inputs**

| Name | Type | Semantics |
|---|---|---|
| `old` | [`Password`] | Current password. Required to decrypt before re-encryption. |
| `new` | [`Password`] | Replacement password. Any byte length. |

**Output:** `Result<()>`. On success, `self.header.salt` and `self.header.nonce` are updated (fresh random values).

**Errors**

| Variant | When |
|---|---|
| `DecryptFailed` | Wrong `old` password or corrupt file. File is **not** modified. |
| `Backend(io)` | Underlying read or write failed. |
| `InvalidKdfParams` | (Internal re-encryption rejected the existing params — should not happen for previously-valid files.) |

**Guarantees**

- The underlying secret is preserved bit-exactly (future signatures are identical to past ones).
- A fresh salt and a fresh nonce are generated — no AES-GCM `(key, nonce)` reuse.
- On failure (including wrong `old`) the on-disk file is unchanged and the old password continues to work.

---

### `Keystore::rotate_kdf`

Bump the Argon2id parameters in place. Password is unchanged.

```rust
pub fn rotate_kdf(
    &mut self,
    password: Password,
    new_params: KdfParams,
) -> Result<()>
```

Also: `rotate_kdf_with_rng<R: RngCore + CryptoRng>(...)`.

**Inputs**

| Name | Type | Semantics |
|---|---|---|
| `password` | [`Password`] | Current password (unchanged). |
| `new_params` | [`KdfParams`] | Stronger (or different) Argon2id parameters. |

**Output:** `Result<()>`. On success, `self.header.kdf` reflects `new_params`.

**Errors:** same as `change_password`.

**Use case:** after an OWASP guideline update or when moving a keystore to higher-value service, bump from `DEFAULT` (64 MiB) to `STRONG` (256 MiB) without key rotation.

---

### `Keystore::delete`

Remove the encrypted blob from the backend. Consumes `self`.

```rust
pub fn delete(self) -> Result<()>
```

**Output:** `Result<()>`.

**Errors**

| Variant | When |
|---|---|
| `Backend(io)` | Backend `delete` raised an I/O error. Note: calling `delete` on an already-missing file is **not** an error (backends are idempotent). |

**Side effects (FileBackend):** best-effort single-pass zero overwrite, then `unlink`.

---

### Accessors

| Method | Return | Purpose |
|---|---|---|
| `header(&self) -> KeystoreHeader` | `KeystoreHeader` (Copy) | The parsed 53-byte on-disk header |
| `path(&self) -> &BackendKey` | borrowed | The backend identifier this keystore reads from |
| `cached_public_key(&self) -> Option<K::PublicKey>` | `Option<...>` | The derived pubkey, if this keystore has been created or unlocked in this process |

None of the accessors touch the backend or do cryptography — they are O(1) reads of in-memory state.

---

## `SignerHandle<K>`

```rust
pub struct SignerHandle<K: KeyScheme> { /* … */ }
```

Unlocked handle. Created **only** by [`Keystore::unlock`](#keystoreunlock). Owns a `Zeroizing<Vec<u8>>` copy of the secret; the secret is wiped when the handle is dropped.

Deliberately narrow API — no `into_raw`, no `AsRef<[u8]>`, no `Deref`. The secret never leaves the handle by design.

### Methods

```rust
pub fn public_key(&self) -> &K::PublicKey;
pub fn sign(&self, msg: &[u8]) -> K::Signature;
pub fn try_sign(&self, msg: &[u8]) -> Result<K::Signature>;
```

| Method | Input | Output | Errors | Panics |
|---|---|---|---|---|
| `public_key` | — | `&K::PublicKey` (borrowed) | — | never |
| `sign` | `msg: &[u8]` | `K::Signature` | — | only if `K::sign` returns `Err` (unreachable for shipped schemes — secret length is guaranteed valid) |
| `try_sign` | `msg: &[u8]` | `Result<K::Signature>` | propagates `K::sign` errors | never |

### Traits

- `Clone` — clones the underlying `Zeroizing` buffer and the pubkey. Both copies wipe independently on drop.
- `Debug` — prints `SignerHandle { scheme, public, secret: <N bytes zeroized> }` (never leaks).
- `Send + Sync` — when `K::PublicKey: Send + Sync` (true for all BLS schemes).

### Example

```rust,no_run
# use std::sync::Arc;
# use dig_keystore::{
#     Keystore, Password, KdfParams,
#     scheme::BlsSigning,
#     backend::{BackendKey, KeychainBackend, MemoryBackend},
# };
# let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
# let ks = Keystore::<BlsSigning>::create(
#     backend, BackendKey::new("k"), Password::from("p"), None, KdfParams::FAST_TEST,
# ).unwrap();
let signer = ks.unlock(Password::from("p"))?;
let sig = signer.sign(b"some bytes");
assert!(chia_bls::verify(&sig, signer.public_key(), b"some bytes"));
# Ok::<(), dig_keystore::KeystoreError>(())
```

---

## `KeyScheme` trait

```rust
pub trait KeyScheme: Send + Sync + 'static {
    type PublicKey: Clone + Debug + Send + Sync;
    type Signature: Clone + Send + Sync;

    const MAGIC: [u8; 6];
    const NAME: &'static str;
    const SCHEME_ID: u16;
    const SECRET_LEN: usize;

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Zeroizing<Vec<u8>>;
    fn public_key(secret: &[u8]) -> Result<Self::PublicKey>;
    fn sign(secret: &[u8], msg: &[u8]) -> Result<Self::Signature>;
}
```

### Contract

| Item | Requirement |
|---|---|
| `MAGIC` | 6-byte unique prefix written to the start of every file of this scheme |
| `NAME` | Human-readable name (for `KeystoreError::SchemeMismatch` messages) |
| `SCHEME_ID` | 2-byte unique id written at offset 8 of the header |
| `SECRET_LEN` | Fixed byte length of stored plaintext |
| `generate` | Pure fn of the RNG state; must yield exactly `SECRET_LEN` bytes |
| `public_key` | Pure fn of the secret bytes; must not panic on malformed input (return `Err`) |
| `sign` | Pure fn of secret + message; deterministic |

### Adding a new scheme

1. Define a unit struct and implement `KeyScheme`.
2. Allocate a fresh `MAGIC` (6 printable ASCII) and `SCHEME_ID` (next unused `u16`).
3. Register the magic in `format::is_known_magic` (inside the crate).
4. Write tests mirroring [`scheme/bls_signing.rs`](src/scheme/bls_signing.rs).

---

## Shipped schemes

### `BlsSigning` (DIGVK1)

DIG L2 validator BLS signing key.

| Constant | Value |
|---|---|
| `MAGIC` | `b"DIGVK1"` |
| `NAME` | `"BlsSigning"` |
| `SCHEME_ID` | `0x0001` |
| `SECRET_LEN` | `32` (raw seed bytes) |
| `PublicKey` | `chia_bls::PublicKey` (48-byte compressed G1) |
| `Signature` | `chia_bls::Signature` (96-byte compressed G2) |

The stored 32 bytes are a **seed**. On unlock, [`chia_bls::SecretKey::from_seed`](https://docs.rs/chia-bls) derives the actual secret key via EIP-2333. `chia_bls::sign` uses the augmented scheme (AUG), matching Chia's on-chain `AGG_SIG_ME` semantics.

### `L1WalletBls` (DIGLW1)

Chia L1 wallet master seed.

| Constant | Value |
|---|---|
| `MAGIC` | `b"DIGLW1"` |
| `NAME` | `"L1WalletBls"` |
| `SCHEME_ID` | `0x0003` |
| `SECRET_LEN` | `32` |
| `PublicKey` | `chia_bls::PublicKey` |
| `Signature` | `chia_bls::Signature` |

The stored 32 bytes are the master seed. HD derivation (`m/12381/8444/2/{index}`) happens in the consuming wallet layer; the keystore only round-trips the master seed.

---

## `KeychainBackend` trait

```rust
pub trait KeychainBackend: Send + Sync + 'static {
    fn read  (&self, key: &BackendKey)          -> Result<Vec<u8>>;
    fn write (&self, key: &BackendKey, data: &[u8]) -> Result<()>;
    fn delete(&self, key: &BackendKey)          -> Result<()>;
    fn list  (&self, prefix: &str)              -> Result<Vec<BackendKey>>;
    fn exists(&self, key: &BackendKey)          -> Result<bool>;  // default impl
}
```

### Method contract

| Method | Input | Output | Contract |
|---|---|---|---|
| `read` | `key: &BackendKey` | `Result<Vec<u8>>` | Returns `Backend(NotFound)` if blob absent |
| `write` | `key: &BackendKey, data: &[u8]` | `Result<()>` | **Must be atomic** — reader sees either old or new blob, never a torn mix |
| `delete` | `key: &BackendKey` | `Result<()>` | **Idempotent** — removing an absent key returns `Ok(())` |
| `list` | `prefix: &str` | `Result<Vec<BackendKey>>` | Returns keys whose inner string starts with `prefix`; order unspecified |
| `exists` | `key: &BackendKey` | `Result<bool>` | Default impl = `read` + inspect `NotFound` — override for cheaper checks |

---

## Shipped backends

### `FileBackend`

```rust
pub struct FileBackend { /* … */ }
impl FileBackend {
    pub fn new(root: impl Into<PathBuf>) -> Self;
    pub fn root(&self) -> &Path;
}
```

| Property | Value |
|---|---|
| Storage | `<root>/<key>.dks` per `BackendKey` |
| Atomicity | tmp file + `fsync` + `rename` (POSIX rename is atomic; Windows uses `MoveFileExW`) |
| Permissions (Unix) | root dir `0700`, files `0600` |
| Root creation | Lazy — on first `write` |
| Secure delete | Best-effort single-pass zero overwrite before `unlink` |

Construction never touches the disk; side effects begin on the first `write` call.

### `MemoryBackend` (feature `testing`)

```rust
pub struct MemoryBackend { /* … */ }
impl MemoryBackend { pub fn new() -> Self; }
```

In-process `parking_lot::Mutex<HashMap<BackendKey, Vec<u8>>>`. `KeychainBackend` impl behaves identically to `FileBackend` but is instantaneous and filesystem-free.

**Use in tests only.** Not compiled without the `testing` feature.

---

## `Password`

```rust
pub struct Password(/* Zeroizing<Vec<u8>> */);
```

Zeroizing wrapper around password bytes. Memory is wiped when `Password` is dropped.

### Methods

| Method | Signature | Purpose |
|---|---|---|
| `Password::new` | `fn new(bytes: impl AsRef<[u8]>) -> Self` | Construct from any byte source (copies into zeroizing buffer) |
| `as_bytes` | `fn as_bytes(&self) -> &[u8]` | Borrow raw bytes |
| `len` | `fn len(&self) -> usize` | Byte length |
| `is_empty` | `fn is_empty(&self) -> bool` | `len() == 0` |
| `strength` (feature `password-strength`) | `fn strength(&self) -> zxcvbn::Entropy` | `zxcvbn` estimate; empty on non-UTF-8 |

### `From` impls

| Source | Behaviour |
|---|---|
| `&str` | Copy via `as_bytes()` |
| `String` | Consume into zeroizing buffer (single allocation) |
| `&[u8]` | Copy |
| `Vec<u8>` | Consume into zeroizing buffer |

### Traits

- `Clone` — duplicates the zeroizing buffer; each copy wipes independently on drop.
- `Debug` — prints `Password(<N bytes>)`, **never** leaks content.

---

## `BackendKey`

```rust
pub struct BackendKey(pub String);
impl BackendKey {
    pub fn new(name: impl Into<String>) -> Self;
    pub fn as_str(&self) -> &str;
}
impl Display for BackendKey { … }
impl<T: Into<String>> From<T> for BackendKey { … }
```

Opaque string key for a blob inside a backend. The inner `String` is public so `serde`-style code can round-trip without adapters. Keep values filesystem-safe ASCII (no slashes, dots, control chars). Typical: `"validator"`, `"wallet_main"`, `"backup_2026"`.

---

## `KdfParams`

```rust
pub struct KdfParams {
    pub id: KdfId,
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u8,
}
```

### Presets

| Preset | `memory_kib` | `iterations` | `lanes` | Use |
|---|---|---|---|---|
| `KdfParams::DEFAULT` | `65536` (64 MiB) | `3` | `4` | production default; matches `dig-l1-wallet` |
| `KdfParams::STRONG` | `262144` (256 MiB) | `4` | `4` | high-value keys |
| `KdfParams::FAST_TEST` | `8192` (8 MiB) | `1` | `1` | **tests only** |

### Validation bounds (enforced in `derive_key`)

| Field | Min | Max |
|---|---|---|
| `memory_kib` | 8192 (8 MiB) | 1048576 (1 GiB) |
| `iterations` | 1 | 256 |
| `lanes` | 1 | 64 |

`Default` impl returns `DEFAULT`.

## `KdfId`

```rust
#[repr(u8)]
pub enum KdfId {
    Argon2id = 0x01,
}
```

Only `Argon2id` is recognized in v1. Future-reserved values: `0x02` (scrypt), `0x03` (balloon), etc.

## `CipherId`

```rust
#[repr(u8)]
pub enum CipherId {
    Aes256Gcm = 0x01,
}
```

Only `Aes256Gcm` is recognized in v1. Future-reserved values: `0x02` (ChaCha20-Poly1305), etc.

---

## `KeystoreHeader`

```rust
pub struct KeystoreHeader {
    pub magic:          [u8; 6],
    pub format_version: u16,
    pub scheme_id:      u16,
    pub kdf:            KdfParams,
    pub cipher:         CipherId,
    pub salt:           [u8; 16],
    pub nonce:          [u8; 12],
    pub payload_len:    u32,
}
```

Parsed representation of the 53-byte on-disk header. All fields are public for inspection; the header is bound into the AES-GCM AAD, so editing it in memory and expecting a resulting ciphertext to still decrypt is impossible.

Exposed via [`Keystore::header`](#accessors) and returned indirectly through the file-format module. Also: `FORMAT_VERSION_V1: u16 = 0x0001`.

---

## `KeystoreError`

```rust
pub enum KeystoreError {
    Backend(Arc<std::io::Error>),
    UnknownMagic { saw: [u8; 6] },
    UnsupportedFormat { found: u16 },
    SchemeMismatch { expected: u16, expected_name: &'static str, found: u16 },
    CrcMismatch { stored: u32, computed: u32 },
    DecryptFailed,
    InvalidKdfParams(&'static str),
    UnsupportedKdf(u8),
    UnsupportedCipher(u8),
    AlreadyExists(String),
    InvalidPlaintext { expected: usize, got: usize },
    InvalidSeed(String),
    Truncated { claimed: usize, available: usize },
}
```

`#[derive(Error, Debug, Clone)]` — `Clone` because async channels and `watch::Sender` broadcasts need it. `Display` comes from `thiserror`.

### Classification

| Class | Variants | Action |
|---|---|---|
| **User error** | `DecryptFailed`, `SchemeMismatch`, `AlreadyExists` | Reshow prompt / instruct user |
| **Corruption / tampering** | `CrcMismatch`, `UnknownMagic`, `Truncated`, `InvalidPlaintext`, `InvalidSeed` | Loud failure; possible attack; alert operator |
| **Configuration** | `InvalidKdfParams`, `UnsupportedKdf`, `UnsupportedCipher`, `UnsupportedFormat` | Operator fixes config or upgrades library |
| **Infrastructure** | `Backend(io)` | Retry / alert operator / inspect I/O error |

### `From<std::io::Error>`

```rust
impl From<std::io::Error> for KeystoreError;
```

Wraps the `io::Error` in `Arc` and returns `KeystoreError::Backend`. Used throughout `FileBackend` via the `?` operator.

---

## `Result<T>`

```rust
pub type Result<T> = std::result::Result<T, KeystoreError>;
```

Every fallible function in the crate returns `Result<T>`.

---

## `bls` re-exports

```rust
pub mod bls {
    pub use chia_bls::{sign, verify, PublicKey, SecretKey, Signature};
}
```

Convenience re-exports so consumers that only need keystore + basic BLS verification don't need to add a direct `chia-bls` dependency. For advanced BLS work (aggregation, `AugSchemeMPL` wrappers, BLS12-381 curve operations) depend on `chia-bls` directly.

---

## `testing` module (feature `testing`)

```rust
pub mod testing {
    pub use crate::backend::MemoryBackend;
    pub const TEST_PASSWORD: &str = "dig-keystore-test-password";
}
```

Helpers for dependent crates. Add to their `dev-dependencies`:

```toml
[dev-dependencies]
dig-keystore = { version = "0.1", features = ["testing"] }
```

Then in tests:

```rust,ignore
use dig_keystore::testing::{MemoryBackend, TEST_PASSWORD};
```

---

## Feature flags

| Flag | Default | Effect |
|---|---|---|
| `file-backend` | **on** | Ships [`FileBackend`] |
| `testing` | off | Ships [`testing`](#testing-module-feature-testing) module |
| `password-strength` | off | Enables [`Password::strength`] via `zxcvbn` |
| `eip2335` | off | *(planned)* import/export [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335) v4 JSON |
| `chia-keychain` | off | *(planned)* import Chia `.keychain` files |

---

## File format

```
┌─────────────────────────────────────────────────────────────┐
│  6 bytes   MAGIC             "DIGVK1" or "DIGLW1"           │
│  2 bytes   FORMAT_VERSION    0x0001                         │
│  2 bytes   KEY_SCHEME        0x0001=BlsSigning              │
│                              0x0003=L1WalletBls             │
│  1 byte    KDF_ID            0x01 = Argon2id                │
│  4 bytes   KDF_MEMORY_KIB    u32 big-endian                 │
│  4 bytes   KDF_ITERATIONS    u32 big-endian                 │
│  1 byte    KDF_LANES         u8                             │
│  1 byte    CIPHER_ID         0x01 = AES-256-GCM             │
│ 16 bytes   SALT              random per file                │
│ 12 bytes   NONCE             random per file                │
│  4 bytes   PAYLOAD_LEN       u32 big-endian                 │
│  N bytes   CIPHERTEXT+TAG    AES-256-GCM(plaintext) || tag  │
│  4 bytes   CRC32             IEEE 802.3 over all preceding  │
└─────────────────────────────────────────────────────────────┘
```

- Header (first 53 bytes) is fed to AES-GCM as AAD; any edit invalidates the tag.
- CRC-32 is a fast-fail before Argon2id — not a security check.
- Full 32-byte-secret file = **105 bytes**.

Specification: [`docs/resources/SPEC.md`](docs/resources/SPEC.md).

---

## Security properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM under a password-derived key |
| Integrity | AES-GCM 128-bit auth tag (AAD-bound header) + outer CRC-32 |
| Brute-force resistance | Argon2id memory-hard KDF (RFC 9106); 64 MiB minimum |
| Memory hygiene | `Zeroizing` on passwords, seeds, AES keys |
| On-disk atomicity | Tmp file + `fsync` + atomic rename |
| Type safety | Magic + scheme-id forbid cross-scheme usage (compile-time + runtime) |

### Not guaranteed

- **Compromised host:** a process with ptrace / memory-read access can lift an unlocked `SignerHandle`. `Zeroizing` reduces but does not eliminate this.
- **Swapped memory:** the OS may page a `Zeroizing` buffer before drop. Disable swap or use `mlock` for high-value keys.
- **Secure-delete on SSDs:** single-pass overwrite does not guarantee sector erasure on modern flash. Use full-disk encryption.
- **Weak passwords:** no KDF hardness compensates for a 6-character password. Use `STRONG` params + enforce length at the CLI layer.

---

## Common call sequences

### New validator

```rust,no_run
# use std::sync::Arc;
# use dig_keystore::*;
# use dig_keystore::{scheme::BlsSigning, backend::*};
# let backend: Arc<dyn KeychainBackend> = Arc::new(FileBackend::new("/var/dig/keys"));
# let prompt_for_password = || Password::from("pw");
let ks = Keystore::<BlsSigning>::create(
    backend,
    BackendKey::new("validator"),
    prompt_for_password(),
    None,
    KdfParams::default(),
)?;
println!("pubkey = {:?}", ks.cached_public_key());
# Ok::<(), KeystoreError>(())
```

### Daily unlock at validator startup

```rust,no_run
# use std::sync::Arc;
# use dig_keystore::*;
# use dig_keystore::{scheme::BlsSigning, backend::*};
# let backend: Arc<dyn KeychainBackend> = Arc::new(FileBackend::new("/var/dig/keys"));
# let prompt_for_password = || Password::from("pw");
let ks = Keystore::<BlsSigning>::load(backend, BackendKey::new("validator"))?;
let signer = Arc::new(ks.unlock(prompt_for_password())?);
// Stash `signer` in the validator's Node struct; share across duty tasks via Arc.
# Ok::<(), KeystoreError>(())
```

### Password rotation

```rust,no_run
# use std::sync::Arc;
# use dig_keystore::*;
# use dig_keystore::{scheme::BlsSigning, backend::*};
# let backend: Arc<dyn KeychainBackend> = Arc::new(FileBackend::new("/var/dig/keys"));
let mut ks = Keystore::<BlsSigning>::load(backend, BackendKey::new("validator"))?;
ks.change_password(Password::from("old"), Password::from("new"))?;
# Ok::<(), KeystoreError>(())
```

### Upgrade KDF hardness

```rust,no_run
# use std::sync::Arc;
# use dig_keystore::*;
# use dig_keystore::{scheme::BlsSigning, backend::*};
# let backend: Arc<dyn KeychainBackend> = Arc::new(FileBackend::new("/var/dig/keys"));
let mut ks = Keystore::<BlsSigning>::load(backend, BackendKey::new("validator"))?;
ks.rotate_kdf(Password::from("pw"), KdfParams::STRONG)?;
# Ok::<(), KeystoreError>(())
```

### Wallet restore from mnemonic seed

```rust,no_run
# use std::sync::Arc;
# use dig_keystore::*;
# use dig_keystore::{scheme::L1WalletBls, backend::*};
# use zeroize::Zeroizing;
# let backend: Arc<dyn KeychainBackend> = Arc::new(FileBackend::new("/var/dig/keys"));
let seed: Zeroizing<Vec<u8>> = Zeroizing::new(vec![/* 32-byte seed derived from BIP-39 */; 32]);
let ks = Keystore::<L1WalletBls>::create(
    backend,
    BackendKey::new("l1_wallet"),
    Password::from("user-password"),
    Some(seed),
    KdfParams::default(),
)?;
# Ok::<(), KeystoreError>(())
```

---

## Performance

All figures on a modern x86_64 laptop (Zen4 / M2-class).

| Operation | Cost |
|---|---|
| `Keystore::create` (default params) | ~500 ms dominated by Argon2id |
| `Keystore::load` | < 1 ms (header parse + CRC) |
| `Keystore::unlock` (default params) | ~500 ms dominated by Argon2id |
| `Keystore::unlock` (`FAST_TEST` params) | ~10 ms |
| `SignerHandle::sign` (BLS G2) | ~0.5 ms per call |
| `SignerHandle::public_key` | O(1) — pubkey cached at unlock |
| `Keystore::change_password` | ~1 s (two Argon2id runs) |
| `FileBackend::write` | fsync-bound; typically < 5 ms on SSD |
| File size (32-byte secret) | 105 bytes |

---

## Testing

```bash
cargo test --features testing     # 72 tests across 6 binaries
cargo test --release              # realistic KDF timings
cargo clippy --features testing --all-targets -- -D warnings   # lint-clean
```

Test coverage:

| Suite | Asserts |
|---|---|
| `src/**/tests` | Unit tests for each primitive (AES-GCM, Argon2id, `Password`, file format, schemes, backends, signer) |
| `tests/roundtrip.rs` | End-to-end create / load / unlock / sign / verify; password + KDF rotation; type-confusion rejection |
| `tests/wrong_password.rs` | Wrong / empty / unicode / 4 KiB passwords; failed `change_password` leaves file intact |
| `tests/tamper.rs` | Every byte of a valid file flipped once — load or unlock must fail; truncation + garbage rejection |
| `tests/vectors.rs` | Known-answer tests pinning BLS derivation + file layout (105-byte size, magic bytes) |

Every `#[test]` carries a `/// **Proves:** ... **Why it matters:** ... **Catches:** ...` triple-slash doc comment. Run `cargo doc --open` to browse.

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
# dig-keystore
