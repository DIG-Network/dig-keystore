---
title: dig-keystore — SPEC
status: design spec
last_updated: 2026-04-21
audience: crate implementers, reviewers (security-critical); consumers (apps/validator, apps/wallet, dig-l1-wallet)
authoritative_sources:
  - docs/resources/03-appendices/10-crate-scope-refined.md
  - apps/validator/SPEC.md §11 "Security"
  - apps/ARCHITECTURE.md §7 "Keychain"
  - apps/STAKING.md §11 "Compromise recovery"
---

# dig-keystore — Specification

> **This is a design-era doc kept for the crates.io package (`Cargo.toml` ships it as
> `docs/resources/SPEC.md`).** The repo-root [`SPEC.md`](../../SPEC.md) is the normative,
> RFC-2119 spec of record (CLAUDE.md §4.2) and is kept current with every change, including
> the `opaque` module (§15) and the `dig-keystore-wasm` WebAssembly binding (§16). Consult it
> first; this file's byte-layout diagram below remains accurate for `DIGVK1`/`DIGLW1` but does
> not describe additions made after `last_updated` above.

Encrypted secret-key storage for DIG binaries. Provides:

- On-disk file format for BLS signing keys (`DIGVK1`) and L1 wallet keys (`DIGLW1`).
- AES-256-GCM + Argon2id encryption with memory-hard KDF parameters.
- `Keystore<K>` generic over key scheme, `SignerHandle<K>` that never exposes raw key bytes.
- A `KeychainBackend` trait with `FileBackend` and `OsKeychainBackend` (OS-native credential store, feature `os-keychain`) shipped, and hardware backends (`LedgerBackend`, `YubiHsmBackend`) as planned future additions.
- `Zeroizing` memory hygiene on every secret.

The crate is the single audit surface for secret-key handling in the DIG workspace. Every BLS or L1 wallet key passed through DIG code goes through this crate.

## Scope

**In scope.**

- Generic `Keystore<K: KeyScheme>` for typed keys (BLS signing, L1 wallet).
- `SignerHandle<K>` that exposes only `sign(msg)` / `public_key()`; never `into_raw()`.
- File format V1: magic prefix + algorithm marker + Argon2id params + salt + ciphertext + tag.
- Encryption: AES-256-GCM (RFC 5116), 96-bit nonce, 128-bit tag.
- Key derivation: Argon2id (RFC 9106), default params 64 MiB / 3 iterations / 4 lanes, configurable per-file.
- Password strength check (optional) via `zxcvbn`.
- Key generation (BLS via `chia-bls::SecretKey::from_seed`, L1 via HD derivation) driven by `KeyScheme::generate`.
- Export / import via EIP-2335 / Chia `.keychain` compatibility shims (feature-gated).
- `KeychainBackend` trait abstraction with a shipped `OsKeychainBackend` (OS-native credential store) slotted in without changing call sites.

**Out of scope.**

- Key generation entropy source beyond calling `OsRng`. Entropy assumptions documented but not enforced.
- Hardware signer implementations (Ledger / YubiHSM) — shape of the backend trait only; full drivers ship later crates.
- Password UX (prompts, confirmation loops). Binaries own their CLI.
- Network operations. `dig-keystore` never touches I/O beyond the file backend.
- Slashing-protection DB. That is `dig-slashing::SlashingProtection` + file I/O in `apps/validator`.

## Placement in the Stack

```
   apps/validator        apps/wallet (future)        dig-l1-wallet
        │                     │                           │
        └──────────┬──────────┴───────────────┬──────────┘
                   ▼                          ▼
                dig-keystore           ← this crate
                   │
                   ├── aes-gcm
                   ├── argon2
                   ├── zeroize
                   ├── chia-bls        (BLS key scheme)
                   └── rand_core       (OsRng)
```

## File Format V1

All numbers big-endian. No compression. File is intended to be small (hundreds of bytes) and human-inspectable.

```
┌─────────────────────────────────────────────────────────────┐
│  6 bytes   MAGIC             "DIGVK1" or "DIGLW1"          │
│  2 bytes   FORMAT_VERSION    0x0001                         │
│  2 bytes   KEY_SCHEME        0x0001=BlsSigning              │
│                              0x0002=L1WalletSecp256k1       │
│                              0x0003=L1WalletBls (DIG L1)    │
│  1 byte    KDF_ID            0x01 = Argon2id                │
│  4 bytes   KDF_MEMORY_KIB    u32 (default 65536 = 64 MiB)   │
│  4 bytes   KDF_ITERATIONS    u32 (default 3)                │
│  1 byte    KDF_LANES         u8 (default 4)                 │
│  1 byte    CIPHER_ID         0x01 = AES-256-GCM             │
│ 16 bytes   SALT              random per file                │
│ 12 bytes   NONCE             random per file                │
│  4 bytes   PAYLOAD_LEN       u32                            │
│  N bytes   CIPHERTEXT        AES-256-GCM(plaintext)         │
│ 16 bytes   TAG               AES-GCM auth tag               │
│  4 bytes   CRC32             over all preceding bytes       │
└─────────────────────────────────────────────────────────────┘
```

Plaintext layout (what gets encrypted):

- **BlsSigning.** 32-byte seed. The BLS secret key is derived via `chia_bls::SecretKey::from_seed(seed)` on unlock. This matches Chia's convention of storing the seed, not the curve-scalar, so key shares can be regenerated deterministically.
- **L1WalletSecp256k1.** 32-byte seed + optional 64-byte BIP-39 mnemonic entropy (encoded length-prefixed). HD derivation happens on unlock.
- **L1WalletBls.** 32-byte raw scalar of an **already-derived** Chia L1 wallet master
  secret key (`chia_bls::SecretKey::to_bytes()`) — NOT a seed. The wallet layer performs
  `mnemonic -> mnemonic.to_seed("") -> SecretKey::from_seed(seed)` once, upstream, then
  hands this crate the resulting master key's raw bytes; `public_key`/`sign` reconstruct
  it via `chia_bls::SecretKey::from_bytes(bytes)` and MUST NOT re-run `from_seed` on it
  (doing so double-derives and produces a key that does not match `dig-l1-wallet` / Sage
  / the Chia reference wallet — fixed in `dig_ecosystem` issues #64 / #57).

`MAGIC` signals what the caller should treat the file as. Mixing (using a `DIGVK1` file with `L1WalletScheme`) is a hard error.

`CRC32` is defensive: catches bit-flips before the AES-GCM tag is evaluated, and gives a quick sanity check during recovery flows.

## Public API

### Core types

```rust
/// A key scheme (BLS signing, L1 wallet, etc.). Defines generation + sign.
pub trait KeyScheme: Send + Sync + 'static {
    type PublicKey: Clone + Debug;
    type Signature: Clone;
    type Message<'a>;

    const MAGIC: [u8; 6];
    const SCHEME_ID: u16;

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Plaintext;

    /// Derive PublicKey from the decrypted secret.
    fn public_key(secret: &SecretBytes) -> Self::PublicKey;

    /// Sign a message. Consumes neither the secret nor the message.
    fn sign(secret: &SecretBytes, msg: Self::Message<'_>) -> Self::Signature;
}

/// The three provided schemes.
pub struct BlsSigning;
pub struct L1WalletSecp256k1;
pub struct L1WalletBls;

impl KeyScheme for BlsSigning { /* uses chia-bls */ }
impl KeyScheme for L1WalletBls { /* uses chia-bls for Chia L1 */ }
impl KeyScheme for L1WalletSecp256k1 { /* uses k256 for Ethereum L1 if ever needed */ }
```

```rust
/// An encrypted key on disk. Does not hold any secret material until `unlock`.
pub struct Keystore<K: KeyScheme> {
    backend: Arc<dyn KeychainBackend>,
    path: BackendKey,
    _marker: PhantomData<K>,
}

impl<K: KeyScheme> Keystore<K> {
    /// Create a new keystore. The secret is generated if `plaintext` is None.
    pub fn create(
        backend: Arc<dyn KeychainBackend>,
        path: BackendKey,
        password: Password,
        plaintext: Option<Plaintext>,
        params: KdfParams,
    ) -> Result<Self>;

    /// Load an existing keystore (metadata only; does NOT decrypt).
    pub fn load(backend: Arc<dyn KeychainBackend>, path: BackendKey) -> Result<Self>;

    /// Decrypt + return a SignerHandle. The handle owns a zeroizing copy of the secret.
    pub fn unlock(&self, password: Password) -> Result<SignerHandle<K>>;

    /// Change the encryption password without changing the secret.
    pub fn change_password(&mut self, old: Password, new: Password) -> Result<()>;

    /// Public key is derivable from ciphertext only by unlocking. Convenience:
    /// if callers cache the pubkey separately, they avoid needing the password.
    pub fn cached_public_key(&self) -> Option<K::PublicKey>;

    /// Inspect the header without decrypting (scheme id, KDF params, etc.).
    pub fn header(&self) -> KeystoreHeader;
}
```

### `SignerHandle<K>`

```rust
/// Owns a zeroizing copy of the secret. The secret is wiped on drop.
pub struct SignerHandle<K: KeyScheme> {
    secret: Zeroizing<SecretBytes>,
    public: K::PublicKey,
    _marker: PhantomData<K>,
}

impl<K: KeyScheme> SignerHandle<K> {
    /// Public key derived at unlock time and cached in the handle.
    pub fn public_key(&self) -> &K::PublicKey;

    /// Sign. Cheap; does not re-derive the key.
    pub fn sign(&self, msg: K::Message<'_>) -> K::Signature;
}

// Explicitly NOT:
// impl<K> SignerHandle<K> { pub fn into_raw(self) -> SecretBytes { ... } }
// The secret never leaves the handle except through zeroization.
```

### Password

```rust
/// A password. Uses Zeroizing<Vec<u8>> internally. Consumes ownership at unlock.
#[derive(Clone)]
pub struct Password(Zeroizing<Vec<u8>>);

impl Password {
    pub fn new(bytes: impl AsRef<[u8]>) -> Self;

    /// Optional strength estimate for CLI helpers. Powered by zxcvbn.
    #[cfg(feature = "password-strength")]
    pub fn strength(&self) -> zxcvbn::Entropy;
}
```

### `KdfParams`

```rust
pub struct KdfParams {
    pub id: KdfId,               // Argon2id in v1
    pub memory_kib: u32,         // default 65536
    pub iterations: u32,         // default 3
    pub lanes: u8,               // default 4
}

pub enum KdfId {
    Argon2id,
}

impl KdfParams {
    pub const DEFAULT: Self = Self {
        id: KdfId::Argon2id,
        memory_kib: 65536,       // 64 MiB
        iterations: 3,
        lanes: 4,
    };

    /// Strong params for high-value keys (e.g., treasury).
    pub const STRONG: Self = Self {
        id: KdfId::Argon2id,
        memory_kib: 262144,      // 256 MiB
        iterations: 4,
        lanes: 4,
    };
}
```

Binaries may tune these per-key. File format records params so rotation is possible.

### `KeychainBackend`

```rust
pub trait KeychainBackend: Send + Sync + 'static {
    fn read(&self, key: &BackendKey) -> Result<Vec<u8>>;
    fn write(&self, key: &BackendKey, data: &[u8]) -> Result<()>;
    fn delete(&self, key: &BackendKey) -> Result<()>;
    fn list(&self, prefix: &str) -> Result<Vec<BackendKey>>;
}

pub struct BackendKey(pub String);

pub struct FileBackend {
    root: PathBuf,
}

impl FileBackend {
    pub fn new(root: PathBuf) -> Self;
}

impl KeychainBackend for FileBackend {
    fn read(&self, key: &BackendKey) -> Result<Vec<u8>> { /* open + read + close */ }
    fn write(&self, key: &BackendKey, data: &[u8]) -> Result<()> {
        // Atomic write: write to `<path>.tmp`, fsync, rename
    }
    fn delete(&self, key: &BackendKey) -> Result<()> {
        // Best-effort secure delete: overwrite + remove
    }
    // ...
}
```

**Atomicity.** `FileBackend::write` does a tmp-then-rename. On Windows, the rename is `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`. On POSIX, `renameat2` with `RENAME_EXCHANGE` when available (gives crash-safe rollback on the previous encrypted file).

**Secure delete.** `FileBackend::delete` overwrites the file with zeros (one pass; modern SSDs make deeper wipes theatre) before unlink. Documented as best-effort.

### `OsKeychainBackend` (feature `os-keychain`)

A `KeychainBackend` that persists each blob in the host OS credential store — **Windows Credential Manager** or **macOS Keychain** — via the cross-platform `keyring` crate. Each `BackendKey` maps to a `(service, account)` pair: the service is fixed per backend instance (chosen by the caller), the account is the `BackendKey` string. The stored value is the raw keystore ciphertext, written through `keyring`'s binary secret API (no textual re-encoding).

**Why an OS credential store.** On Windows and macOS the credential store gates access with a **per-application ACL** scoped to the logged-in user and released by the login session. That ACL — not the crate — is the access-control primitive. The keystore's own DIGVK1/DIGOP1 sealing remains layered underneath as defence-in-depth against a raw at-rest artifact; it is not weakened or replaced by this backend.

**Platform gating (HARD).** The `keyring` dependency is compiled **only** on `target_os = "windows"` or `target_os = "macos"`. On every other target — Linux and `wasm32` included — `keyring` is never pulled (no dbus/libsecret system-library tax, no wasm break) and `OsKeychainBackend::open` returns `None` so callers fall back to `FileBackend`. Linux is deliberately excluded as a custody primary: the kernel keyutils session keyring is readable by any same-UID process and is non-persistent across logout, so the passphrase-sealed file is the correct primary there.

**Fail-to-fallback construction.**

```rust
impl OsKeychainBackend {
    /// Open the OS credential store for `service`, probing the backend once.
    /// Returns `None` when no usable OS store exists on this host (⇒ the caller
    /// uses `FileBackend`). On Linux / wasm this is always `None`.
    pub fn open(service: impl Into<String>) -> Option<Self>;
}
```

`open` probes the backend with a throwaway lookup: a `NoEntry` result proves the store is reachable (and returns `Some`); only a hard backend error returns `None`. This makes "is the OS store usable?" a single decision taken once, rather than a failure surfacing mid-`unlock`.

**Enumeration (`list`).** OS credential stores expose no native key enumeration. `OsKeychainBackend` maintains a best-effort **index entry** (a reserved account) holding the set of live `BackendKey`s; `list(prefix)` filters it. `read`/`write`/`delete`/`exists` consult the credential store directly and are the source of truth — the index only powers `list`, so index/store drift can never corrupt a read or a write, only stale a listing. Index mutation is serialized within the process by a mutex.

**Memory hygiene.** Secret bytes handled in-process are held in `Zeroizing` buffers and wiped on drop. `OsKeychainBackend`'s `Debug` impl redacts — no service, account, or secret material is ever printed.

### Planned future backends

- **`LedgerBackend`** — communicates with a connected Ledger Nano. The `sign` operation forwards to the device; no `read`/`write` needed (ciphertext never leaves the device). Implemented as a `KeychainBackend` that returns placeholder metadata and a `SignerHandle<K>` that proxies `sign` over USB HID.
- **`YubiHsmBackend`** — same shape as Ledger.

These are documented in the trait docs but not shipped in v1.

### Errors

```rust
#[derive(thiserror::Error, Debug)]
pub enum KeystoreError {
    #[error("backend I/O error: {0}")]
    Backend(#[source] Arc<anyhow::Error>),

    #[error("unknown magic; not a DIG keystore file (saw {saw:?})")]
    UnknownMagic { saw: [u8; 6] },

    #[error("unsupported format version {found}")]
    UnsupportedFormat { found: u16 },

    #[error("key scheme mismatch: expected {expected:?}, file is {found:?}")]
    SchemeMismatch { expected: u16, found: u16 },

    #[error("CRC32 check failed")]
    CrcMismatch,

    #[error("AES-GCM authentication failed (wrong password or tampered file)")]
    DecryptFailed,

    #[error("invalid KDF params: {0}")]
    InvalidKdfParams(&'static str),

    #[error("unsupported KDF id {0}")]
    UnsupportedKdf(u8),

    #[error("unsupported cipher id {0}")]
    UnsupportedCipher(u8),

    #[error("key path already exists: {0:?}")]
    AlreadyExists(BackendKey),
}
```

## Invariants

| ID | Invariant | Enforcer |
|---|---|---|
| KS-001 | `SignerHandle` never exposes raw secret bytes | no `into_raw`, no `AsRef`/`Deref` to secret, `Zeroizing` on drop |
| KS-002 | AES-GCM tag verified before any bytes of plaintext are returned | `aes-gcm::Aead::decrypt` atomic semantics |
| KS-003 | CRC32 checked before AES-GCM attempt; fast-fail on corruption | read path |
| KS-004 | Passwords stored only in `Zeroizing<Vec<u8>>`; never in `String` | `Password` type |
| KS-005 | File writes are atomic (tmp + rename) | `FileBackend::write` |
| KS-006 | `change_password` re-encrypts under a fresh salt + nonce | method impl |
| KS-007 | `Keystore::create` refuses if `backend.read(path)` already succeeds (no accidental overwrite) | explicit check |
| KS-008 | KDF defaults are ≥ 64 MiB memory, ≥ 3 iterations, ≥ 4 lanes | `KdfParams::DEFAULT` constants |
| KS-009 | `KeyScheme::MAGIC` uniquely identifies the scheme on disk | review gate |
| KS-010 | Every panic path in `unlock` is caught and converted to `DecryptFailed` | `catch_unwind` at the boundary |
| KS-011 | `OsKeychainBackend::open` returns `None` (never panics/errors mid-op) when no usable OS store exists — always `None` on Linux/wasm | `open` probe + target gating |
| KS-012 | `OsKeychainBackend` `read`/`write`/`delete`/`exists` consult the credential store directly; the `list` index is best-effort and never authoritative for a read | backend impl |
| KS-013 | `keyring` is compiled only on Windows/macOS; never on Linux or wasm | target-gated `Cargo.toml` dependency |

## Feature Flags

| Flag | Default | Effect |
|---|---|---|
| `file-backend` | on | Ships `FileBackend` |
| `os-keychain` | off | Ships `OsKeychainBackend` (Windows Credential Manager / macOS Keychain via `keyring`; `None` ⇒ file fallback elsewhere). `keyring` is target-gated to Windows/macOS. |
| `password-strength` | off | Enables `Password::strength` via `zxcvbn` |
| `eip2335` | off | Import/export in Ethereum keystore v4 JSON format (for operators migrating from `ethdo`, `eth2-val-tools`, etc.) |
| `chia-keychain` | off | Import Chia `.keychain` files (seed-based) |
| `testing` | off | Exposes `MemoryBackend` + `TEST_PASSWORD` helpers |

## Dependencies

```toml
[dependencies]
aes-gcm = "0.10"
argon2 = "0.5"
zeroize = { version = "1", features = ["derive"] }
rand_core = "0.6"
rand_chacha = "0.3"             # for deterministic testing
chia-bls = { workspace = true }
crc32fast = "1"
thiserror = "1"
anyhow = "1"

[dependencies.zxcvbn]
version = "3"
optional = true

[dev-dependencies]
proptest = "1"
tempfile = "3"

[features]
default = ["file-backend"]
file-backend = []
password-strength = ["dep:zxcvbn"]
eip2335 = []
chia-keychain = []
testing = []
```

## Consumers

| Consumer | Key schemes used | Notes |
|---|---|---|
| `apps/validator` | `BlsSigning` (DIGVK1) | One keystore file per validator; loaded once at `pre_start`; `SignerHandle` held in `Arc<Validator>` for duty loop |
| `apps/wallet` (future) | `L1WalletBls` (DIGLW1) + possibly `BlsSigning` | Per-account keystore files |
| `dig-l1-wallet` | `L1WalletBls` (DIGLW1) | Currently ships its own ad-hoc key storage; plan is to migrate onto `dig-keystore` for a single audit target |

## Security Properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM over a password-derived key |
| Integrity | AES-GCM auth tag + outer CRC32 |
| Brute-force resistance | Argon2id (memory-hard; GPU/ASIC cost) |
| In-memory hygiene | `Zeroizing` on secret bytes, passwords, and intermediate KDF outputs |
| File-system atomicity | Tmp + rename on write |
| Protection vs swap | Best-effort `mlock` on decrypted buffers (POSIX) / `VirtualLock` on Windows; documented as not guaranteed |

**Non-guarantees (documented explicitly).**

- A compromised process with root or memory-read access can extract the unlocked `SignerHandle` — no software-only mitigation.
- A compromised backup of the keystore file + weak password → brute force possible. Mitigation: `KdfParams::STRONG` for high-value keys.
- The OS may swap `Zeroizing` buffers despite best efforts; use `mlock` / avoid paging file for sensitive workloads.

## Testing Strategy

- **Round-trip tests.** `create → load → unlock → sign` for every `KeyScheme`.
- **Wrong password.** `unlock` fails with `DecryptFailed`; no plaintext leak.
- **Tampered file.** Flip every byte in the ciphertext one-at-a-time; assert `DecryptFailed` (for payload bytes) or `CrcMismatch` (for header bytes).
- **Parameter tampering.** Flip KDF memory / iterations in the header; verify `DecryptFailed` (wrong key derived).
- **Concurrent access.** Two threads unlocking the same file concurrently both succeed; two threads calling `change_password` are serialized by an advisory file lock.
- **Property test.** `proptest` over arbitrary `KdfParams` + passwords verifies encrypt→decrypt round-trip.
- **KATs (known-answer tests).** A fixed-seed RNG + fixed password produces a byte-exact keystore file (`tests/vectors/`). Catches any accidental algorithm change.
- **Fuzzing.** `cargo-fuzz` targets the file parser with arbitrary byte sequences; no panics or segfaults allowed.

## File Layout

```
dig-keystore/
├── Cargo.toml
├── README.md
├── docs/
│   └── resources/
│       └── SPEC.md
├── src/
│   ├── lib.rs
│   ├── keystore.rs            ← Keystore<K>, SignerHandle<K>
│   ├── scheme/
│   │   ├── mod.rs
│   │   ├── bls_signing.rs     ← BlsSigning (DIGVK1)
│   │   ├── l1_bls.rs          ← L1WalletBls (DIGLW1)
│   │   └── l1_secp256k1.rs    ← L1WalletSecp256k1 (future)
│   ├── format.rs              ← file-format v1 encode/decode
│   ├── kdf.rs                 ← Argon2id wrapper
│   ├── cipher.rs              ← AES-256-GCM wrapper
│   ├── password.rs            ← Password type, strength
│   ├── backend/
│   │   ├── mod.rs             ← KeychainBackend trait
│   │   ├── file.rs            ← FileBackend
│   │   ├── memory.rs          ← MemoryBackend
│   │   └── os_keychain.rs     ← OsKeychainBackend (feature = "os-keychain")
│   ├── eip2335.rs             ← optional import/export (feature = "eip2335")
│   ├── chia_keychain.rs       ← optional (feature = "chia-keychain")
│   └── error.rs
└── tests/
    ├── roundtrip.rs
    ├── tamper.rs
    ├── wrong_password.rs
    ├── vectors/
    │   ├── bls_signing_v1.bin
    │   └── l1_wallet_bls_v1.bin
    └── vectors.rs             ← KAT harness
```

## Risks & Open Questions

1. **Zeroizing in async context.** `SignerHandle` may live across `await` boundaries; `Zeroizing` drops run when the future is dropped. Confirmed correct by the `zeroize` crate but worth an integration test that cancels a spawn mid-sign.
2. **Password prompts.** Binaries drive prompts. This crate does not include a `read_password_from_tty` helper to keep the dependency list clean. Risk: inconsistent prompt behavior across binaries. Mitigation: a documented snippet in the crate README pointing binaries at `rpassword::read_password`.
3. **KDF upgrade path.** V1 = Argon2id. If a future version wants scrypt or a PHC-newer function, the header's `KDF_ID` field accommodates it; older files continue to work.
4. **Hardware signer stability.** The `KeychainBackend` + `SignerHandle` design allows hardware backends, but the exact trait split (can a hardware backend return a `SignerHandle` that isn't really holding a secret?) is mildly awkward. Decision: introduce a `Signer` trait in v1.1 that `SignerHandle` implements and hardware backends return directly. Defer until a real hardware integration is on the roadmap.
5. **Mlock / VirtualLock.** Pinning decrypted keys in memory is best-effort; on many systems it requires privileges. Document this; do not rely on it for security claims.
6. **Deterministic derivation for tests.** Tests need deterministic BLS key derivation. Provide `rand_chacha::ChaCha20Rng::from_seed(...)` + documented test vectors.
7. **Format migration.** When V2 ships, `Keystore::load` must recognize both. Plan: a top-level `Keystore` enum over versions, routed by `FORMAT_VERSION`. Not implemented in v1.
8. **Constant-time comparisons.** AES-GCM tag comparison is in `aes-gcm`; CRC32 check is non-sensitive (user-observable). OK.
9. **Multi-key files.** EIP-2335 supports a single key per file; we follow. Storing multiple keys per file adds indexing complexity for marginal benefit.

## Authoritative Sources

- [`apps/validator/SPEC.md`](../../../dig-network/apps/validator/SPEC.md) §11 "Security"
- [`apps/ARCHITECTURE.md`](../../../dig-network/apps/ARCHITECTURE.md) §7 "Keychain"
- [`apps/STAKING.md`](../../../dig-network/apps/STAKING.md) §11 "Compromise recovery"
- [`docs/resources/03-appendices/10-crate-scope-refined.md`](../../../dig-network/docs/resources/03-appendices/10-crate-scope-refined.md) — rationale
- [`chia-bls` crate](https://crates.io/crates/chia-bls) — BLS primitives
- [RFC 9106 — Argon2](https://datatracker.ietf.org/doc/html/rfc9106)
- [RFC 5116 — AEAD APIs](https://datatracker.ietf.org/doc/html/rfc5116)
- [EIP-2335 — BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335)
- [Chia keychain module](https://github.com/Chia-Network/chia-blockchain/blob/main/chia/util/keychain.py)
