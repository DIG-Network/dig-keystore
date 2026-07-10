# dig-keystore — Specification

**Status:** Normative. This document is the authoritative contract for the `dig-keystore`
crate: the on-disk keystore file format (byte level), the public API surface and its
semantics, error behavior, security properties, and conformance requirements. The key
words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in
RFC 2119.

`dig-keystore` is the encrypted secret-key storage layer for DIG Network binaries. It
provides a typed `Keystore<K: KeyScheme>` over an encrypted blob, an AES-256-GCM +
Argon2id at-rest file format, a pluggable `KeychainBackend` storage abstraction
(`FileBackend`, `MemoryBackend`), a BLS AugScheme signing surface via `SignerHandle<K>`,
and zeroizing memory hygiene on every secret. It is the single audit surface for
secret-key handling in the DIG workspace: every BLS validator key and Chia L1 wallet
master seed handled by DIG code goes through this crate.

---

## 1. Scope

**In scope**

- The v1 keystore file format (`FORMAT_VERSION 0x0001`) — §3.
- Key derivation: Argon2id (RFC 9106) — §4.
- Encryption: AES-256-GCM (RFC 5116 / NIST SP 800-38D) with header-as-AAD binding — §5.
- Key schemes: `BlsSigning` (`DIGVK1`) and `L1WalletBls` (`DIGLW1`), both BLS12-381 via
  `chia-bls` — §6.
- The `Keystore<K>` lifecycle (create / load / unlock / change_password / rotate_kdf /
  delete) — §7.
- The `SignerHandle<K>` signing surface and its secret-containment rules — §8.
- The `Password` type — §9.
- The `KeychainBackend` trait and the shipped `FileBackend` / `MemoryBackend` — §10.
- The error catalog — §11.
- Zeroization and other security properties — §12.
- The `opaque` module — arbitrary-length password-sealed secrets, no `KeyScheme` — §15.
- The `dig-keystore-wasm` WebAssembly binding (npm `@dignetwork/dig-keystore-wasm`) — §16.

**Out of scope**

- HD (hierarchical-deterministic) child-key derivation. The keystore stores and
  round-trips the master seed only; wallet layers (e.g. `dig-l1-wallet`) perform
  `m/12381/8444/...` derivation on the exposed seed.
- Password UX (prompts, confirmation loops). Binaries own their CLI.
- Network I/O. The crate performs no I/O beyond the storage backend.
- Hardware signers and OS keyrings. The `KeychainBackend` trait is designed to admit
  them, but no such backend ships.

---

## 2. Definitions

| Term | Meaning |
|---|---|
| **Keystore file** | A single encrypted blob in the v1 format of §3, holding exactly one secret. |
| **Scheme** | A `KeyScheme` implementation defining what the stored secret is and how it signs (§6). |
| **Secret** | The plaintext bytes protected by the file — for both shipped schemes, a 32-byte seed. |
| **Backend** | A `KeychainBackend` implementation: a byte-blob KV store addressed by `BackendKey`. |
| **Unlock** | Decrypting a keystore file with a password, yielding a `SignerHandle`. |

---

## 3. File format v1 (normative, byte level)

Every keystore file MUST have the following layout. All multi-byte integers are
**big-endian**. There is no compression and no padding.

```
Offset  Size  Field            Value / semantics
------  ----  ---------------  --------------------------------------------------
 0       6    MAGIC            b"DIGVK1" (BlsSigning) or b"DIGLW1" (L1WalletBls)
 6       2    FORMAT_VERSION   0x0001 (the only version this spec defines)
 8       2    KEY_SCHEME       0x0001 = BlsSigning
                               0x0002 = (reserved, unimplemented)
                               0x0003 = L1WalletBls
10       1    KDF_ID           0x01 = Argon2id (only assigned value)
11       4    KDF_MEMORY_KIB   u32 Argon2id memory cost in KiB
15       4    KDF_ITERATIONS   u32 Argon2id iteration count
19       1    KDF_LANES        u8  Argon2id parallelism (lanes)
20       1    CIPHER_ID        0x01 = AES-256-GCM (only assigned value)
21      16    SALT             random per file; Argon2id salt
37      12    NONCE            random per file; AES-GCM nonce
49       4    PAYLOAD_LEN      u32 = length of CIPHERTEXT+TAG in bytes
53       N    CIPHERTEXT+TAG   AES-256-GCM(secret) || 16-byte auth tag
53+N     4    CRC32            IEEE CRC-32 over ALL preceding bytes (header + payload)
```

- The fixed header is **53 bytes** (offsets 0–52). The footer is 4 bytes.
- `PAYLOAD_LEN` MUST equal `secret_len + 16` (the AES-GCM tag is a fixed 16 bytes).
  For both shipped schemes (`secret_len = 32`) the payload is 48 bytes and the total
  file size is **105 bytes**.
- The CRC-32 is the IEEE 802.3 polynomial (as computed by `crc32fast::hash`), stored
  big-endian, computed over every byte of the file except the trailing 4.

### 3.1 AAD binding (normative)

The 53 header bytes MUST be supplied as AES-GCM **associated data** (AAD) at encrypt
time, and the exact header bytes read from the file MUST be supplied as AAD at decrypt
time. Consequently any edit to any header field (magic, scheme id, KDF params, salt,
nonce, payload length) invalidates the authentication tag. No separate header MAC
exists or is needed.

### 3.2 Decode procedure (normative order)

A conforming reader MUST process a file in this order and fail with the stated error
(§11) at the first violation:

1. **Length floor.** If the file is shorter than `53 + 16 + 4 = 73` bytes →
   `Truncated`.
2. **CRC-32.** Recompute over `bytes[..len-4]`; compare to the stored footer →
   `CrcMismatch` on disagreement. The CRC is a fast-fail corruption check only; it is
   NOT a security boundary (the AES-GCM tag is).
3. **Magic.** The 6-byte magic MUST be one of the known values (`DIGVK1`, `DIGLW1`) →
   `UnknownMagic` otherwise.
4. **Format version.** MUST be `0x0001` → `UnsupportedFormat { found }` otherwise.
   (A reader implementing only v1 rejects both older and newer versions; when a future
   version ships, its readers dispatch on this field and continue to accept v1.)
5. **KDF id.** MUST be `0x01` → `UnsupportedKdf(byte)` otherwise.
6. **Cipher id.** MUST be `0x01` → `UnsupportedCipher(byte)` otherwise.
7. **Payload bounds.** `53 + PAYLOAD_LEN + 4` MUST NOT exceed the file length →
   `Truncated` otherwise.

Only after these checks MAY the reader run the KDF and attempt decryption. Steps 1–7
run before any cryptography so that garbage input rejects in microseconds instead of
paying the ~0.5 s Argon2id cost.

### 3.3 Scheme/type binding

`Keystore::<K>::load` and `unlock` MUST verify **both** `MAGIC == K::MAGIC` and
`KEY_SCHEME == K::SCHEME_ID`, and fail with `SchemeMismatch` if either disagrees.
Opening a wallet file as a validator key (or vice versa) is a hard error, never a
silent reinterpretation.

### 3.4 Forward compatibility

- New scheme ids, KDF ids, and cipher ids are additive: unassigned values are reserved
  and MUST be rejected by v1 readers with the corresponding `Unsupported*` error.
- `FORMAT_VERSION` is the versioning hinge. A change to the header layout, field
  semantics, or footer REQUIRES a version bump; v1 files remain readable forever by
  later readers.

---

## 4. Key derivation (Argon2id)

The 32-byte AES-256 key MUST be derived as:

```
key = Argon2id(version = 0x13, password, salt = SALT[16], m = KDF_MEMORY_KIB,
               t = KDF_ITERATIONS, p = KDF_LANES, output_len = 32)
```

- Algorithm: **Argon2id**, RFC 9106, algorithm version **0x13**. (Version 0x10 is not
  used.)
- The derivation is deterministic: identical `(password, salt, params)` MUST yield an
  identical key. This is the property that makes `unlock` possible.
- The derived key is held in a `Zeroizing<[u8; 32]>` and wiped on drop.

### 4.1 Parameter validation (normative bounds)

`KdfParams` MUST be validated before every derivation (create and unlock alike). A
conforming implementation rejects, with `InvalidKdfParams`:

| Bound | Rule |
|---|---|
| memory floor | `memory_kib >= 8192` (8 MiB) |
| memory cap | `memory_kib <= 1_048_576` (1 GiB) |
| iterations | `1 <= iterations <= 256` |
| lanes | `1 <= lanes <= 64` |

The caps exist so a hostile header cannot DoS the process with pathological cost
parameters; the floors are cryptographic minima.

### 4.2 Presets

| Preset | memory_kib | iterations | lanes | Use |
|---|---|---|---|---|
| `KdfParams::DEFAULT` (= `Default`) | 65 536 (64 MiB) | 3 | 4 | Recommended default; matches `dig-l1-wallet` (§14) |
| `KdfParams::STRONG` | 262 144 (256 MiB) | 4 | 4 | High-value keys |
| `KdfParams::FAST_TEST` (doc-hidden) | 8 192 (8 MiB) | 1 | 1 | Tests only; MUST NOT be used for real keys |

Parameters are recorded per file in the header, so files created under different
presets coexist and `rotate_kdf` (§7) can migrate between them.

---

## 5. Encryption (AES-256-GCM)

- Cipher: **AES-256-GCM** per RFC 5116 / NIST SP 800-38D, 96-bit (12-byte) nonce,
  128-bit (16-byte) tag. Output layout is `ciphertext || tag` (tag appended).
- The plaintext is the scheme secret (32 bytes for both shipped schemes).
- AAD is the 53-byte header (§3.1).
- **Nonce uniqueness (normative):** every encryption operation — `create`,
  `change_password`, `rotate_kdf` — MUST generate a fresh random salt AND a fresh
  random nonce. A `(key, nonce)` pair is never reused, because the key is re-derived
  from a fresh salt whenever a new nonce is drawn.
- **Failure indistinguishability (normative):** every decryption failure — wrong
  password, tampered ciphertext, tampered header (AAD mismatch), wrong nonce — MUST
  surface as the single error `DecryptFailed`. Implementations MUST NOT distinguish
  the causes at the error level (side-channel hygiene).
- Decrypted plaintext MUST be returned wrapped in `Zeroizing`.

---

## 6. Key schemes

### 6.1 The `KeyScheme` trait (contract)

```rust
pub trait KeyScheme: Send + Sync + 'static {
    type PublicKey: Clone + Debug + Send + Sync;
    type Signature: Clone + Send + Sync;

    const MAGIC: [u8; 6];        // unique per scheme; registered in the format decoder
    const NAME: &'static str;    // human-readable, used in SchemeMismatch errors
    const SCHEME_ID: u16;        // stored in the header
    const SECRET_LEN: usize;     // exact plaintext length

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Zeroizing<Vec<u8>>;
    fn public_key(secret: &[u8]) -> Result<Self::PublicKey>;
    fn sign(secret: &[u8], msg: &[u8]) -> Result<Self::Signature>;
}
```

Implementations MUST obey:

- `public_key` and `sign` are **pure functions** of their inputs — no RNG, no external
  state. Signatures are deterministic given `(secret, msg)`.
- `generate` MUST use the caller-supplied RNG (never a hidden `OsRng`) and MUST return
  exactly `SECRET_LEN` bytes in a `Zeroizing` buffer.
- `public_key` / `sign` MUST return `InvalidPlaintext { expected, got }` (never panic)
  when `secret.len() != SECRET_LEN`.
- `MAGIC` and `SCHEME_ID` MUST be unique across schemes; a new scheme's magic MUST be
  registered in the format decoder's known-magic set.

### 6.2 Shipped schemes

| Scheme | Magic | Scheme id | Secret | PublicKey | Signature |
|---|---|---|---|---|---|
| `BlsSigning` | `DIGVK1` | `0x0001` | 32-byte seed | `chia_bls::PublicKey` (48-byte compressed G1) | `chia_bls::Signature` (96-byte compressed G2) |
| `L1WalletBls` | `DIGLW1` | `0x0003` | 32-byte seed | `chia_bls::PublicKey` | `chia_bls::Signature` |

Scheme id `0x0002` is reserved (a secp256k1 wallet scheme that is not implemented) and
MUST NOT be emitted.

**Secret semantics (normative).** The stored secret is a **seed**, not a curve scalar.
On every use, the BLS secret key is derived as `chia_bls::SecretKey::from_seed(seed)`
(EIP-2333-style master-key derivation as implemented by `chia-bls` 0.26). Storing the
seed keeps the file interoperable with Chia tooling conventions and lets HD consumers
regenerate the full key tree.

**Signing algorithm (normative).** `sign` delegates to `chia_bls::sign`, which
implements the BLS12-381 **augmented scheme (AUG)** — ciphersuite
`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_` per draft-irtf-cfrg-bls-signature-05: the
signer's public key is prepended to the message before hashing, foreclosing rogue-key
attacks. Signatures produced by this crate verify with `chia_bls::verify(sig, pk, msg)`
and are byte-compatible with Chia's BLS signing (the same primitive used for Chia L1
`AGG_SIG` conditions).

The two schemes are behaviourally identical; they exist as **distinct types** with
distinct magics so that a validator signing key and a wallet master seed can never be
confused at compile time or on disk.

`L1WalletBls` performs **no HD derivation** — `public_key`/`sign` operate on the master
key. Wallet layers obtain the seed via `SignerHandle::expose_secret` (§8) and derive
children themselves.

---

## 7. `Keystore<K>` lifecycle and semantics

`Keystore<K>` holds the backend handle, the `BackendKey`, and the parsed header — never
the plaintext secret. It is `Send + Sync`; the only interior state is a mutex-guarded
cached public key.

```
create(password, secret?) ──► encrypted blob on backend ──► Keystore
load(backend, key)        ──► Keystore  (header validated; NOT decrypted)
unlock(password)          ──► SignerHandle<K>
change_password(old, new)     re-encrypts, same secret, fresh salt+nonce
rotate_kdf(password, params)  re-encrypts, same secret, new KDF cost, fresh salt+nonce
delete(self)              ──► blob removed from backend
```

### 7.1 `create` / `create_with_rng`

- If a blob already exists at the key, `create` MUST fail with `AlreadyExists` —
  it never silently overwrites an existing key. (The existence probe treats a
  backend `NotFound` read error as "absent"; any other backend error propagates.)
- If `plaintext` is supplied, its length MUST equal `K::SECRET_LEN`
  (`InvalidPlaintext` otherwise). If `None`, a fresh secret is generated via
  `K::generate` with `OsRng` (or the supplied RNG in `_with_rng`).
- The public key is derived before writing (validating the secret) and cached.
- Salt and nonce are drawn fresh from the RNG; `payload_len` is finalized **before**
  encryption because the header is AAD.
- `create_with_rng` exists for deterministic test fixtures; production keys MUST use
  a cryptographically secure OS RNG.

### 7.2 `load`

Reads the blob, runs the full decode procedure of §3.2 plus the scheme check of §3.3,
and returns a `Keystore` **without decrypting**. The cached public key starts `None`.

### 7.3 `unlock`

- MUST re-read the blob from the backend on every call (never trusts in-memory state),
  so concurrent `change_password`/`rotate_kdf` by another handle is picked up and any
  external tampering since the last unlock is caught.
- Runs §3.2 + §3.3 checks, derives the key (§4), decrypts (§5), verifies
  `plaintext.len() == K::SECRET_LEN` (`InvalidPlaintext` otherwise — defence in depth),
  derives and caches the public key, and returns a `SignerHandle`.
- Cost is dominated by Argon2id (~0.5 s at default params). Callers that sign
  frequently SHOULD unlock once and share the `SignerHandle` (e.g. in an `Arc`), not
  re-unlock per signature.

### 7.4 `change_password` / `rotate_kdf` (+ `_with_rng` variants)

Both decrypt with the current password, then re-encrypt with a **fresh random salt and
nonce** (so the output ciphertext differs even under an unchanged password), and write
the new file through the backend's atomic write. `change_password` keeps the KDF
params; `rotate_kdf` keeps the password and replaces the params (validated per §4.1).
The secret itself never changes. On success the in-memory header is updated to match
the written file.

### 7.5 Accessors

- `header()` → the parsed `KeystoreHeader` (metadata inspection without a password).
- `path()` → the `BackendKey`.
- `cached_public_key()` → `Some(pk)` only if this process has created or unlocked the
  keystore; otherwise `None`. Reading the public key from a cold file REQUIRES an
  unlock (the format stores no plaintext public key).
- `Debug` for `Keystore` prints scheme name, path, and KDF params — never key material.

---

## 8. `SignerHandle<K>` — the signing surface

`SignerHandle<K>` owns a `Zeroizing<Vec<u8>>` copy of the decrypted secret plus the
public key derived at unlock time.

| Method | Semantics |
|---|---|
| `public_key() -> &K::PublicKey` | Borrow the cached public key; no crypto cost. |
| `sign(msg: &[u8]) -> K::Signature` | Sign via `K::sign` (BLS AugScheme for shipped schemes). Infallible in practice — the handle's secret length is validated at construction; an internal length error would panic. |
| `try_sign(msg) -> Result<K::Signature>` | Fallible variant surfacing scheme errors instead of panicking. `sign` and `try_sign` MUST produce identical signatures for the same input. |
| `expose_secret() -> &[u8]` | Borrow the raw seed bytes. The **only** secret escape hatch (see below). |

**Secret containment (normative).**

- `SignerHandle` MUST NOT implement `AsRef<[u8]>`, `Deref` to the secret, or any owned
  `into_raw()`-style extractor.
- `expose_secret` exists solely for HD-wallet consumers that need the master seed to
  derive child keys (e.g. `chia_bls::SecretKey::from_seed(handle.expose_secret())` then
  `DerivableKey` derivation). It returns a **borrow** tied to the handle's lifetime —
  the bytes are wiped when the handle drops. Callers MUST NOT copy the bytes into a
  non-zeroizing buffer.
- `Clone` deep-copies the zeroizing buffer; each clone wipes independently on drop and
  produces byte-identical signatures.
- `Debug` MUST redact the secret (it prints `<N bytes zeroized>`); the handle is safe
  to include in `tracing`/log output.
- Drop zeroizes the secret.

---

## 9. `Password`

- Internally `Zeroizing<Vec<u8>>`; the buffer is wiped on drop. `Clone` copies are
  wiped independently.
- Accepts **arbitrary bytes** (not just UTF-8) via `Password::new(impl AsRef<[u8]>)`
  and `From<&str> / From<String> / From<&[u8]> / From<Vec<u8>>`. The owning `From`
  impls (`String`, `Vec<u8>`) move the buffer into the zeroizing wrapper without an
  extra copy. No normalization, trimming, or case-folding is applied — the KDF hashes
  the caller's bytes verbatim.
- Empty passwords are **permitted** by this layer (Argon2id hashes them); rejecting
  them is the calling binary's responsibility.
- `Debug` MUST redact content (prints `Password(<N> bytes)`).
- `strength()` (feature `password-strength` only) returns a zxcvbn score for CLI
  prompts; non-UTF-8 passwords are conservatively scored as the empty string and MUST
  NOT panic. It is a UX aid, not a security guarantee.

---

## 10. Storage backends

### 10.1 `BackendKey`

An opaque `String` newtype addressing one blob within a backend
(`new`, blanket `From<Into<String>>`, `as_str`, `Display`; `Eq + Hash`).

### 10.2 `KeychainBackend` trait (contract)

```rust
pub trait KeychainBackend: Send + Sync + 'static {
    fn read(&self, key: &BackendKey) -> Result<Vec<u8>>;
    fn write(&self, key: &BackendKey, data: &[u8]) -> Result<()>;
    fn delete(&self, key: &BackendKey) -> Result<()>;
    fn list(&self, prefix: &str) -> Result<Vec<BackendKey>>;
    fn exists(&self, key: &BackendKey) -> Result<bool> { /* default via read */ }
}
```

Implementations MUST satisfy:

- **`read` of a missing key** returns `KeystoreError::Backend` wrapping an
  `std::io::Error` of kind `NotFound`. This exact shape is load-bearing: the default
  `exists` and `Keystore::create`'s overwrite guard branch on it. (`Ok(true)` when a
  read succeeds; `Ok(false)` on `NotFound`; any other error propagates.)
- **`write` is atomic**: a concurrent reader observes either the old bytes or the new
  bytes in full — never a torn mix. Overwriting an existing key replaces it.
- **`delete` is idempotent**: deleting an absent key succeeds. Implementations SHOULD
  best-effort overwrite storage before removal.
- **`list(prefix)`** returns keys whose names **start with** `prefix` (strict prefix,
  not substring); order unspecified; empty prefix lists all.

### 10.3 `FileBackend` (feature `file-backend`, on by default)

- Maps `BackendKey` → `<root>/<key>.dks` (`.dks` = "DIG KeyStore").
- **Lazy root creation:** `FileBackend::new(root)` has no side effects; the root
  directory (and parents) is created on the first `write`, with mode `0700` on Unix.
- **Atomic write procedure (normative):** write to a sibling
  `<key>.dks.tmp.<random16hex>` (mode `0600` on Unix) → `fsync` the file → `rename`
  onto the final name → on Unix, `fsync` the containing directory. On rename failure
  the tmp file is best-effort unlinked. The tmp-name random suffix is
  non-cryptographic (time × golden-ratio-prime + pid) and exists only to disambiguate
  concurrent writers.
- **Delete:** no-op if absent; otherwise best-effort single-pass zero-overwrite (4 KiB
  chunks) + `fsync`, then unlink. The zero pass is explicitly best-effort — SSD FTLs
  and CoW filesystems may retain old sectors; operators needing stronger guarantees
  MUST use full-disk encryption.
- **List:** scans the root (empty result if the root does not exist), skipping
  non-`.dks` and non-UTF-8 names, returning the extension-stripped stems matching the
  prefix.
- **Exists:** cheap `stat`-based override.
- Windows: `std::fs::rename` (`MoveFileExW` + `MOVEFILE_REPLACE_EXISTING`) provides
  old-or-new (never torn) semantics; Unix file permissions do not apply and NTFS ACL
  inheritance governs access.

### 10.4 `MemoryBackend` (always available)

A `Mutex<HashMap>`-backed backend compiled unconditionally (since v0.1.2). Legitimate
uses: **scratch backend** for encrypt-to-bytes/decrypt-from-bytes adapters (notably
`dig-l1-wallet`'s encryption helpers, which reuse the full §3 file format in memory),
tests, and doc examples. It MUST NOT be used as durable storage — process exit drops
all state. It satisfies the full §10.2 contract, including the `NotFound` error shape.

---

## 11. Errors

All fallible operations return `Result<T> = Result<T, KeystoreError>`. `KeystoreError`
is `Clone` (the `std::io::Error` is `Arc`-wrapped) so errors can traverse channels.

| Variant | Meaning / when |
|---|---|
| `Backend(Arc<io::Error>)` | Backend I/O failure; preserves the `io::ErrorKind` (see §10.2). |
| `UnknownMagic { saw: [u8; 6] }` | First 6 bytes are not a known magic (§3.2 step 3). |
| `UnsupportedFormat { found: u16 }` | Format version ≠ `0x0001` (step 4). |
| `SchemeMismatch { expected, expected_name, found }` | File's magic/scheme id disagrees with the `K` type parameter (§3.3). |
| `CrcMismatch { stored, computed }` | Footer CRC-32 disagreement (step 2). Corruption/tamper fast-fail, not a security check. |
| `DecryptFailed` | Any AES-GCM authentication failure: wrong password, tampered ciphertext, tampered header/AAD. Deliberately undifferentiated (§5). |
| `InvalidKdfParams(&'static str)` | KDF params outside §4.1 bounds, or the Argon2 backend rejected them. |
| `UnsupportedKdf(u8)` | KDF id ≠ `0x01` (step 5). |
| `UnsupportedCipher(u8)` | Cipher id ≠ `0x01` (step 6). |
| `AlreadyExists(String)` | `create` at an occupied key (§7.1). |
| `InvalidPlaintext { expected, got }` | Secret/plaintext length ≠ `K::SECRET_LEN` (create input, unlock output, or scheme call). |
| `InvalidSeed(String)` | Reserved for schemes with byte-validity constraints; not produced by the shipped BLS schemes. |
| `Truncated { claimed, available }` | File shorter than its own accounting (steps 1 and 7). |

Error `Display` strings MUST NOT contain secret material.

---

## 12. Security properties

| Property | Mechanism | Guarantee level |
|---|---|---|
| Confidentiality at rest | AES-256-GCM under an Argon2id password-derived key | Cryptographic |
| Integrity / tamper evidence | 128-bit AES-GCM tag with the 53-byte header as AAD | Cryptographic |
| Offline brute-force cost | Argon2id ≥ 8 MiB (default 64 MiB / 3 / 4); per-file random 16-byte salt defeats precomputation | Cryptographic (password-strength-dependent) |
| Wrong-password vs tamper indistinguishability | Single `DecryptFailed` for all auth failures | Design invariant |
| Fast-fail on corruption | Outer CRC-32 before any KDF work | Non-security convenience |
| In-memory hygiene | `Zeroizing` on passwords, generated seeds, decrypted plaintexts, derived KDF keys, and the `SignerHandle` secret; wipe on drop | Best effort (see non-guarantees) |
| No secret leakage via `Debug`/logs | Custom redacting `Debug` on `Password` and `SignerHandle`; errors carry no secrets | Design invariant |
| Secret containment | No `AsRef`/`Deref`/`into_raw` on `SignerHandle`; `expose_secret` is the single named, borrow-only escape hatch | Design invariant |
| Crash-safe persistence | tmp + fsync + atomic rename (+ Unix dir fsync) in `FileBackend` | OS-level |
| File-system access control | Unix mode `0700` dir / `0600` files | Unix only |
| Memory safety | `unsafe_code = "forbid"` crate-wide | Compiler-enforced |

**Non-guarantees (explicit).**

- A process with the same privileges (or root / a debugger / memory-read access) can
  extract an unlocked secret from RAM. No software-only mitigation exists; this crate
  does **not** `mlock`/`VirtualLock` buffers, and the OS may swap them.
- A stolen keystore file plus a weak password is brute-forceable; Argon2id raises the
  cost but cannot rescue a guessable password. Use `KdfParams::STRONG` for high-value
  keys.
- `FileBackend::delete`'s zero-overwrite may not reach physical sectors (SSD FTL, CoW
  filesystems).
- `Zeroizing` is best-effort against compiler optimization and paging.

---

## 13. Public API surface (summary)

Root re-exports (crate `dig-keystore`, importable as `dig_keystore`):

- `Keystore<K>` — §7. `SignerHandle<K>` — §8. `Password` — §9.
- `KeyScheme`, `scheme::{BlsSigning, L1WalletBls}` — §6.
- `KeychainBackend`, `BackendKey`, `MemoryBackend`; `FileBackend` (feature
  `file-backend`) — §10.
- `KeystoreHeader`, `KdfParams`, `KdfId`, `CipherId`, `FORMAT_VERSION_V1` — §3–4.
- `KeystoreError`, `Result` — §11.
- `bls` module — convenience re-exports of `chia_bls::{sign, verify, PublicKey,
  SecretKey, Signature}` so simple consumers need no direct `chia-bls` dependency.
- `testing` module (feature `testing`) — re-exports `MemoryBackend` and the constant
  `TEST_PASSWORD = "dig-keystore-test-password"` for dependent crates' tests.

- `opaque` module — `seal`, `seal_with_rng`, `open`, `verify_password`, `MAGIC`, `SCHEME_ID`
  — §15.

### 13.1 Feature flags

| Flag | Default | Effect |
|---|---|---|
| `file-backend` | **on** | Ships `FileBackend`. |
| `password-strength` | off | `Password::strength()` via zxcvbn. |
| `testing` | off | `testing` module (`MemoryBackend` re-export + `TEST_PASSWORD`); required by the integration-test suite. |
| `eip2335` | off | **Reserved, no-op** — EIP-2335 import/export is not implemented. |
| `chia-keychain` | off | **Reserved, no-op** — Chia `.keychain` import is not implemented. |

There is no `wasm` feature on THIS package — the WebAssembly binding is a separate sibling
crate/package, `dig-keystore-wasm` (§16), so this crate's own feature set and dependency graph
are completely unaffected by wasm support existing.

### 13.2 Crate lints / MSRV

`unsafe_code = "forbid"`, `missing_docs = "warn"`. MSRV 1.70. License
`Apache-2.0 OR MIT`. This applies to the `dig-keystore` package only; the sibling
`dig-keystore-wasm` package (§16) has its own, looser lint posture because wasm-bindgen's
generated glue code is not `forbid(unsafe_code)`-clean — see §16.1.

---

## 14. Conformance

### 14.1 Cross-repo requirements

| Contract | Must match | Where |
|---|---|---|
| BLS signing algorithm | Chia's BLS12-381 AugScheme (`chia-bls` 0.26; `SecretKey::from_seed` + `chia_bls::sign`) — signatures MUST verify with `chia_bls::verify` and interoperate with Chia L1 `AGG_SIG` semantics | §6.2 |
| Default KDF cost | `dig-l1-wallet` uses the same Argon2id 64 MiB / 3 / 4 default, so both crates present a uniform offline-attack cost | §4.2 |
| Keystore byte format | `dig-l1-wallet`'s encrypt/decrypt-bytes helpers wrap `MemoryBackend` and reuse the §3 format verbatim — the bytes they produce are valid keystore files byte-for-byte | §3, §10.4 |
| File format stability | Every v1 file ever written MUST remain readable by all future releases (additive-only evolution; version-dispatched decoding) | §3.4 |

### 14.2 Conformance summary table

| # | Requirement | Spec |
|---|---|---|
| C-1 | File layout exactly per §3: 53-byte BE header, `ciphertext‖tag`, trailing IEEE CRC-32 | §3 |
| C-2 | Header bytes bound as AES-GCM AAD on encrypt and decrypt | §3.1 |
| C-3 | Decode order: length → CRC → magic → version → KDF id → cipher id → payload bounds → crypto | §3.2 |
| C-4 | Magic AND scheme id both checked against `K`; mismatch is a hard error | §3.3 |
| C-5 | Argon2id v0x13, 32-byte output; params validated within §4.1 bounds on every derivation | §4 |
| C-6 | AES-256-GCM, 12-byte nonce, 16-byte appended tag; fresh salt+nonce per encryption | §5 |
| C-7 | All decrypt failures collapse to `DecryptFailed` | §5, §11 |
| C-8 | Secrets are 32-byte seeds; BLS keys via `from_seed`; signing via AugScheme | §6.2 |
| C-9 | `create` never overwrites (`AlreadyExists`); `unlock` re-reads from the backend | §7 |
| C-10 | Password/KDF rotation re-encrypts under fresh salt+nonce, secret unchanged | §7.4 |
| C-11 | `SignerHandle`: no secret extraction except borrow-only `expose_secret`; redacting `Debug`; zeroize on drop | §8 |
| C-12 | `Password`: arbitrary bytes verbatim, zeroizing, redacting `Debug` | §9 |
| C-13 | Backend contract: `NotFound` error shape, atomic write, idempotent delete, strict-prefix list | §10.2 |
| C-14 | `FileBackend`: `<root>/<key>.dks`, lazy 0700 root, 0600 tmp+fsync+rename writes, best-effort zero-wipe delete | §10.3 |
| C-15 | No `unsafe` code anywhere in the crate | §13.2 |
| C-16 | CI gates: `cargo fmt --check`, `clippy -D warnings`, full test suite under `cargo llvm-cov --all-features --fail-under-lines 80` | repo `.github/workflows/publish.yml` |

### 14.3 Test evidence

The repository's test suite pins these requirements: header/file round-trip and the
53-byte constant, every decode-order rejection, AAD binding, CRC coverage, KDF
determinism and bounds, wrong-password/tamper behavior (`tests/tamper.rs`,
`tests/wrong_password.rs`), full create→load→unlock→sign round-trips per scheme
(`tests/roundtrip.rs`), deterministic known-answer vectors (`tests/vectors.rs`),
backend contract branches (`tests/keystore_branches.rs`, module tests), and the
no-leak `Debug` impls. A change that alters any behavior in this document MUST come
with a corresponding test change, and format changes MUST keep old fixtures decoding
byte-identically.

---

## 15. `opaque` — arbitrary-length password-sealed secrets

### 15.1 Motivation and scope

`Keystore<K: KeyScheme>` (§7) requires a fixed `K::SECRET_LEN` and a typed public-key
derivation. That fits validator/wallet seeds (always 32 bytes) but not every secret a DIG
binary or browser client needs to protect at rest — e.g. BIP-39 entropy (16/20/24/28 bytes
depending on word count), or any other opaque application blob with no public-key concept.
`opaque` provides bytes-in/bytes-out password sealing for a secret of **any** length
(including zero), reusing the exact same container format as §3 rather than defining a new
one.

`opaque` is the primitive `dig-keystore-wasm` (§16) wraps for the DIG Chrome extension's
vault (dig_ecosystem #147).

### 15.2 Container identity (normative)

A blob produced by `opaque::seal` / `opaque::seal_with_rng` MUST be a byte-for-byte valid §3
container: the same 53-byte header, the same AES-256-GCM ciphertext+tag payload, the same
trailing CRC-32, the same header-as-AAD binding (§3.1). The ONLY distinguishing fields are:

| Field | Value |
|---|---|
| `MAGIC` | `DIGOP1` |
| `SCHEME_ID` | `0x0004` |

`crate::format::is_known_magic` recognizes `DIGOP1` in addition to `DIGVK1`/`DIGLW1`; this
registration is purely additive and changes nothing about how the two `KeyScheme` magics are
recognized or decoded (§5.1 backwards-compat spirit; §3.4).

### 15.3 API (normative)

```rust
pub const MAGIC: [u8; 6] = *b"DIGOP1";
pub const SCHEME_ID: u16 = 0x0004;

pub fn seal(password: &Password, secret: &[u8], kdf_params: KdfParams) -> Result<Vec<u8>>;
pub fn seal_with_rng<R: RngCore + CryptoRng>(
    password: &Password, secret: &[u8], kdf_params: KdfParams, rng: &mut R,
) -> Result<Vec<u8>>;
pub fn open(password: &Password, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
pub fn verify_password(password: &Password, blob: &[u8]) -> bool;
```

- `seal` MUST accept `secret` of any length, including empty, and MUST NOT truncate, pad, or
  otherwise transform it — `open` MUST recover the exact original bytes.
- `seal` uses OS randomness (`rand_core::OsRng`) for the salt + nonce; `seal_with_rng` exists
  for deterministic test fixtures only (production callers MUST use `seal`).
- `open` MUST reject a blob whose `MAGIC`/`SCHEME_ID` are not `DIGOP1`/`0x0004` with
  `KeystoreError::SchemeMismatch` — including a well-formed `DIGVK1`/`DIGLW1` `Keystore<K>`
  file. This is the same type-confusion protection §3.3 gives typed schemes.
- `open` MUST fail with `KeystoreError::DecryptFailed` for a wrong password or any tampering
  (ciphertext or header/AAD), per the same indistinguishability rule as §5.
- `opaque` has no `KeychainBackend` concept — it is pure bytes-in/bytes-out. Callers own
  storage (a file, a database row, `chrome.storage.local`, …) themselves.
- `verify_password` MUST run the full KDF + AEAD verification and return only a `bool`,
  never exposing the secret on success or failure.

### 15.4 Conformance

| # | Requirement |
|---|---|
| O-1 | `opaque::seal` output is a byte-for-byte valid §3 container with `MAGIC=DIGOP1`, `SCHEME_ID=0x0004` |
| O-2 | `seal` → `open` recovers the exact original secret bytes for any length, including empty |
| O-3 | `open` rejects a `DIGVK1`/`DIGLW1` blob (or any other magic) with `SchemeMismatch` |
| O-4 | `open` collapses wrong-password and tamper failures to `DecryptFailed` (§5) |
| O-5 | `is_known_magic` recognizes `DIGOP1` additively — `DIGVK1`/`DIGLW1` decoding is unchanged |

Test evidence: `src/opaque.rs` unit tests, `tests/opaque_vectors.rs` (public-API-level KAT).

---

## 16. `dig-keystore-wasm` — WebAssembly binding (npm)

### 16.1 Package layout (normative)

The WebAssembly binding is a SEPARATE crate/package, `dig-keystore-wasm`, living at `wasm/`
in this repository as a Cargo workspace member (root `Cargo.toml` gains `[workspace]
members = ["wasm"] default-members = ["."]` — `default-members` keeps every bare `cargo
<cmd>` invocation, including this repo's own CI and `cargo publish`, scoped to the
`dig-keystore` package exactly as before; the wasm crate requires an explicit `-p
dig-keystore-wasm`).

It is NOT a `wasm` feature on the `dig-keystore` package itself. Reason: this package's
`unsafe_code = "forbid"` (§13.2) is a spec-pinned, tested security property (conformance
C-15, "no unsafe code anywhere in the crate"), and wasm-bindgen's generated glue is not
`forbid`-clean. Keeping the binding in a separate package means `dig-keystore` itself stays
byte-for-byte unaffected — no new dependencies, no relaxed lints, no format change — while
`dig-keystore-wasm` is free to carry the wasm-bindgen toolchain's own constraints.

`dig-keystore-wasm` has `crate-type = ["cdylib", "rlib"]`, is `publish = false` on
crates.io, and publishes to npm as `@dignetwork/dig-keystore-wasm` via `wasm-pack build
--target bundler` (git-dep / local-path consumable regardless of npm publish status — see
§16.4).

### 16.2 Exported surface (normative)

| JS export | Signature | Semantics |
|---|---|---|
| `init()` | `() -> void` | Installs a panic hook (feature `console-panic-hook`, default on) so a Rust panic surfaces a real message in the browser/Node console. Optional; idempotent. |
| `seal(password, secret)` | `(string, Uint8Array) -> Uint8Array`, throws | Direct call to `opaque::seal` with `KdfParams::DEFAULT`. `secret` may be any length, including empty. |
| `open(password, blob)` | `(string, Uint8Array) -> Uint8Array`, throws | Direct call to `opaque::open`. Throws (rejects) with the `KeystoreError` `Display` string on wrong password, tampering, or a non-opaque blob (§15.3). |
| `verifyPassword(password, blob)` | `(string, Uint8Array) -> boolean` | Direct call to `opaque::verify_password`. Never throws. |
| `sealStrong(password, secret)` | `(string, Uint8Array) -> Uint8Array`, throws | Direct call to `opaque::seal` with `KdfParams::STRONG` (256 MiB / 4 iterations / 4 lanes) instead of `DEFAULT` — for a caller's high-value-secret option (dig_ecosystem #147 Phase B: the extension's `ARGON2_STRONG` wallet preset). Opened by the SAME `open` as a `seal`-produced blob; the preset is recorded in the blob's own self-describing header, not tracked by the caller. |
| `sealWithSeed(password, secret, seed)` | `(string, Uint8Array, bigint) -> Uint8Array`, throws | **Test/fixture-only.** Deterministic `ChaCha20Rng::seed_from_u64(seed)` seal at `KdfParams::FAST_TEST`, for cross-target KAT proofs only (§16.3). MUST NOT be used to seal a real secret — the RNG is trivially predictable. |

Every real export (`seal`/`sealStrong`/`open`/`verifyPassword`) is a **direct, non-branching** call into
`dig_keystore::opaque` — no wasm-specific crypto logic exists in `dig-keystore-wasm`. There
is deliberately no `KeychainBackend`/`FileBackend`/`MemoryBackend` binding: the file and
OS-keychain backends have no meaning in a browser, and `seal`/`open` are already
bytes-in/bytes-out, so the JS caller owns storage (e.g. `chrome.storage.local`) directly.

Error values thrown from `seal`/`open` are plain strings built from `KeystoreError::Display`
(§11), which never contains secret material or the password.

### 16.3 Native ↔ wasm byte compatibility (normative)

Because `dig-keystore-wasm`'s exports are direct, non-branching calls into `opaque::seal`/
`opaque::open` — the identical Rust source compiled for `wasm32-unknown-unknown` with no
`cfg(target_arch)` fork — a blob sealed on one target MUST open identically on the other.
This is pinned empirically by a shared deterministic known-answer vector (fixed seed,
password, secret) asserted identical in BOTH:

- `tests/opaque_vectors.rs` (native, calls `opaque::seal_with_rng` directly), and
- `wasm/tests/opaque_wasm.rs` (`wasm-bindgen-test`, calls `sealWithSeed`),

using the same concrete RNG (`rand_chacha::ChaCha20Rng`, NOT `rand::StdRng` — a different
algorithm that would silently break the vector despite an identical numeric seed). Both
suites additionally decode the other's fixture: the native suite opens the wasm-shaped hex
constant and vice versa. This is the property Phase B (dig_ecosystem #147 — migrating the
extension's vault) depends on to prove old blobs stay readable across a native/wasm boundary.

### 16.4 Publishing (normative)

- `wasm/package.json` is a private, non-published dev harness (`wasm-pack build`/`test`
  script wrapper). The PUBLISHED package is `wasm/pkg/package.json`, generated by `wasm-pack
  build --target bundler` from `wasm/Cargo.toml`, then rewritten by
  `wasm/scripts/patch-pkg.mjs` to the scoped name `@dignetwork/dig-keystore-wasm` with
  `publishConfig.access = "public"`.
- `.github/workflows/publish-npm.yml` builds + publishes on a `v*` tag push, a published
  GitHub Release, or manual dispatch, authenticating via npm Trusted Publishing (OIDC) — no
  `NPM_TOKEN` secret is used.
- **Known gap (dig_ecosystem #70-adjacent):** npm's trusted-publisher config can only be
  attached to a package that already exists on the registry, so the FIRST publish of this
  brand-new scoped name 404s even with OIDC correctly wired (confirmed: the `v0.2.1`
  `publish-npm` run authenticated fine and still got `404 Not Found - PUT
  .../@dignetwork%2fdig-keystore-wasm`) — an org-admin bootstrap (one manual authenticated
  `npm publish` to create the package) is needed before OIDC publishing can take over. This
  does NOT block consuming `dig-keystore-wasm`: it is buildable and usable as a git/path
  dependency (`wasm-pack build` locally, or vendoring the built `wasm/pkg` output into a
  consuming repo as a local/`file:` dependency) in the interim, the same stopgap
  `@dignetwork/chia-provider` and `@dignetwork/chip35-dl-coin-wasm` use. The dig-chrome-extension
  (dig_ecosystem #147 Phase B) vendors the built `pkg/` output this way.

### 16.5 Conformance

| # | Requirement |
|---|---|
| W-1 | `dig-keystore-wasm` builds cleanly for `wasm32-unknown-unknown` (`cargo clippy -p dig-keystore-wasm --target wasm32-unknown-unknown -- -D warnings`) |
| W-2 | `dig-keystore`'s own build/lints/format/dependency graph are unaffected by `dig-keystore-wasm` existing (§13.1, §13.2) |
| W-3 | `seal`/`sealStrong`/`open`/`verifyPassword` are direct calls into `opaque::*` — no divergent wasm-only crypto path |
| W-4 | The native↔wasm KAT vector (§16.3) matches byte-for-byte in both `tests/opaque_vectors.rs` and `wasm/tests/opaque_wasm.rs` |
| W-5 | `sealWithSeed` is documented test/fixture-only and MUST NOT be reachable from a production seal path |
| W-6 | `sealStrong`-produced blobs round-trip through the same `open` as `seal`-produced blobs (`wasm/tests/opaque_wasm.rs::seal_strong_roundtrip`) |

Test evidence: `wasm/tests/opaque_wasm.rs` (`wasm-bindgen-test`, run via `wasm-pack test
--node`), cross-checked against `tests/opaque_vectors.rs`.

