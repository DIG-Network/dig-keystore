# dig-keystore-hardware

Platform trusted-component providers for [`dig-keystore`](https://crates.io/crates/dig-keystore).

`dig-keystore` defines the `HardwareProvider` seam and the `DIGHW1` envelope but ships no
binding to real silicon: it sets `unsafe_code = "forbid"` as a spec-pinned security property
(`SPEC.md` §12/§13.2, conformance C-15), and every platform trusted-component API is FFI.
This crate is where that FFI lives, so the forbid stays intact in the crate that holds the
key material.

## What it buys

A wrapping key created inside the host trusted component and **non-exportable from it**, so
copying a sealed keystore to another machine does not let an attacker open it.

## The ladder

| rung | protection | where |
|---|---|---|
| 1 | host trusted component, non-exportable wrapping key | this crate |
| 2 | OS credential store | `dig_keystore::OsKeychainBackend` |
| 3 | AES-256-GCM + Argon2id passphrase envelope — **the floor** | `dig_keystore` |

Rung 3 is never skipped. Hardware wrapping is an outer envelope around an already-sealed
blob, so a host with no trusted component writes exactly the bytes it always wrote — never a
bare file.

## Platform status

| platform | status |
|---|---|
| Windows | **implemented** — TPM 2.0 through the CNG *Microsoft Platform Crypto Provider* |
| macOS | not implemented — reports `PlatformUnsupported` |
| Linux | not implemented — reports `PlatformUnsupported` |

An unimplemented platform degrades and **says so with a reason naming this build**, never as
`NoHardwarePresent` — that would be a confident claim about a machine nothing inspected.

## Usage

```rust,no_run
use dig_keystore::backend::FileBackend;
use dig_keystore::hardware::HardwarePolicy;

let backend = dig_keystore_hardware::bind_strongest(
    FileBackend::new("/var/lib/dig/keys"),
    HardwarePolicy::Preferred,
)?;
println!("this host: {}", backend.tier());
# Ok::<(), dig_keystore::KeystoreError>(())
```

## Testing

The ladder is platform-independent and runs everywhere — it is the code that executes on
hosts *without* a trusted component, which is most of them.

Assertions that need real silicon live in `tests/windows_tpm.rs` and are binding only under
`DIG_KEYSTORE_REQUIRE_TPM=1`, which turns an absent TPM into a failure rather than a skip:

```sh
DIG_KEYSTORE_REQUIRE_TPM=1 cargo test -p dig-keystore-hardware
```

Unset, those tests still run, assert the complementary unbound-host properties, and print
which properties they did **not** exercise. A pass without the variable means "the degraded
path is correct", never "the TPM path is correct".

## License

Apache-2.0 OR MIT
