# dig-keystore — Development Log

Concise, durable realizations from developing this crate. Context, not a change diary.

## OS credential store (`OsKeychainBackend`, feature `os-keychain`)

- **`keyring` is target-gated to Windows/macOS only — never Linux, never wasm.** It lives in a
  `[target.'cfg(any(target_os = "windows", target_os = "macos"))'.dependencies]` table as an
  `optional` dep, and the `os-keychain` feature activates it via `dep:keyring`. Cargo resolves
  `dep:` against a target-only optional dependency correctly: on Linux/wasm the feature is a no-op
  for that dep (verified — `cargo check --target x86_64-unknown-linux-gnu --features os-keychain`
  resolves features with no keyring in the graph; only a missing C cross-linker for `blst` stops a
  full host cross-build). This keeps CI free of dbus/libsecret and keeps the wasm member building.

- **Linux is deliberately excluded as a custody primary, not an oversight.** The kernel keyutils
  session keyring is readable by any same-UID process (no per-application ACL) and is non-persistent
  across reboot/logout — unsafe for custody and would lose the identity on logout. On Linux the
  passphrase-sealed file backend is the correct primary. This rationale is inherited from dig-app's
  original `OsCredentialStore`, which this backend absorbs so the ecosystem keeps one keystore impl.

- **The OS ACL is the access-control primitive; DIGVK1/DIGOP1 sealing is defence-in-depth under it.**
  An attacker who defeats the per-app ACL and dumps the entry gets the ciphertext; the sealing adds a
  layer against a raw at-rest artifact but is not a second independent secret on this path.

- **OS credential stores have no native enumeration.** `list` is powered by a best-effort index
  entry (a reserved account, `__dig_keystore_index__`) holding the live key set. `read`/`write`/
  `delete`/`exists` hit the store directly and are authoritative — index/store drift can only stale a
  `list`, never corrupt a read or write. The `RawStore` inner trait makes all of this testable with
  an in-memory double on every platform; the real OS path is covered by a self-skipping integration
  test (skips where no backend, so it is never flaky).

- **Use `keyring` v3's binary secret API (`get_secret`/`set_secret`), not `get_password`/`set_password`.**
  Keystore blobs are raw ciphertext (`Vec<u8>`); the binary API avoids any textual re-encoding of the
  bytes. (dig-app used the password API because it stored base64 strings; here the value is binary.)
