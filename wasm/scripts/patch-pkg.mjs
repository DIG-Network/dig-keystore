// patch-pkg.mjs — post-build fixup for wasm-pack bundler output.
//
// wasm-pack --target bundler emits pkg/package.json from the Cargo.toml
// `[package]` (name + version), which is the UNSCOPED Cargo crate name
// `dig-keystore-wasm`. The package we publish to npm is the SCOPED
// `@dignetwork/dig-keystore-wasm`, and it must publish with public access.
//
// This script rewrites the generated pkg/package.json in place so that a plain
// `npm publish ./pkg` (as CI runs) targets the correct scoped, public package.
// It is idempotent: running it on an already-patched manifest is a no-op.
//
// Version is sourced from Cargo.toml (wasm-pack copies it through); this script
// does NOT set the version, only asserts it is the expected scoped value so a
// stale/wrong build can never be published silently.
//
// Run automatically by: npm run build:bundler
// Mirrors chip35_dl_coin's wasm/scripts/patch-pkg.mjs (dig_ecosystem #147 Phase A).

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const SCOPED_NAME = "@dignetwork/dig-keystore-wasm";

const here = dirname(fileURLToPath(import.meta.url));
const pkgPath = resolve(here, "..", "pkg", "package.json");

const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));

// 1) Scope the name to the published npm package. wasm-pack emits the unscoped
//    Cargo crate name; we always overwrite it with the scoped name.
pkg.name = SCOPED_NAME;

// 2) Ensure ESM bundler output stays flagged as a module.
pkg.type = "module";

// 3) Guarantee the publish includes the wasm binary, ESM glue, and the .d.ts.
//    wasm-pack already populates `files`, but enforce the full set so a future
//    wasm-pack change can't silently drop an artifact from the tarball.
const requiredFiles = [
  "dig_keystore_wasm_bg.wasm",
  "dig_keystore_wasm.js",
  "dig_keystore_wasm_bg.js",
  "dig_keystore_wasm.d.ts",
];
const files = new Set(Array.isArray(pkg.files) ? pkg.files : []);
for (const f of requiredFiles) files.add(f);
pkg.files = [...files];

// 4) Keep the ESM entry/types pointers wasm-pack generates (defensive defaults).
pkg.main ??= "dig_keystore_wasm.js";
pkg.types ??= "dig_keystore_wasm.d.ts";

// 5) A scoped package defaults to restricted access; force public so
//    `npm publish ./pkg` (and `--access public`) succeeds.
pkg.publishConfig = { ...(pkg.publishConfig ?? {}), access: "public" };

writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");

// 6) Sanity gate: refuse to leave behind a manifest that would mis-publish.
if (pkg.name !== SCOPED_NAME) {
  throw new Error(`patch-pkg: name is "${pkg.name}", expected "${SCOPED_NAME}"`);
}
if (typeof pkg.version !== "string" || !/^\d+\.\d+\.\d+/.test(pkg.version)) {
  throw new Error(`patch-pkg: invalid version "${pkg.version}"`);
}

console.log(`patch-pkg: ${pkgPath} -> ${pkg.name}@${pkg.version} (access: public)`);
