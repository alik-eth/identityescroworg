#!/usr/bin/env node
// Drift-check for the @qkb/circuits source code vendored under
// `src/witness/v5/`.
//
// Why vendored: @qkb/circuits is Node-flavoured (`node:crypto`,
// `require('ethers/lib/utils')`, `require('circomlibjs')`), so the V5
// register flow can't import it directly in a browser bundle. Web-eng
// vendored a copy with three byte-equivalent patches (sha256 lib swap,
// keccak lib swap, CJS-require → ES-import).
//
// We use a SHA-256 fingerprint of each circuits-side source file rather
// than a full-text diff — text-level diffs over-report on stylistic
// drift (comments, whitespace) that doesn't affect the witness shape.
// The lockfile records "what version of arch-circuits the vendored copy
// was last synced from"; running this script re-hashes the upstream
// source and reports any file whose hash drifted.
//
// When drift fires, the maintainer's job is to:
//   1. Read the updated arch-circuits source.
//   2. Re-apply the three known browser patches manually (or via the
//      `--apply-patches` hint at the bottom of this file's PATCHES
//      table).
//   3. Re-run with `--update-lock` to bless the new version.
//
// Resolves arch-circuits via the QKB_CIRCUITS_SRC env var or the
// hard-coded sibling worktree at `/data/Develop/qkb-wt-v5/arch-circuits`.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = resolve(HERE, '..');
const LOCK_PATH = resolve(SDK_ROOT, 'scripts/circuits-vendor.lock.json');

const CIRCUITS_ROOT =
  process.env.QKB_CIRCUITS_SRC ??
  '/data/Develop/qkb-wt-v5/arch-circuits/packages/circuits';

if (!existsSync(CIRCUITS_ROOT)) {
  console.error(
    `[drift-check] circuits source not found at ${CIRCUITS_ROOT}.\n` +
      `Set QKB_CIRCUITS_SRC to the @qkb/circuits package root.`,
  );
  process.exit(2);
}

// Tracked source files (relative to @qkb/circuits package root).
const FILES = [
  'src/types.ts',
  'src/binding-offsets.ts',
  'src/leaf-cert-walk.ts',
  'src/limbs.ts',
  'src/poseidon-chunk-hash.ts',
  'src/parse-p7s.ts',
  'src/build-witness-v5.ts',
  'scripts/spki-commit-ref.ts',
];

// Patches applied to the vendored copy after fresh-sync. Keep this list
// in lockstep with the actual edits in `src/witness/v5/`. If
// circuits-eng lands a patch eliminating one of these (e.g. ES-import
// for circomlibjs), drop the entry here and re-run --update-lock.
const PATCHES_README = [
  '1. node:crypto.createHash("sha256")  →  @noble/hashes/sha2.sha256',
  '2. require("ethers/lib/utils").keccak256  →  @noble/hashes/sha3.keccak_256',
  '3. require("circomlibjs")  →  import { buildPoseidon } from "circomlibjs"',
  '4. node:buffer (in imports)  →  buffer (resolves via vite-plugin-node-polyfills)',
  '5. import { Buffer } from "buffer"  →  import { Buffer } from "./_buffer-global"',
];

function sha256(text) {
  return createHash('sha256').update(text).digest('hex');
}

function loadLock() {
  if (!existsSync(LOCK_PATH)) return { hashes: {} };
  return JSON.parse(readFileSync(LOCK_PATH, 'utf8'));
}

function saveLock(lock) {
  writeFileSync(LOCK_PATH, JSON.stringify(lock, null, 2) + '\n');
}

const updateLock = process.argv.includes('--update-lock');

const lock = loadLock();
const newHashes = {};
let drift = 0;
let synced = 0;

for (const rel of FILES) {
  const path = resolve(CIRCUITS_ROOT, rel);
  if (!existsSync(path)) {
    console.error(`[drift-check] circuits source missing: ${rel}`);
    drift++;
    continue;
  }
  const text = readFileSync(path, 'utf8');
  const hash = sha256(text);
  newHashes[rel] = hash;

  const prior = lock.hashes?.[rel];
  if (prior === undefined) {
    drift++;
    console.error(`[drift-check] NEW: ${rel} not in lockfile.`);
  } else if (prior !== hash) {
    drift++;
    console.error(`[drift-check] DRIFT: ${rel}`);
    console.error(`   prior:   ${prior}`);
    console.error(`   current: ${hash}`);
  } else {
    synced++;
  }
}

if (updateLock) {
  const newLock = {
    note:
      'SHA-256 fingerprints of @qkb/circuits source files vendored under ' +
      'packages/sdk/src/witness/v5/. Update via `pnpm -F @qkb/sdk drift-check:update-lock`.',
    circuitsRoot: CIRCUITS_ROOT.replace(
      /^\/data\/Develop\/qkb-wt-v5\/arch-circuits/,
      '/data/Develop/qkb-wt-v5/arch-circuits',
    ),
    patchesApplied: PATCHES_README,
    hashes: newHashes,
  };
  saveLock(newLock);
  console.log(`[drift-check] lockfile updated: ${LOCK_PATH}`);
  process.exit(0);
}

if (drift === 0) {
  console.log(
    `[drift-check] all ${synced}/${FILES.length} circuits-side fingerprints match lockfile.`,
  );
  process.exit(0);
}

console.error(
  `\n[drift-check] ${drift} of ${FILES.length} files drifted.\n` +
    `   Re-sync the vendored copies under packages/sdk/src/witness/v5/, then\n` +
    `   bless the new fingerprints with:\n` +
    `       pnpm -F @qkb/sdk drift-check:update-lock\n` +
    `\n   The browser patches that MUST be re-applied to each fresh sync:\n` +
    PATCHES_README.map((p) => `     ${p}`).join('\n') +
    '\n',
);
process.exit(1);
