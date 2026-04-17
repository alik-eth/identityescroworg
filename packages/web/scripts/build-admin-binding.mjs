#!/usr/bin/env node
// Build a Phase-1 QKB binding statement keyed to the admin pubkey, ready for
// the user to take to Diia Підпис and produce a real `.p7s` over.
//
//   pnpm binding:admin
//
// Sources:
//   - admin private key  ← repo-root .env  (ADMIN_PRIVATE_KEY)
//   - declaration text   ← fixtures/declarations/en.txt (raw bytes)
//   - binding builder    ← reimplemented inline against the canonical
//                          encoding rules in orchestration §4.1 (committed
//                          4784a95). The CANONICAL implementation lives at
//                          packages/web/src/lib/binding.ts; this script
//                          cannot import it directly because that module
//                          uses Vite's `?raw` suffix to embed the
//                          declaration, which Node/tsx don't understand.
//                          KEEP THE TWO IN SYNC — any change to encoding
//                          locks must update both files.
//
// Output:
//   - <repo-root>/binding.qkb.json — the JCS-canonicalized binding bytes,
//     ready to be loaded into the QES tool.
//
// The output file is gitignored. Re-run produces a fresh nonce + timestamp
// (so each run is a distinct binding); use the same .p7s only with the
// same binding.qkb.json that produced its messageDigest.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
import * as secp from '@noble/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import canonicalize from 'canonicalize';

const BINDING_VERSION = 'QKB/1.0';
const BINDING_SCHEME = 'secp256k1';
const PK_UNCOMPRESSED_LENGTH = 65;
const NONCE_LENGTH = 32;

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = findRepoRoot(here);

const adminKey = loadAdminKey(repoRoot);
const privBytes = hexToBytes(stripHex(adminKey));
if (privBytes.length !== 32) {
  console.error('error: ADMIN_PRIVATE_KEY must be 32 bytes hex (64 hex chars)');
  process.exit(1);
}

const pk = secp.getPublicKey(privBytes, false); // 65-byte uncompressed 0x04||x||y
if (pk.length !== PK_UNCOMPRESSED_LENGTH || pk[0] !== 0x04) {
  console.error('error: derived pubkey is not 65-byte uncompressed SEC1');
  process.exit(1);
}
const adminAddr = pubkeyToAddress(pk);

const nonce = new Uint8Array(randomBytes(NONCE_LENGTH));
const timestamp = Math.floor(Date.now() / 1000);

const declarationPath = resolve(repoRoot, 'fixtures/declarations/en.txt');
const declaration = readFileSync(declarationPath, 'utf8');

// Mirror packages/web/src/lib/binding.ts buildBinding + canonicalizeBinding.
const binding = {
  version: BINDING_VERSION,
  pk: '0x' + bytesToHex(pk),
  scheme: BINDING_SCHEME,
  declaration,
  timestamp,
  context: '0x',
  nonce: '0x' + bytesToHex(nonce),
  escrow_commitment: null,
};
const json = canonicalize(binding);
if (json === undefined) {
  console.error('error: canonicalize returned undefined');
  process.exit(1);
}
const bytes = new TextEncoder().encode(json);
const outPath = resolve(repoRoot, 'binding.qkb.json');
writeFileSync(outPath, bytes);

const sha256 = createHash('sha256').update(bytes).digest('hex');

console.log('admin-keyed binding written');
console.log('  path        :', outPath);
console.log('  bytes       :', bytes.length);
console.log('  sha256      : 0x' + sha256);
console.log();
console.log('  pk (uncomp.) : 0x' + bytesToHex(pk).slice(0, 20) + '… (65 bytes)');
console.log('  pkAddr (eth) :', adminAddr);
console.log('  scheme       :', binding.scheme);
console.log('  declaration  : en (' + binding.declaration.length + ' chars)');
console.log('  declHash     : 0x' + sha256Of(new TextEncoder().encode(binding.declaration)));
console.log('  timestamp    :', timestamp, '(' + new Date(timestamp * 1000).toISOString() + ')');
console.log('  context      :', binding.context);
console.log('  nonce        : 0x' + bytesToHex(nonce));
console.log('  escrow       :', binding.escrow_commitment);
console.log('  version      :', binding.version);
console.log();
console.log('next: take', outPath, 'to Diia Підпис; sign as detached CAdES;');
console.log('      bring back binding.qkb.json + binding.qkb.json.p7s.');

function loadAdminKey(root) {
  if (process.env.ADMIN_PRIVATE_KEY) return process.env.ADMIN_PRIVATE_KEY;
  const envPath = resolve(root, '.env');
  if (!existsSync(envPath)) {
    console.error('error: ADMIN_PRIVATE_KEY not in env and no .env at', envPath);
    process.exit(1);
  }
  for (const raw of readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const k = line.slice(0, eq).trim();
    if (k !== 'ADMIN_PRIVATE_KEY') continue;
    let v = line.slice(eq + 1).trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    if (v.length === 0) {
      console.error('error: ADMIN_PRIVATE_KEY is empty in', envPath);
      process.exit(1);
    }
    return v;
  }
  console.error('error: ADMIN_PRIVATE_KEY not found in', envPath);
  process.exit(1);
}

function findRepoRoot(start) {
  let dir = start;
  for (let i = 0; i < 10; i++) {
    if (existsSync(resolve(dir, 'pnpm-workspace.yaml'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  console.error('error: cannot locate repo root (pnpm-workspace.yaml) from', start);
  process.exit(1);
}

function stripHex(s) {
  return s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
}

function hexToBytes(h) {
  if (h.length % 2 !== 0) throw new Error('hex must be even length');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function sha256Of(b) {
  return createHash('sha256').update(b).digest('hex');
}

function pubkeyToAddress(pk65) {
  // Ethereum address = last 20 bytes of keccak256(pk[1:65]).
  const h = keccak_256(pk65.slice(1));
  return '0x' + bytesToHex(h.slice(12));
}
