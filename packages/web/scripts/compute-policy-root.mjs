#!/usr/bin/env node
// Deterministically re-derive the UA v1 policy root from the committed
// fixtures/declarations/ua/policy-v1.json seed and emit
// fixtures/trust/ua/policy-root.json.
//
// Usage (from repo root):
//   pnpm -F @qkb/web compute-policy-root
//
// Verifies:
//   1. contentHash in policy-v1.json matches sha256(fixtures/declarations/uk.txt).
//   2. metadataHash in policy-v1.json matches sha256(JCS({lang,template})).
// …then builds the Poseidon Merkle tree (depth 4, 16 slots, 1 filled) using
// the same convention as packages/web/src/lib/policyTree.ts and writes the root.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import canonicalize from 'canonicalize';
import { buildPoseidon } from 'circomlibjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '../../..');
const SEED_PATH = resolve(REPO_ROOT, 'fixtures/declarations/ua/policy-v1.json');
const OUT_PATH = resolve(REPO_ROOT, 'fixtures/trust/ua/policy-root.json');
const UK_DECL_PATH = resolve(REPO_ROOT, 'fixtures/declarations/uk.txt');
const TREE_DEPTH = 4;
const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const POLICY_LEAF_SCHEMA = 'qkb-policy-leaf/v1';
const BINDING_V2_SCHEMA = 'qkb-binding-core/v1';

function sha256Hex(bytesOrStr) {
  return `0x${createHash('sha256').update(bytesOrStr).digest('hex')}`;
}

function sha256Bytes(bytesOrStr) {
  return new Uint8Array(createHash('sha256').update(bytesOrStr).digest());
}

function bytesToBigInt(bytes) {
  let out = 0n;
  for (const b of bytes) out = (out << 8n) | BigInt(b);
  return out;
}

function toHex32(v) {
  return `0x${v.toString(16).padStart(64, '0')}`;
}

function policyLeafField(leaf) {
  const jcs = canonicalize(leaf);
  const digest = sha256Bytes(jcs);
  return bytesToBigInt(digest) % BN254_SCALAR_FIELD;
}

async function buildMerkleRoot(poseidon, leaves, depth) {
  const hash2 = (l, r) => poseidon.F.toObject(poseidon([l, r]));
  const zeros = new Array(depth + 1);
  zeros[0] = 0n;
  for (let i = 1; i <= depth; i++) zeros[i] = hash2(zeros[i - 1], zeros[i - 1]);

  let level = leaves.slice();
  for (let d = 0; d < depth; d++) {
    const nextLen = Math.ceil(level.length / 2);
    const next = new Array(nextLen);
    for (let i = 0; i < nextLen; i++) {
      const l = level[2 * i] ?? zeros[d];
      const r = level[2 * i + 1] ?? zeros[d];
      next[i] = hash2(l, r);
    }
    level = next;
  }
  return level.length === 1 ? level[0] : zeros[depth];
}

async function main() {
  const seed = JSON.parse(readFileSync(SEED_PATH, 'utf8'));

  if (seed.leafSchema !== POLICY_LEAF_SCHEMA) {
    throw new Error(`unexpected leafSchema: ${seed.leafSchema}`);
  }
  if (seed.bindingSchema !== BINDING_V2_SCHEMA) {
    throw new Error(`unexpected bindingSchema: ${seed.bindingSchema}`);
  }

  const ukText = readFileSync(UK_DECL_PATH);
  const contentHashActual = sha256Hex(ukText);
  if (contentHashActual.toLowerCase() !== seed.contentHash.toLowerCase()) {
    throw new Error(
      `contentHash mismatch: seed=${seed.contentHash} actual=${contentHashActual}`,
    );
  }

  const metaJcs = canonicalize({ lang: 'uk', template: 'qkb-default-ua/v1' });
  const metadataHashActual = sha256Hex(metaJcs);
  if (metadataHashActual.toLowerCase() !== seed.metadataHash.toLowerCase()) {
    throw new Error(
      `metadataHash mismatch: seed=${seed.metadataHash} actual=${metadataHashActual}`,
    );
  }

  // Canonical shape mirrors buildPolicyLeafV1() — only the fields that end up
  // in the JCS digest (no jurisdiction/activeFrom/activeTo for the UA default).
  const policyLeaf = {
    leafSchema: POLICY_LEAF_SCHEMA,
    policyId: seed.policyId,
    policyVersion: seed.policyVersion,
    bindingSchema: BINDING_V2_SCHEMA,
    contentHash: seed.contentHash.toLowerCase(),
    metadataHash: seed.metadataHash.toLowerCase(),
  };
  const leafField = policyLeafField(policyLeaf);
  const leafHex = toHex32(leafField);

  const poseidon = await buildPoseidon();
  const rootField = await buildMerkleRoot(poseidon, [leafField], TREE_DEPTH);
  const rootHex = toHex32(rootField);

  const out = {
    schema: 'qkb-v4-policy-root/v1',
    country: 'UA',
    policyLeafHashes: [leafHex],
    treeDepth: TREE_DEPTH,
    policyRoot: rootHex,
    generatedAt: new Date().toISOString(),
    source: {
      seed: 'fixtures/declarations/ua/policy-v1.json',
      ukDeclaration: 'fixtures/declarations/uk.txt',
    },
  };

  mkdirSync(dirname(OUT_PATH), { recursive: true });
  writeFileSync(OUT_PATH, `${JSON.stringify(out, null, 2)}\n`, 'utf8');

  process.stdout.write(
    `UA policy root computed\n` +
      `  leafHash:   ${leafHex}\n` +
      `  policyRoot: ${rootHex}\n` +
      `  depth:      ${TREE_DEPTH}\n` +
      `  written:    ${OUT_PATH}\n`,
  );
}

main().catch((err) => {
  process.stderr.write(`${err?.stack ?? err}\n`);
  process.exit(1);
});
