#!/usr/bin/env node
// Sync packages/sdk/src/deployments.ts addresses from
// fixtures/contracts/{sepolia,base}.json. Hand-curated structure preserved —
// only the per-network address fields are swapped via precise string-replace.
//
// The Sepolia fixture is country-scoped under `countries.UA` (UA is the only
// jurisdiction live today). When a Base fixture lands at M8 it's expected to
// follow the same shape; the script tolerates a missing base.json and leaves
// those addresses at the zero-placeholder.
import { readFileSync, writeFileSync } from 'node:fs';

const sourcePath = 'packages/sdk/src/deployments.ts';

function loadFixture(path, country = 'UA') {
  let raw;
  try { raw = JSON.parse(readFileSync(path, 'utf8')); }
  catch { return null; }
  const c = raw.countries?.[country];
  if (!c) {
    throw new Error(`${path} missing countries.${country} section`);
  }
  return {
    registry: c.registry,
    identityEscrowNft: c.identityEscrowNft,
    leaf: c.leafVerifier,
    chain: c.chainVerifier,
    age: c.ageVerifier,
    mintDeadline: c.mintDeadline ?? 0,
  };
}

const sepolia = loadFixture('fixtures/contracts/sepolia.json');
const base = loadFixture('fixtures/contracts/base.json');

let src = readFileSync(sourcePath, 'utf8');

function swap(network, fx) {
  if (!fx) return;
  const swaps = [
    [new RegExp(`(\\b${network}:[\\s\\S]*?registry:\\s*)'0x[0-9a-fA-F]+'`),
      `$1'${fx.registry}'`],
    [new RegExp(`(\\b${network}:[\\s\\S]*?identityEscrowNft:\\s*)'0x[0-9a-fA-F]+'`),
      `$1'${fx.identityEscrowNft}'`],
    [new RegExp(`(\\b${network}:[\\s\\S]*?verifiers:\\s*\\{[\\s\\S]*?leaf:\\s*)'0x[0-9a-fA-F]+'`),
      `$1'${fx.leaf}'`],
    [new RegExp(`(\\b${network}:[\\s\\S]*?verifiers:\\s*\\{[\\s\\S]*?chain:\\s*)'0x[0-9a-fA-F]+'`),
      `$1'${fx.chain}'`],
    [new RegExp(`(\\b${network}:[\\s\\S]*?verifiers:\\s*\\{[\\s\\S]*?age:\\s*)'0x[0-9a-fA-F]+'`),
      `$1'${fx.age}'`],
    [new RegExp(`(\\b${network}:[\\s\\S]*?mintDeadline:\\s*)\\d+`),
      `$1${fx.mintDeadline}`],
  ];
  for (const [re, sub] of swaps) src = src.replace(re, sub);
}

swap('sepolia', sepolia);
swap('base', base);

writeFileSync(sourcePath, src);
console.log(`synced ${sourcePath}`);
console.log(`  sepolia: ${sepolia ? 'populated' : 'skipped (no fixture)'}`);
console.log(`  base:    ${base ? 'populated' : 'skipped (no fixture yet)'}`);
