import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import { spkiCommit } from '../../src/ca/spkiCommit.js';

interface ParityFixture {
  schema: string;
  cases: Array<{
    label: string;
    spki: string;
    expectedCommitDecimal: string;
  }>;
}

const here = dirname(fileURLToPath(import.meta.url));
// Parity fixture lives at the repo root (lead-owned, pumped from arch-circuits).
const parityPath = resolve(here, '../../../../fixtures/spki-commit/v5-parity.json');

async function loadCase(label: string) {
  const fx = JSON.parse(await readFile(parityPath, 'utf8')) as ParityFixture;
  const c = fx.cases.find((x) => x.label === label);
  if (!c) throw new Error(`parity case "${label}" not found in fixture`);
  return c;
}

describe('spkiCommit (V5 §9.1 parity gate)', () => {
  test('matches circuits-eng reference for admin-leaf-ecdsa', async () => {
    const c = await loadCase('admin-leaf-ecdsa');
    const spki = Uint8Array.from(Buffer.from(c.spki, 'hex'));
    const commit = await spkiCommit(spki);
    expect(commit.toString()).toBe(c.expectedCommitDecimal);
  });

  test('matches circuits-eng reference for admin-intermediate-ecdsa', async () => {
    const c = await loadCase('admin-intermediate-ecdsa');
    const spki = Uint8Array.from(Buffer.from(c.spki, 'hex'));
    const commit = await spkiCommit(spki);
    expect(commit.toString()).toBe(c.expectedCommitDecimal);
  });

  test('rejects non-91-byte SPKI', async () => {
    await expect(spkiCommit(new Uint8Array(64))).rejects.toThrow(/length|91|unexpected/i);
  });
});
