import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import { canonicalizeCertHash } from '../../src/ca/canonicalize.js';

const here = dirname(fileURLToPath(import.meta.url));
const derPath = resolve(here, '../../fixtures/certs/test-ca.der');

describe('canonicalizeCertHash', () => {
  test('is deterministic across runs on the same DER', async () => {
    const der = new Uint8Array(await readFile(derPath));
    const a = await canonicalizeCertHash(der);
    const b = await canonicalizeCertHash(der);
    expect(a).toBe(b);
  });

  test('differs when a single byte is flipped', async () => {
    const der = new Uint8Array(await readFile(derPath));
    const flipped = new Uint8Array(der);
    flipped[100]! ^= 0x01;
    const a = await canonicalizeCertHash(der);
    const b = await canonicalizeCertHash(flipped);
    expect(a).not.toBe(b);
  });

  test('packs short input deterministically', async () => {
    const a = await canonicalizeCertHash(new Uint8Array([1, 2, 3]));
    const b = await canonicalizeCertHash(new Uint8Array([1, 2, 3]));
    expect(a).toBe(b);
    expect(typeof a).toBe('bigint');
    expect(a).toBeGreaterThan(0n);
  });

  test('hash of test-ca.der matches pinned snapshot', async () => {
    const der = new Uint8Array(await readFile(derPath));
    const h = await canonicalizeCertHash(der);
    // Snapshot is captured the first time this test runs (see SNAPSHOT below).
    // If you intentionally change chunking, regenerate via the dev script and
    // bump the SNAPSHOT in lockstep with circuits-eng's mirror.
    expect(h.toString()).toMatchSnapshot();
  });
});
