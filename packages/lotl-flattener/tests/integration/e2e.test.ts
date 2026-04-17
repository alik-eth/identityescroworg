import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { run } from '../../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, '../../fixtures');
const lotlPath = join(fixturesDir, 'lotl-mini.xml');
const expectedDir = join(fixturesDir, 'expected');

let outDir: string;
beforeEach(async () => {
  outDir = await mkdtemp(join(tmpdir(), 'qkb-flat-e2e-'));
});
afterEach(async () => {
  await rm(outDir, { recursive: true, force: true });
});

describe('flattener end-to-end pipeline', () => {
  test('produces root matching pinned expected against synthetic LOTL', async () => {
    const result = await run({
      lotl: lotlPath,
      out: outDir,
      lotlVersion: 'mini-fixture',
      treeDepth: 16,
      builtAt: '2026-04-17T00:00:00Z',
    });

    const root = JSON.parse(await readFile(join(outDir, 'root.json'), 'utf8'));
    const cas = JSON.parse(await readFile(join(outDir, 'trusted-cas.json'), 'utf8'));
    const layers = JSON.parse(await readFile(join(outDir, 'layers.json'), 'utf8'));

    expect(root.treeDepth).toBe(16);
    expect(root.lotlVersion).toBe('mini-fixture');
    expect(cas.cas).toHaveLength(2);
    expect(cas.cas[0].merkleIndex).toBe(0);
    expect(cas.cas[1].merkleIndex).toBe(1);
    expect(layers.depth).toBe(16);
    expect(layers.layers).toHaveLength(17);

    const expected = JSON.parse(await readFile(join(expectedDir, 'root.json'), 'utf8'));
    expect(root.rTL).toBe(expected.rTL);
    expect(BigInt(root.rTL)).toBe(result.rTL);
  });
});
