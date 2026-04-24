import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { run } from '../../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, '../../fixtures');
const lotlPath = join(fixturesDir, 'lotl-mini.xml');

let outDir: string;
beforeEach(async () => {
  outDir = await mkdtemp(join(tmpdir(), 'qkb-flat-filter-'));
});
afterEach(async () => {
  await rm(outDir, { recursive: true, force: true });
});

describe('flattener --filter-country integration', () => {
  test('filters mini LOTL to one country slice', async () => {
    await run({
      lotl: lotlPath,
      out: outDir,
      lotlVersion: 'mini-EE-only',
      treeDepth: 16,
      builtAt: '2026-04-24T00:00:00Z',
      filterCountry: 'EE',
    });
    const trusted = JSON.parse(await readFile(join(outDir, 'trusted-cas.json'), 'utf8')) as {
      cas: Array<{ territory?: string }>;
    };
    expect(trusted.cas.length).toBeGreaterThan(0);
    expect(trusted.cas.every((c) => c.territory?.toUpperCase() === 'EE')).toBe(true);
  });

  test('case-insensitive matching', async () => {
    await run({
      lotl: lotlPath,
      out: outDir,
      lotlVersion: 'mini-ee-lowercase',
      treeDepth: 16,
      builtAt: '2026-04-24T00:00:00Z',
      filterCountry: 'ee',
    });
    const trusted = JSON.parse(await readFile(join(outDir, 'trusted-cas.json'), 'utf8')) as {
      cas: Array<{ territory?: string }>;
    };
    expect(trusted.cas.every((c) => c.territory?.toUpperCase() === 'EE')).toBe(true);
  });

  test('throws when no services match the country', async () => {
    await expect(
      run({
        lotl: lotlPath,
        out: outDir,
        lotlVersion: 'mini-xx',
        treeDepth: 16,
        builtAt: '2026-04-24T00:00:00Z',
        filterCountry: 'XX',
      }),
    ).rejects.toThrow(/no trusted services/);
  });
});
