import { mkdtemp, readFile, rm, writeFile, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { run } from '../../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, '../../fixtures');
const lotlPath = join(fixturesDir, 'lotl-mini.xml');
const expectedDir = join(fixturesDir, 'expected');
const pinnedPath = join(expectedDir, 'root-pinned.json');

// Deterministic inputs to the pipeline — any drift here must also drift the
// pinned baseline deliberately.
const PINNED_OPTS = {
  lotlVersion: 'pinned-synthetic-2026-04-17',
  treeDepth: 16,
  builtAt: '2026-04-17T00:00:00Z',
} as const;

const exists = async (p: string): Promise<boolean> => {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
};

let outDirA: string;
let outDirB: string;

beforeEach(async () => {
  outDirA = await mkdtemp(join(tmpdir(), 'qkb-repro-a-'));
  outDirB = await mkdtemp(join(tmpdir(), 'qkb-repro-b-'));
});

afterEach(async () => {
  await rm(outDirA, { recursive: true, force: true });
  await rm(outDirB, { recursive: true, force: true });
});

describe('flattener reproducibility snapshot', () => {
  test('two runs against the synthetic LOTL produce byte-identical outputs', async () => {
    await run({ lotl: lotlPath, out: outDirA, ...PINNED_OPTS });
    await run({ lotl: lotlPath, out: outDirB, ...PINNED_OPTS });

    for (const file of ['root.json', 'trusted-cas.json', 'layers.json']) {
      const a = await readFile(join(outDirA, file), 'utf8');
      const b = await readFile(join(outDirB, file), 'utf8');
      expect(b).toBe(a);
    }
  });

  test('root matches the pinned baseline (or writes it on first run)', async () => {
    const { rTL } = await run({ lotl: lotlPath, out: outDirA, ...PINNED_OPTS });
    const rootJson = JSON.parse(await readFile(join(outDirA, 'root.json'), 'utf8'));

    // First-run bootstrap: if the pinned baseline is absent, commit it.
    // In CI it must be committed already — a missing baseline there will still
    // fail review at the commit-diff stage.
    if (!(await exists(pinnedPath))) {
      await writeFile(
        pinnedPath,
        `${JSON.stringify(
          {
            rTL: rootJson.rTL,
            treeDepth: rootJson.treeDepth,
            lotlVersion: rootJson.lotlVersion,
            builtAt: rootJson.builtAt,
            note: 'Pinned reproducibility baseline for synthetic LOTL fixture chain. Update deliberately only.',
          },
          null,
          2,
        )}\n`,
      );
    }

    const pinned = JSON.parse(await readFile(pinnedPath, 'utf8'));
    expect(rootJson.rTL).toBe(pinned.rTL);
    expect(rootJson.treeDepth).toBe(pinned.treeDepth);
    expect(rootJson.lotlVersion).toBe(pinned.lotlVersion);
    expect(rootJson.builtAt).toBe(pinned.builtAt);
    expect(BigInt(pinned.rTL)).toBe(rTL);
  });
});
