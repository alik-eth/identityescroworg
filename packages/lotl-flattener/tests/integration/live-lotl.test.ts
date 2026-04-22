import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { DEFAULT_EU_LOTL_URL, readTrustedCerts, run } from '../../src/index.js';

const enabled = process.env.LOTL_LIVE === '1';
const describeLive = enabled ? describe : describe.skip;

let outDir: string;

beforeEach(async () => {
  outDir = await mkdtemp(join(tmpdir(), 'qkb-live-lotl-'));
});

afterEach(async () => {
  await rm(outDir, { recursive: true, force: true });
});

describeLive('live EU LOTL smoke', () => {
  test('verifies LOTL/MS-TL XML signatures and emits a non-empty QES CA set', async () => {
    const anchors = process.env.LOTL_TRUST_ANCHORS;
    if (!anchors) {
      throw new Error('LOTL_TRUST_ANCHORS must point to LOTL trust-anchor file(s) or directory');
    }

    const lotlTrustedCerts = await readTrustedCerts(anchors.split(':').filter(Boolean));
    expect(lotlTrustedCerts.length).toBeGreaterThan(0);

    const result = await run({
      lotl: process.env.LOTL_URL ?? DEFAULT_EU_LOTL_URL,
      out: outDir,
      lotlVersion: process.env.LOTL_VERSION ?? 'live-eu-lotl',
      signaturePolicy: 'require',
      lotlTrustedCerts,
      allowInsecureTransport: process.env.LOTL_ALLOW_INSECURE_TRANSPORT === '1',
    });

    expect(result.caCount).toBeGreaterThan(0);

    const root = JSON.parse(await readFile(join(outDir, 'root.json'), 'utf8')) as {
      rTL: string;
      treeDepth: number;
    };
    const cas = JSON.parse(await readFile(join(outDir, 'trusted-cas.json'), 'utf8')) as {
      cas: unknown[];
    };
    expect(root.rTL).toMatch(/^0x[0-9a-f]+$/);
    expect(root.treeDepth).toBe(16);
    expect(cas.cas.length).toBe(result.caCount);
  }, 180_000);
});
