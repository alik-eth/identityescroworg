import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import { verifyXmlSignature } from '../../src/fetch/xmlSignature.js';
import { readTrustedCert } from '../../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, '../../fixtures');
const pinnedLotlPath = join(fixturesDir, 'lotl/eu-lotl-pinned.xml');
const anchorPath = join(fixturesDir, 'lotl-trust-anchors/ec-lotl-2023-digit-dmo.pem');

describe('EU LOTL live DSig verify against pinned 2023 anchor', () => {
  test('verifies the committed LOTL snapshot against the 2023 anchor cert', async () => {
    const xml = await readFile(pinnedLotlPath, 'utf8');
    const anchorDer = await readTrustedCert(anchorPath);
    const result = verifyXmlSignature(xml, {
      trustedCerts: [anchorDer],
      expectedRootLocalName: 'TrustServiceStatusList',
    });
    expect(result.ok).toBe(true);
    expect(result.signedReferenceCount).toBeGreaterThan(0);
  });
});
