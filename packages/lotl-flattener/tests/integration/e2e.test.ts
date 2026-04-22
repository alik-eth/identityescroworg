import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import {
  combineOutputs,
  diagnose,
  inspectLotlSigners,
  inspectOutput,
  run,
} from '../../src/index.js';

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
  vi.restoreAllMocks();
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

  test('can load LOTL and Member State TLs through HTTPS URLs', async () => {
    const lotl = await readFile(lotlPath, 'utf8');
    const ee = await readFile(join(fixturesDir, 'ms-tl-ee.xml'), 'utf8');
    const pl = await readFile(join(fixturesDir, 'ms-tl-pl.xml'), 'utf8');
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input: Parameters<typeof fetch>[0]) => {
      const url = String(input);
      const body = url.endsWith('/lotl.xml')
        ? lotl.replace('ms-tl-ee.xml', 'https://tl.example.test/ms-tl-ee.xml')
        : url.endsWith('/ms-tl-ee.xml')
          ? ee
          : url.endsWith('/ms-tl-pl.xml')
            ? pl
            : undefined;
      if (!body) return new Response('not found', { status: 404 });
      return new Response(body, { status: 200 });
    });

    const result = await run({
      lotl: 'https://tl.example.test/lotl.xml',
      out: outDir,
      lotlVersion: 'url-fixture',
      treeDepth: 16,
      builtAt: '2026-04-17T00:00:00Z',
    });

    expect(result.caCount).toBe(2);
    expect(globalThis.fetch).toHaveBeenCalledWith('https://tl.example.test/lotl.xml');
    expect(globalThis.fetch).toHaveBeenCalledWith('https://tl.example.test/ms-tl-ee.xml');
    expect(globalThis.fetch).toHaveBeenCalledWith('https://tl.example.test/ms-tl-pl.xml');
  });

  test('allow-insecure-transport applies to LOTL and Member State TL fetches', async () => {
    const lotl = await readFile(lotlPath, 'utf8');
    const ee = await readFile(join(fixturesDir, 'ms-tl-ee.xml'), 'utf8');
    const pl = await readFile(join(fixturesDir, 'ms-tl-pl.xml'), 'utf8');
    const previousTlsSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    const tlsStates: string[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input: Parameters<typeof fetch>[0]) => {
      tlsStates.push(process.env.NODE_TLS_REJECT_UNAUTHORIZED ?? '');
      const url = String(input);
      const body = url.endsWith('/lotl.xml')
        ? lotl.replace('ms-tl-ee.xml', 'https://tl.example.test/ms-tl-ee.xml')
        : url.endsWith('/ms-tl-ee.xml')
          ? ee
          : url.endsWith('/ms-tl-pl.xml')
            ? pl
            : undefined;
      if (!body) return new Response('not found', { status: 404 });
      return new Response(body, { status: 200 });
    });

    await run({
      lotl: 'https://tl.example.test/lotl.xml',
      out: outDir,
      lotlVersion: 'url-fixture',
      treeDepth: 16,
      builtAt: '2026-04-17T00:00:00Z',
      signaturePolicy: 'require',
      lotlTrustedCerts: [new Uint8Array([1, 2, 3])],
      xmlSignatureVerifier: (xml) => ({
        ok: true,
        authenticatedXml: xml,
        signedReferenceCount: 1,
      }),
      allowInsecureTransport: true,
    });

    expect(tlsStates).toEqual(['0', '0', '0']);
    expect(process.env.NODE_TLS_REJECT_UNAUTHORIZED).toBe(previousTlsSetting);
  });

  test('require-signatures aborts when XML signature verification fails', async () => {
    await expect(
      run({
        lotl: lotlPath,
        out: outDir,
        signaturePolicy: 'require',
        xmlSignatureVerifier: () => ({
          ok: false,
          signedReferenceCount: 0,
          error: 'test-failure',
        }),
      }),
    ).rejects.toThrow(/requires at least one trusted LOTL signing certificate/);
  });

  test('require-signatures uses explicit LOTL trust anchors', async () => {
    const calls: Array<{ label: string; trustedCerts?: readonly Uint8Array[] }> = [];
    const lotlTrust = new Uint8Array([9, 9, 9]);
    const result = await run({
      lotl: lotlPath,
      out: outDir,
      lotlVersion: 'anchored-fixture',
      treeDepth: 16,
      builtAt: '2026-04-17T00:00:00Z',
      signaturePolicy: 'require',
      lotlTrustedCerts: [lotlTrust],
      xmlSignatureVerifier: (xml, opts) => {
        calls.push({ label: opts.label, trustedCerts: opts.trustedCerts });
        return { ok: true, authenticatedXml: xml, signedReferenceCount: 1 };
      },
    });

    expect(result.caCount).toBe(2);
    expect(calls[0]).toMatchObject({ label: 'LOTL', trustedCerts: [lotlTrust] });
    expect(
      calls
        .slice(1)
        .map((c) => c.label)
        .sort(),
    ).toEqual(['MS TL EE', 'MS TL PL']);
  });

  test('inspectLotlSigners reports embedded signer fingerprints without requiring trust', async () => {
    const derB64 = 'MAoCAQECAgECAwE=';
    const lotl = `<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:KeyInfo><ds:X509Data><ds:X509Certificate>${derB64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
      </ds:Signature>
    </TrustServiceStatusList>`;
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(lotl, { status: 200 }));

    const signers = await inspectLotlSigners('https://tl.example.test/lotl.xml');

    expect(signers).toHaveLength(1);
    expect(signers[0]?.sha256Hex).toBe(
      'ed723107507e47cded7261dec86cb628dd7e6ad6bdebcb2298590b58fbdfb739',
    );
  });

  test('require-signatures parses authenticated XML returned by verifier', async () => {
    const result = await run({
      lotl: lotlPath,
      out: outDir,
      lotlVersion: 'authenticated-fixture',
      treeDepth: 16,
      builtAt: '2026-04-17T00:00:00Z',
      signaturePolicy: 'require',
      lotlTrustedCerts: [new Uint8Array([1, 2, 3])],
      xmlSignatureVerifier: (xml) => ({
        ok: true,
        authenticatedXml: xml,
        signedReferenceCount: 1,
      }),
    });
    expect(result.caCount).toBe(2);
  });

  test('allow-insecure-transport requires required XML signatures', async () => {
    await expect(
      run({
        lotl: lotlPath,
        out: outDir,
        allowInsecureTransport: true,
      }),
    ).rejects.toThrow(/allow-insecure-transport requires --require-signatures/);
  });

  test('diagnose reports per-MS failures without aborting', async () => {
    const calls: string[] = [];
    const result = await diagnose({
      lotl: lotlPath,
      signaturePolicy: 'require',
      lotlTrustedCerts: [new Uint8Array([1])],
      xmlSignatureVerifier: (xml) => ({
        ok: true,
        authenticatedXml: xml,
        signedReferenceCount: 1,
      }),
      msTlLoader: async (location) => {
        calls.push(location);
        if (location === 'ms-tl-pl.xml') throw new Error('network reset');
        return await readFile(join(fixturesDir, 'ms-tl-ee.xml'), 'utf8');
      },
    });

    expect(calls.sort()).toEqual(['ms-tl-ee.xml', 'ms-tl-pl.xml']);
    expect(result.pointerCount).toBe(2);
    expect(result.diagnostics).toHaveLength(2);
    expect(result.diagnostics.find((d) => d.territory === 'EE')).toMatchObject({
      ok: true,
      caCount: 1,
    });
    expect(result.diagnostics.find((d) => d.territory === 'PL')).toMatchObject({
      ok: false,
      error: 'network reset',
    });
  });

  test('inspectOutput summarizes generated artifacts', async () => {
    await run({
      lotl: lotlPath,
      out: outDir,
      lotlVersion: 'mini-fixture',
      treeDepth: 16,
      builtAt: '2026-04-17T00:00:00Z',
    });

    await expect(inspectOutput(outDir)).resolves.toMatchObject({
      caCount: 2,
      countries: { EE: 1, PL: 1 },
      missingTerritoryCount: 0,
      eSealOnlyCount: 0,
      root: {
        lotlVersion: 'mini-fixture',
        treeDepth: 16,
      },
    });
  });

  test('combineOutputs creates one circuit-compatible root from multiple flattener outputs', async () => {
    const leftDir = join(outDir, 'left');
    const rightDir = join(outDir, 'right');
    const combinedDir = join(outDir, 'combined');
    await run({
      lotl: lotlPath,
      out: leftDir,
      lotlVersion: 'left-fixture',
      treeDepth: 16,
      builtAt: '2026-04-17T00:00:00Z',
    });
    await run({
      lotl: join(fixturesDir, 'diia/lotl.xml'),
      out: rightDir,
      lotlVersion: 'right-fixture',
      treeDepth: 16,
      builtAt: '2026-04-17T00:00:00Z',
    });

    const result = await combineOutputs({
      inputs: [leftDir, rightDir],
      out: combinedDir,
      lotlVersion: 'combined-fixture',
      trustDomain: 'combined-test',
      trustSources: ['left-test', 'right-test'],
      treeDepth: 16,
      builtAt: '2026-04-17T00:00:00Z',
    });

    const root = JSON.parse(await readFile(join(combinedDir, 'root.json'), 'utf8'));
    const cas = JSON.parse(await readFile(join(combinedDir, 'trusted-cas.json'), 'utf8'));
    const layers = JSON.parse(await readFile(join(combinedDir, 'layers.json'), 'utf8'));
    expect(result.caCount).toBe(4);
    expect(cas.cas).toHaveLength(4);
    expect(cas.cas.map((ca: { territory: string }) => ca.territory)).toEqual([
      'EE',
      'PL',
      'UA',
      'UA',
    ]);
    expect(root).toMatchObject({
      rTL: layers.layers[16][0],
      treeDepth: 16,
      builtAt: '2026-04-17T00:00:00Z',
      lotlVersion: 'combined-fixture',
      trustDomain: 'combined-test',
      trustSources: ['left-test', 'right-test'],
    });
    expect(BigInt(root.rTL)).toBe(result.rTL);
  });
});
