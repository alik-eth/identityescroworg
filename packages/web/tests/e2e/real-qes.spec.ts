/**
 * Real signed-QES e2e, gated by E2E_REAL_QES_DIR.
 *
 * Expected fixture directory:
 *   binding.qkb.json
 *   binding.qkb.json.p7s
 *
 * This drives the production upload path with the real CAdES parser,
 * trusted-list verifier, Merkle lookup, and witness exporter. If
 * E2E_REAL_PROOF_BUNDLE points at a qkb-proof-bundle/v1 file, the test imports
 * that real proof bundle. Otherwise it imports a clearly fake proof bundle
 * derived from the real witness public signals so the /register UI and wallet
 * handoff can still be covered without running the 4.5 GB zkey prover.
 */
import { test, expect } from '@playwright/test';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';

const REAL_QES_DIR = process.env.E2E_REAL_QES_DIR;
const REAL_PROOF_BUNDLE = process.env.E2E_REAL_PROOF_BUNDLE;

test.skip(!REAL_QES_DIR, 'set E2E_REAL_QES_DIR to a real binding.qkb.json + .p7s fixture dir');

test('real QES upload -> witness -> proof import -> mocked register submit', async ({
  page,
}, testInfo) => {
  test.setTimeout(120_000);

  const fixtureDir = resolveFixtureDir(REAL_QES_DIR!);
  const bindingPath = join(fixtureDir, 'binding.qkb.json');
  const p7sPath = join(fixtureDir, 'binding.qkb.json.p7s');
  const bindingBytes = readFileSync(bindingPath);
  const p7s = readFileSync(p7sPath);
  const binding = JSON.parse(bindingBytes.toString('utf8')) as { pk: string };
  const root = JSON.parse(readFileSync(resolve(process.cwd(), 'public/trusted-cas/root.json'), 'utf8')) as {
    rTL: string;
    treeDepth: number;
  };
  const pk = binding.pk.replace(/^0x/, '');
  const trustedListFetches = new Set<string>();
  page.on('response', (response) => {
    const url = response.url();
    if (
      response.ok() &&
      (url.endsWith('/trusted-cas/root.json') ||
        url.endsWith('/trusted-cas/trusted-cas.json') ||
        url.endsWith('/trusted-cas/layers.json'))
    ) {
      trustedListFetches.add(url.split('/trusted-cas/')[1]);
    }
  });

  await page.addInitScript(
    ({ bindingObj, bcanonB64, pubkeyHex }) => {
      sessionStorage.setItem(
        'qkb.session.v1',
        JSON.stringify({
          pubkeyUncompressedHex: pubkeyHex,
          locale: 'uk',
          binding: bindingObj,
          bcanonB64,
        }),
      );
    },
    {
      bindingObj: binding,
      bcanonB64: bindingBytes.toString('base64'),
      pubkeyHex: pk,
    },
  );

  await page.goto('/upload');
  expect(await page.evaluate(() => typeof window.__QKB_VERIFY__)).toBe('undefined');
  await page.getByTestId('prove-mode-offline').check();

  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 120_000 }),
    page.setInputFiles('[data-testid="file-input"]', {
      name: 'binding.qkb.json.p7s',
      mimeType: 'application/pkcs7-signature',
      buffer: p7s,
    }),
  ]);
  await expect(page.getByTestId('upload-awaiting-offline')).toBeVisible();

  const witnessPath = join(testInfo.outputDir, 'witness.json');
  await download.saveAs(witnessPath);
  const witness = JSON.parse(readFileSync(witnessPath, 'utf8')) as WitnessBundle;
  expect(witness.schema).toBe('qkb-witness/v1');
  expect(witness.algorithmTag).toBe(1);
  expect(Number(witness.leaf.BcanonLen)).toBe(bindingBytes.length);
  expect(Number(witness.leaf.signedAttrsLen)).toBeGreaterThan(1000);
  expect(String(witness.chain.rTL)).toBe(BigInt(root.rTL).toString(10));
  expect(String(witness.chain.algorithmTag)).toBe('1');
  expect(String(witness.chain.leafSpkiCommit)).toBe(String(witness.leaf.leafSpkiCommit));
  expect(witness.chain.merklePath).toHaveLength(root.treeDepth);
  expect(witness.chain.merkleIndices).toHaveLength(root.treeDepth);
  expect(trustedListFetches).toEqual(
    new Set(['root.json', 'trusted-cas.json', 'layers.json']),
  );

  const proofBundle = REAL_PROOF_BUNDLE
    ? JSON.parse(readFileSync(resolve(REAL_PROOF_BUNDLE), 'utf8'))
    : buildMockProofBundle(witness);
  const proofBundlePath = join(testInfo.outputDir, 'proof-bundle.json');
  writeFileSync(proofBundlePath, `${JSON.stringify(proofBundle, null, 2)}\n`);

  await page.setInputFiles('[data-testid="proof-import-input"]', {
    name: 'proof-bundle.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(proofBundle)),
  });
  await expect(page.getByTestId('upload-done')).toBeVisible();
  await page.getByTestId('upload-next').click();
  await expect(page).toHaveURL(/\/register$/);

  const mockAddress = '0x00000000000000000000000000000000000000aa';
  const mockTx = `0x${createHash('sha256').update(p7s).digest('hex')}`;
  await page.evaluate(
    ({ addr, tx }) => {
      (window as unknown as { __QKB_ETHEREUM__: unknown }).__QKB_ETHEREUM__ = {
        request: async ({ method }: { method: string }) => {
          if (method === 'eth_requestAccounts') return [addr];
          if (method === 'wallet_switchEthereumChain') return null;
          if (method === 'eth_chainId') return '0xaa36a7';
          return null;
        },
      };
      (window as unknown as { __QKB_SUBMIT_TX__: unknown }).__QKB_SUBMIT_TX__ =
        async (input: { from: string }) => ({ txHash: tx, pkAddr: input.from });
    },
    { addr: mockAddress, tx: mockTx },
  );

  await page.getByTestId('connect-wallet').click();
  await expect(page.getByTestId('wallet-address')).toHaveText(mockAddress);
  await page.getByTestId('submit-register').click();
  await expect(page.getByTestId('register-success')).toBeVisible();
  await expect(page.getByTestId('tx-hash')).toHaveText(mockTx);

  mkdirSync(fixtureDir, { recursive: true });
  writeFileSync(join(fixtureDir, 'last-e2e-witness.json'), JSON.stringify(witness, null, 2));
  writeFileSync(join(fixtureDir, 'last-e2e-proof-bundle.json'), JSON.stringify(proofBundle, null, 2));
});

interface WitnessBundle {
  schema: string;
  circuitVersion: string;
  algorithmTag: 0 | 1;
  leaf: Record<string, unknown>;
  chain: Record<string, unknown>;
}

function resolveFixtureDir(dir: string): string {
  const candidates = [resolve(dir), resolve(process.cwd(), '../..', dir)];
  const match = candidates.find((candidate) =>
    existsSync(join(candidate, 'binding.qkb.json')) &&
    existsSync(join(candidate, 'binding.qkb.json.p7s')),
  );
  if (!match) {
    throw new Error(
      `E2E_REAL_QES_DIR must contain binding.qkb.json and binding.qkb.json.p7s; tried ${candidates.join(', ')}`,
    );
  }
  return match;
}

function buildMockProofBundle(witness: WitnessBundle) {
  const proof = {
    pi_a: ['0x1', '0x2', '1'],
    pi_b: [
      ['0x3', '0x4'],
      ['0x5', '0x6'],
      ['1', '0'],
    ],
    pi_c: ['0x7', '0x8', '1'],
    protocol: 'groth16',
    curve: 'bn128',
  };
  return {
    schema: 'qkb-proof-bundle/v1',
    circuitVersion: witness.circuitVersion,
    algorithmTag: witness.algorithmTag,
    proofLeaf: proof,
    publicLeaf: [
      ...(witness.leaf.pkX as string[]),
      ...(witness.leaf.pkY as string[]),
      String(witness.leaf.ctxHash),
      String(witness.leaf.declHash),
      String(witness.leaf.timestamp),
      String(witness.leaf.nullifier),
      String(witness.leaf.leafSpkiCommit),
    ],
    proofChain: proof,
    publicChain: [
      String(witness.chain.rTL),
      String(witness.chain.algorithmTag),
      String(witness.chain.leafSpkiCommit),
    ],
  };
}
