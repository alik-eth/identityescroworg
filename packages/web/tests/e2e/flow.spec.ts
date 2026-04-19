/**
 * Happy-path e2e covering /generate → /sign → /upload → /register, with
 * the snarkjs prover mocked through MockProver (real prover takes minutes
 * and 4 GB — gated separately behind E2E_REAL_PROVER=1 in happy-path.spec.ts).
 *
 * Each route is also exercised in isolation so a failure during, say, /sign
 * does not cascade into meaningless /register red.
 */
import { test, expect } from '@playwright/test';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { sha256 } from '@noble/hashes/sha256';
import * as secp from '@noble/secp256k1';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname_flow = dirname(fileURLToPath(import.meta.url));
import canonicalize from 'canonicalize';

pkijs.setEngine(
  'node-webcrypto',
  new pkijs.CryptoEngine({ name: 'node', crypto: globalThis.crypto }),
);

interface FlowFixture {
  bcanonB64: string;
  pubkeyUncompressedHex: string;
  binding: Record<string, unknown>;
  p7s: Buffer;
}

async function buildFlowFixture(): Promise<FlowFixture> {
  // Mint an independent secp256k1 keypair for the binding's `pk` field.
  const priv = secp.utils.randomPrivateKey();
  const pkUncompressed = secp.getPublicKey(priv, false);
  const pubkeyUncompressedHex = Array.from(pkUncompressed, (b) => b.toString(16).padStart(2, '0')).join('');

  const nonce = new Uint8Array(32);
  for (let i = 0; i < 32; i++) nonce[i] = (i * 13 + 7) & 0xff;
  const enText = readFileSync(
    resolve(__dirname_flow, '../../../../fixtures/declarations/en.txt'),
    'utf8',
  );
  const nonceHex = '0x' + Array.from(nonce, (b) => b.toString(16).padStart(2, '0')).join('');
  const binding = {
    context: '0x',
    declaration: enText,
    escrow_commitment: null,
    nonce: nonceHex,
    pk: '0x' + pubkeyUncompressedHex,
    scheme: 'secp256k1',
    timestamp: Math.floor(Date.now() / 1000),
    version: 'QKB/1.0',
  };
  const bcanonText = canonicalize(binding);
  if (!bcanonText) throw new Error('canonicalize failed');
  const bcanon = new TextEncoder().encode(bcanonText);
  const bcanonB64 = Buffer.from(bcanon).toString('base64');

  // Mint an ECDSA-P256 leaf cert + detached CAdES-BES over the bcanon.
  const subtle = globalThis.crypto.subtle;
  const kp = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 1 });
  const setName = (t: pkijs.RelativeDistinguishedNames, cn: string) => {
    t.typesAndValues = [
      new pkijs.AttributeTypeAndValue({
        type: '2.5.4.3',
        value: new asn1js.Utf8String({ value: cn }),
      }),
    ];
  };
  setName(cert.subject, 'QKB E2E Leaf');
  setName(cert.issuer, 'QKB E2E Leaf');
  cert.notBefore.value = new Date(Date.now() - 60_000);
  cert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  await cert.subjectPublicKeyInfo.importKey(kp.publicKey);
  await cert.sign(kp.privateKey, 'SHA-256');

  const md = sha256(bcanon);
  const signedAttrs = new pkijs.SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      new pkijs.Attribute({
        type: '1.2.840.113549.1.9.3',
        values: [new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' })],
      }),
      new pkijs.Attribute({
        type: '1.2.840.113549.1.9.4',
        values: [new asn1js.OctetString({ valueHex: md.buffer.slice(0) as ArrayBuffer })],
      }),
    ],
  });
  const signer = new pkijs.SignerInfo({
    version: 1,
    sid: new pkijs.IssuerAndSerialNumber({ issuer: cert.issuer, serialNumber: cert.serialNumber }),
    signedAttrs,
  });
  const signed = new pkijs.SignedData({
    version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: '1.2.840.113549.1.7.1' }),
    signerInfos: [signer],
    certificates: [cert],
  });
  await signed.sign(kp.privateKey, 0, 'SHA-256');
  const ci = new pkijs.ContentInfo({
    contentType: pkijs.id_ContentType_SignedData,
    content: signed.toSchema(true),
  });
  const p7s = Buffer.from(new Uint8Array(ci.toSchema().toBER(false)));

  return { bcanonB64, pubkeyUncompressedHex, binding, p7s };
}

test('generate — creates a keypair and navigates to /sign', async ({ page }) => {
  await page.goto('/generate');
  await page.getByTestId('generate-key').click();
  const pubkey = await page.getByTestId('pubkey-hex').textContent();
  expect(pubkey).toMatch(/^0x04[0-9a-f]{128}$/);
  await page.getByTestId('create-binding').click();
  await expect(page).toHaveURL(/\/sign$/);
});

test('sign — renders canonical preview, hash, download, jurisdiction tools', async ({ page }) => {
  // Walk /generate first so session state is populated.
  await page.goto('/generate');
  await page.getByTestId('generate-key').click();
  await page.getByTestId('create-binding').click();
  await expect(page).toHaveURL(/\/sign$/);

  const preview = await page.getByTestId('bcanon-preview').textContent();
  expect(preview).toContain('"version":"QKB/1.0"');
  expect(preview).toContain('"scheme":"secp256k1"');

  const hash = await page.getByTestId('bcanon-hash').textContent();
  expect(hash).toMatch(/^0x[0-9a-f]{64}$/);

  // Download round-trip via Playwright's download API.
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('download-binding').click(),
  ]);
  expect(download.suggestedFilename()).toBe('binding.qkb.json');

  // Jurisdiction pointers are present.
  const tools = await page.getByTestId('qes-tools').textContent();
  expect(tools).toMatch(/Diia|Дія/);
  expect(tools).toMatch(/SK/);
  expect(tools).toMatch(/Szafir/);
});

test('sign — missing-binding fallback when session is empty', async ({ page }) => {
  await page.goto('/sign');
  await expect(page.getByTestId('sign-missing')).toBeVisible();
});

test('upload — missing-binding fallback when session is empty', async ({ page }) => {
  await page.goto('/upload');
  await expect(page.getByTestId('upload-missing')).toBeVisible();
});

test('upload — parse → verify (stubbed) → mock-prove → /register handoff', async ({ page }) => {
  // Mint binding + keypair + p7s in Node so the spec stays deterministic
  // and fast. Seed the SPA's sessionStorage before /upload loads, then feed
  // the p7s through the file input.
  const fixture = await buildFlowFixture();

  await page.addInitScript((f) => {
    sessionStorage.setItem(
      'qkb.session.v1',
      JSON.stringify({
        bcanonB64: f.bcanonB64,
        pubkeyUncompressedHex: f.pubkeyUncompressedHex,
        binding: f.binding,
        locale: 'en',
      }),
    );
    // Stub the verifier — /upload still runs parseCades + buildLeafWitness
    // for real, but skipping verifyQes means we don't need the minted CA to
    // be in trusted-cas.json.
    (window as unknown as { __QKB_VERIFY__: () => Promise<unknown> }).__QKB_VERIFY__ =
      async () => ({ ok: true, algorithmTag: 1, caMerkleIndex: 0 });
  }, {
    bcanonB64: fixture.bcanonB64,
    pubkeyUncompressedHex: fixture.pubkeyUncompressedHex,
    binding: fixture.binding,
  });

  await page.goto('/upload');
  await page.setInputFiles('[data-testid="file-input"]', {
    name: 'binding.qkb.json.p7s',
    mimeType: 'application/pkcs7-signature',
    buffer: fixture.p7s,
  });

  await expect(page.getByTestId('upload-done')).toBeVisible({ timeout: 30_000 });
  await page.getByTestId('upload-next').click();
  await expect(page).toHaveURL(/\/register$/);
});

test('register — missing-bundle fallback when session has no split proofs', async ({ page }) => {
  // Split-proof pivot (2026-04-18): /register renders the missing-bundle
  // banner unless proofLeaf, publicLeaf, proofChain, AND publicChain are
  // all present. A partial session (only one side) still trips this guard.
  await page.goto('/register');
  await expect(page.getByTestId('register-missing')).toBeVisible();
});

test('register — connect wallet + submit register() via mocked EIP-1193', async ({ page }) => {
  // Seed session with a mock SPLIT-PROOF bundle so /register renders the
  // connect/submit surface. Split-proof pivot (2026-04-18): V3's register()
  // takes a leaf proof (13-signal public output) AND a chain proof
  // (3-signal public output); the route guard requires all four session
  // keys (proofLeaf + publicLeaf + proofChain + publicChain) to be present
  // before rendering the submit path, falling through to the missing-bundle
  // banner otherwise.
  //
  // Shapes:
  //   - Groth16Proof: {pi_a:[string,string,'1'], pi_b:[[s,s],[s,s],['1','0']], pi_c:[s,s,'1']}
  //     The third element is the normalized Jacobian z-coord; packProof
  //     projects to the first two per element.
  //   - publicLeaf (13): pkX[0..3], pkY[0..3], ctxHash[8], declHash[9],
  //     timestamp[10], nullifier[11], leafSpkiCommit[12] — all decimal
  //     strings.
  //   - publicChain (3): rTL[0], algorithmTag[1] ('1' = ECDSA),
  //     leafSpkiCommit[2] — must equal publicLeaf[12] for the V3 on-chain
  //     equality check. The __QKB_SUBMIT_TX__ stub below bypasses real ABI
  //     encoding so strict equality isn't verified in-test, but the test
  //     data mirrors the invariant to stay faithful.
  const mockAddress = '0x00000000000000000000000000000000000000aa';
  const mockTx = '0xdeadbeef'.padEnd(66, '0');
  const mockCommit = '99';
  await page.addInitScript(
    ({ addr, tx, commit }) => {
      const mockProof = {
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
      sessionStorage.setItem(
        'qkb.session.v1',
        JSON.stringify({
          proofLeaf: mockProof,
          publicLeaf: [
            '1', '2', '3', '4',      // pkX
            '5', '6', '7', '8',      // pkY
            '0',                     // ctxHash (empty context)
            '1234',                  // declHash
            '1730000000',            // timestamp
            '42',                    // nullifier
            commit,                  // leafSpkiCommit
          ],
          proofChain: mockProof,
          publicChain: [
            '4660',                  // rTL (0x1234)
            '1',                     // algorithmTag (ECDSA)
            commit,                  // leafSpkiCommit — matches publicLeaf[12]
          ],
          algorithmTag: 1,
        }),
      );
      (window as unknown as { __QKB_ETHEREUM__: unknown }).__QKB_ETHEREUM__ = {
        request: async (args: { method: string }) => {
          if (args.method === 'eth_requestAccounts') return [addr];
          if (args.method === 'eth_sendTransaction') return tx;
          return null;
        },
      };
      (window as unknown as { __QKB_SUBMIT_TX__: unknown }).__QKB_SUBMIT_TX__ =
        async (input: { from: string }) => ({ txHash: tx, pkAddr: input.from });
    },
    { addr: mockAddress, tx: mockTx, commit: mockCommit },
  );

  await page.goto('/register');
  await page.getByTestId('connect-wallet').click();
  await expect(page.getByTestId('wallet-address')).toHaveText(mockAddress);
  await page.getByTestId('submit-register').click();
  await expect(page.getByTestId('register-success')).toBeVisible();
  await expect(page.getByTestId('tx-hash')).toHaveText(mockTx);
  await expect(page.getByTestId('pk-addr')).toHaveText(mockAddress);
});
