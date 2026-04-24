/**
 * UA flow e2e — /ua/generate → /ua/sign → /ua/upload → /ua/register.
 *
 * Design:
 *   - MockProver keeps the `flow` project's 30s budget comfortable.
 *   - `.p7s` upload isn't fixture-seeded (no committed real Diia test cert);
 *     we instead drive the session-guard + dispatch layer directly by
 *     seeding sessionStorage with the shape `/ua/upload` would otherwise
 *     produce.
 *   - Registry submit is stubbed at the `__QKB_SUBMIT_TX_V4__` boundary so
 *     we can assert the calldata shape without needing a live Sepolia tx.
 *   - An AJV draft-2020 schema check runs against the QKB/2.0 binding that
 *     `/ua/generate` persists, pinning the page output against the
 *     committed schema.
 */
import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const __here = dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = resolve(
  __here,
  '../../../../fixtures/schemas/qkb-binding-v2.schema.json',
);

function compileV2Schema() {
  const schema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf8'));
  const ajv = new Ajv2020({ strict: true, allErrors: true, allowUnionTypes: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

// 16-sig / 3-sig fixture matching the circuit ordering — matches the
// publicLeafV4 shape produced by buildUaLeafPublicSignalsV4 for a
// synthetic binding. The registry-address + pubkey values don't matter
// for calldata-shape assertions; we just need a well-formed 16/3 tuple.
const SAMPLE_PK_HEX = `04${'ab'.repeat(64)}`;
const SAMPLE_PROOF = {
  pi_a: ['1', '2', '1'],
  pi_b: [
    ['3', '4'],
    ['5', '6'],
    ['1', '0'],
  ],
  pi_c: ['7', '8', '1'],
  protocol: 'groth16',
  curve: 'bn128',
};
const SAMPLE_PUBLIC_LEAF_V4 = [
  '1', '2', '3', '4',
  '5', '6', '7', '8',
  '0',                          // ctxHash
  '1234',                       // policyLeafHash
  '1eef6cacb886925d014ff151d4dbef9b37b16cc836f47b1ec89fc821496e2414', // policyRoot (UA)
  '1780000000',                 // timestamp
  '42',                         // nullifier
  '99',                         // leafSpkiCommit
  '12583541437132735734108669866114103169564651237895298778035846191048104863326', // dobCommit = Poseidon(0,1)
  '0',                          // dobSupported
];
const SAMPLE_PUBLIC_CHAIN_V4 = ['4660', '1', '99'];

/**
 * Asset paths are emitted with a `./` base so the SPA can run from file://
 * (pinned by the dist-smoke vitest guard). That means Playwright can't
 * directly `page.goto('/ua/register')` — the bundle would 404 trying to
 * load `/ua/assets/*`. Navigate via the SPA root + client-side pushState.
 */
async function gotoUa(page: import('@playwright/test').Page, path: string): Promise<void> {
  await page.goto('/');
  // Wait for the SPA bundle to execute.
  await page.waitForFunction(() => typeof window !== 'undefined' && !!document.querySelector('header'));
  await page.evaluate((p) => {
    window.history.pushState({}, '', p);
    window.dispatchEvent(new PopStateEvent('popstate'));
  }, path);
}

test.describe('/ua/ flow — end-to-end', () => {
  test('/ua/generate emits a schema-valid QKB/2.0 binding and lands on /ua/sign', async ({ page }) => {
    await gotoUa(page, '/ua/generate');
    await expect(page.getByTestId('generate-key')).toBeVisible();
    await page.getByTestId('generate-key').click();
    await expect(page.getByTestId('pubkey-hex')).toBeVisible();
    await page.getByTestId('create-binding').click();
    // /ua/sign landing signals the navigation happened; the V1 SignScreen is
    // reused under /ua/sign in Commit 4b and shows the heading copy.
    await page.waitForURL(/\/ua\/sign(\/?)?$/);

    const sessionRaw = await page.evaluate(() => sessionStorage.getItem('qkb.session.v1'));
    expect(sessionRaw).toBeTruthy();
    const session = JSON.parse(sessionRaw!);
    expect(session.country).toBe('UA');
    expect(session.bindingV2).toBeDefined();
    expect(session.bindingV2.version).toBe('QKB/2.0');
    expect(session.bindingV2.policy.policyId).toBe('qkb-default-ua');
    expect(session.bindingV2.policy.policyVersion).toBe(1);
    expect(session.bindingV2.display?.lang).toBe('uk');
    expect(session.bindingV2.display?.template).toBe('qkb-default-ua/v1');
    expect(session.bcanonV2B64).toBeTruthy();

    const validate = compileV2Schema();
    const ok = validate(session.bindingV2);
    expect(ok, JSON.stringify(validate.errors ?? [], null, 2)).toBe(true);
  });

  test('/ua/register without V2 session → missing-V2 banner + auto-redirect to /ua/generate', async ({ page }) => {
    // Make sure no session state leaks between tests.
    await page.addInitScript(() => sessionStorage.clear());
    await gotoUa(page, '/ua/register');
    await expect(page.getByTestId('register-missing-v2')).toBeVisible();
    await page.waitForURL(/\/ua\/generate(\/?)?$/, { timeout: 6_000 });
  });

  test('/ua/register with only V2 (no proofs) → missing-proof banner', async ({ page }) => {
    await page.addInitScript((pk) => {
      sessionStorage.setItem(
        'qkb.session.v1',
        JSON.stringify({
          country: 'UA',
          bcanonV2B64: 'AA==',
          pubkeyUncompressedHex: pk,
          bindingV2: {
            version: 'QKB/2.0',
            statementSchema: 'qkb-binding-core/v1',
            pk: `0x${pk}`,
            scheme: 'secp256k1',
            context: '0x',
            timestamp: 1_780_000_000,
            nonce: `0x${'11'.repeat(32)}`,
            policy: {
              leafHash: '0x2d00e73da8dd4dc99f04371d3ce01ecbcf4ad8e476c9017a304c57873494f812',
              policyId: 'qkb-default-ua',
              policyVersion: 1,
              bindingSchema: 'qkb-binding-core/v1',
            },
            assertions: {
              keyControl: true,
              bindsContext: true,
              acceptsAttribution: true,
              revocationRequired: true,
            },
          },
        }),
      );
    }, SAMPLE_PK_HEX);
    await gotoUa(page, '/ua/register');
    await expect(page.getByTestId('register-missing-proof')).toBeVisible();
    // Link back to /ua/upload is present and clickable.
    const uploadLink = page.getByRole('link', { name: /ua\/upload/ });
    await expect(uploadLink).toBeVisible();
  });

  test('/ua/register with full V4 bundle → connect-wallet + stubbed submit hits encodeV4RegisterCalldata boundary', async ({ page }) => {
    // Seed session + install the EIP-1193 stub + submit-boundary stub.
    await page.addInitScript(
      (init: {
        pk: string;
        publicLeaf: string[];
        publicChain: string[];
        proof: unknown;
      }) => {
        sessionStorage.setItem(
          'qkb.session.v1',
          JSON.stringify({
            country: 'UA',
            bcanonV2B64: 'AA==',
            pubkeyUncompressedHex: init.pk,
            bindingV2: {
              version: 'QKB/2.0',
              statementSchema: 'qkb-binding-core/v1',
              pk: `0x${init.pk}`,
              scheme: 'secp256k1',
              context: '0x',
              timestamp: 1_780_000_000,
              nonce: `0x${'11'.repeat(32)}`,
              policy: {
                leafHash:
                  '0x2d00e73da8dd4dc99f04371d3ce01ecbcf4ad8e476c9017a304c57873494f812',
                policyId: 'qkb-default-ua',
                policyVersion: 1,
                bindingSchema: 'qkb-binding-core/v1',
              },
              assertions: {
                keyControl: true,
                bindsContext: true,
                acceptsAttribution: true,
                revocationRequired: true,
              },
            },
            proofLeafV4: init.proof,
            publicLeafV4: init.publicLeaf,
            proofChainV4: init.proof,
            publicChainV4: init.publicChain,
          }),
        );

        // Stub EIP-1193: eth_requestAccounts + wallet_switchEthereumChain +
        // eth_chainId so the connect → chain-guard sequence succeeds.
        (window as unknown as { __QKB_ETHEREUM__: unknown }).__QKB_ETHEREUM__ = {
          request: async ({ method }: { method: string }) => {
            if (method === 'eth_requestAccounts')
              return ['0x1234567890123456789012345678901234567890'];
            if (method === 'wallet_switchEthereumChain') return null;
            if (method === 'eth_chainId') return '0xaa36a7'; // 11155111 (Sepolia)
            throw new Error(`unexpected EIP-1193 call: ${method}`);
          },
        };

        // Submit-boundary stub: capture the calldata shape assertions would
        // need, return a deterministic tx hash + placeholder pk address.
        (
          window as unknown as { __QKB_SUBMIT_TX_V4__?: unknown }
        ).__QKB_SUBMIT_TX_V4__ = async (input: {
          proofLeaf: unknown;
          publicLeaf: readonly string[];
          proofChain: unknown;
          publicChain: readonly string[];
          pk: string;
        }) => {
          (
            window as unknown as { __QKB_LAST_SUBMIT__?: unknown }
          ).__QKB_LAST_SUBMIT__ = {
            publicLeafLen: input.publicLeaf.length,
            publicChainLen: input.publicChain.length,
            pk: input.pk,
          };
          return {
            txHash: '0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef',
            pkAddr: '0x1234567890123456789012345678901234567890',
          };
        };
      },
      {
        pk: SAMPLE_PK_HEX,
        publicLeaf: SAMPLE_PUBLIC_LEAF_V4,
        publicChain: SAMPLE_PUBLIC_CHAIN_V4,
        proof: SAMPLE_PROOF,
      },
    );

    await gotoUa(page, '/ua/register');
    // UA registry address surfaced on the screen.
    await expect(page.getByTestId('ua-register-addr')).toHaveText(
      '0x4c8541f4Ff16AE2650C4e146587E81eD56A2456C',
    );
    await page.getByTestId('connect-wallet').click();
    await expect(page.getByTestId('wallet-address')).toBeVisible();
    await page.getByTestId('submit-register').click();

    await expect(page.getByTestId('register-success')).toBeVisible();
    await expect(page.getByTestId('tx-hash')).toHaveText(
      '0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef',
    );

    // Assert the submit-boundary capture saw a 16-signal publicLeafV4 and
    // 3-signal publicChainV4 — the invariant that the V4 ABI fragment
    // expects. Calldata-length was unit-tested; here we confirm the
    // right shape flows through to the submit seam.
    const captured = (await page.evaluate(
      () =>
        (window as unknown as {
          __QKB_LAST_SUBMIT__?: {
            publicLeafLen: number;
            publicChainLen: number;
            pk: string;
          };
        }).__QKB_LAST_SUBMIT__,
    )) as { publicLeafLen: number; publicChainLen: number; pk: string } | undefined;
    expect(captured).toBeDefined();
    expect(captured?.publicLeafLen).toBe(16);
    expect(captured?.publicChainLen).toBe(3);
    expect(captured?.pk).toBe(`0x${SAMPLE_PK_HEX}`);
  });

  test('/ua/upload renders and exposes the pick-p7s affordance when V2 session is present', async ({ page }) => {
    await page.addInitScript((pk) => {
      sessionStorage.setItem(
        'qkb.session.v1',
        JSON.stringify({
          country: 'UA',
          bcanonV2B64: 'AA==',
          pubkeyUncompressedHex: pk,
          bindingV2: {
            version: 'QKB/2.0',
            statementSchema: 'qkb-binding-core/v1',
            pk: `0x${pk}`,
            scheme: 'secp256k1',
            context: '0x',
            timestamp: 1_780_000_000,
            nonce: `0x${'11'.repeat(32)}`,
            policy: {
              leafHash: '0x2d00e73da8dd4dc99f04371d3ce01ecbcf4ad8e476c9017a304c57873494f812',
              policyId: 'qkb-default-ua',
              policyVersion: 1,
              bindingSchema: 'qkb-binding-core/v1',
            },
            assertions: {
              keyControl: true,
              bindsContext: true,
              acceptsAttribution: true,
              revocationRequired: true,
            },
          },
        }),
      );
    }, SAMPLE_PK_HEX);
    await gotoUa(page, '/ua/upload');
    await expect(page.getByTestId('pick-p7s')).toBeVisible();
    await expect(page.getByTestId('upload-status')).toHaveText(/status: idle/);
  });
});
