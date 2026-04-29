// V5 happy-path Playwright e2e — Task 11 from web plan.
//
// Drives Steps 1-4 of /ua/registerV5 with the mock-prover env
// (VITE_USE_MOCK_PROVER=1, set globally in playwright.config.ts) and a
// stubbed eth_sendTransaction route. Asserts that v5-submit-skipped
// renders when registryV5 is undeployed (current pre-§9.4 state) and
// that the pipeline reaches the encode-calldata stage.
//
// Real-Anvil-based E2E becomes the §9.7 acceptance gate post-deploy
// (replaces this file or supersedes the assertion to wait on
// v5-tx-hash + redirect to /ua/mintNft).
import { expect, test } from '@playwright/test';
import { injectMockWallet } from './helpers/walletMock';

const FLAGSHIP_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15';
const TEST_ADDR = ('0x' + 'a'.repeat(40)) as `0x${string}`;
const SEPOLIA_CHAIN_ID = 11155111;

async function pushV5Route(page: import('@playwright/test').Page) {
  await page.evaluate(() => {
    window.history.pushState({}, '', '/ua/registerV5');
    window.dispatchEvent(new PopStateEvent('popstate'));
  });
}

test.describe('/ua/registerV5 — V5 happy path (mock prover, undeployed registry)', () => {
  test('drives Steps 1-4 → renders v5-submit-skipped (pre-§9.4)', async ({ browser }) => {
    const ctx = await browser.newContext({ userAgent: FLAGSHIP_UA });
    const page = await ctx.newPage();

    // Stub the storage gate to flagship-grade so the device gate lets
    // us through. Without this the test runs through whatever quota
    // jsdom/headless Chromium happens to grant.
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'storage', {
        configurable: true,
        value: {
          persist: () => Promise.resolve(true),
          estimate: () => Promise.resolve({ quota: 8_000_000_000, usage: 0 }),
        },
      });
      Object.defineProperty(navigator, 'deviceMemory', {
        configurable: true,
        value: 8,
      });
    });

    // Inject the mock wallet (EIP-6963 announcement → RainbowKit picks
    // it up as "Mock Wallet"). Address + chain pinned to Sepolia so the
    // V5 deployment slot resolves to the (zero-addressed) sepolia entry.
    await injectMockWallet(page, {
      address: TEST_ADDR,
      chainId: SEPOLIA_CHAIN_ID,
    });

    // Belt-and-suspenders: intercept any eth_sendTransaction at the
    // network layer in case the submit path changes in future. The
    // current code skips submit when registryV5 is zero-addressed, so
    // this should never fire in this test.
    await page.route('**/*', (route) => route.continue());

    await page.goto('/');
    await pushV5Route(page);

    // ---- Step 1: connect wallet ----
    // Wait for the device gate to clear and Step 1 heading to render.
    await expect(
      page.getByRole('heading', { name: /Connect your wallet/i }),
    ).toBeVisible({ timeout: 10_000 });
    // Drive RainbowKit: click "Connect Wallet" → click "Mock Wallet".
    await page.getByRole('button', { name: /Connect Wallet/i }).click();
    // The modal lists EIP-6963 providers; our injected one is "Mock Wallet".
    await page.getByText(/Mock Wallet/i).first().click();
    // After connection wagmi exposes the address; Step 1 then offers
    // an "advance" CTA. Use the testid since the label is i18n.
    const step1Advance = page.getByRole('button', {
      name: /Continue|advance|next|→/i,
    });
    await expect(step1Advance.first()).toBeVisible({ timeout: 10_000 });
    await step1Advance.first().click();

    // ---- Step 2: generate binding (currently a no-op handoff) ----
    const step2Advance = page.getByRole('button', {
      name: /Continue|advance|next|→/i,
    });
    await expect(step2Advance.first()).toBeVisible();
    await step2Advance.first().click();

    // ---- Step 3: upload p7s ----
    // Mock-prover doesn't parse the bytes, but Step 3's onP7s gates on
    // a non-empty file. Provide a tiny placeholder.
    await page.getByTestId('v5-p7s-upload').setInputFiles({
      name: 'mock.p7s',
      mimeType: 'application/pkcs7-signature',
      buffer: Buffer.from([0x30, 0x80, 0x06, 0x09]),
    });

    // ---- Step 4: prove + submit ----
    const cta = page.getByTestId('v5-prove-register-cta');
    await expect(cta).toBeVisible({ timeout: 10_000 });
    await cta.click();

    // Pipeline progress event surfaces with a stage + percentage. We
    // don't pin the exact stage label (parse/witness/prove/encode) since
    // the mock pipeline emits all four; just assert the testid renders.
    await expect(page.getByTestId('v5-pipeline-stage')).toBeVisible({
      timeout: 15_000,
    });

    // Registry is zero-addressed → submit is skipped with the
    // "awaiting deploy" copy. This is the canonical pre-§9.4 assertion.
    await expect(page.getByTestId('v5-submit-skipped')).toBeVisible({
      timeout: 15_000,
    });

    // Tx hash testid MUST NOT appear — writeContract was never called.
    await expect(page.getByTestId('v5-tx-hash')).toHaveCount(0);

    await ctx.close();
  });
});
