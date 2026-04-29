// Device-gating e2e (spec amendment 9c866ad). Confirms that out-of-gate
// devices — here, an in-app WebView identified by UA string — get rerouted
// to /ua/use-desktop BEFORE the V5 prove flow renders Step 1.
//
// We stub navigator.userAgent + navigator.storage in an init script so the
// gate fires on first paint, then push the V5 register route through the
// SPA router (matching the convention in v5-register-route.spec.ts).
import { expect, test } from '@playwright/test';

const TELEGRAM_UA =
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/126.0.0.0 Mobile Safari/537.36 Telegram/10.13.0';
const FLAGSHIP_UA =
  'Mozilla/5.0 (Linux; Android 14; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36';

async function pushV5Route(page: import('@playwright/test').Page) {
  await page.evaluate(() => {
    window.history.pushState({}, '', '/ua/registerV5');
    window.dispatchEvent(new PopStateEvent('popstate'));
  });
}

test.describe('/ua/registerV5 device gate', () => {
  test('Telegram in-app WebView is rerouted to /ua/use-desktop', async ({ browser }) => {
    const ctx = await browser.newContext({ userAgent: TELEGRAM_UA });
    const page = await ctx.newPage();
    // Stub a permissive storage manager so the WebView UA path is the
    // only thing that fails. Without this, jsdom + headless Chromium
    // would fail an earlier gate first.
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'storage', {
        configurable: true,
        value: {
          persist: () => Promise.resolve(true),
          estimate: () => Promise.resolve({ quota: 4_000_000_000, usage: 0 }),
        },
      });
      Object.defineProperty(navigator, 'deviceMemory', {
        configurable: true,
        value: 8,
      });
    });

    await page.goto('/');
    await pushV5Route(page);

    // The gate runs in useEffect; allow it to settle. The use-desktop
    // page exposes a stable testid for the assertion.
    await expect(page.getByTestId('use-desktop-page')).toBeVisible({
      timeout: 5_000,
    });
    // Step 1 of the prove flow MUST NOT have rendered.
    await expect(
      page.getByRole('heading', { name: /Connect your wallet/i }),
    ).toHaveCount(0);

    await ctx.close();
  });

  test('flagship UA + ready storage stays on /ua/registerV5 and renders Step 1', async ({
    browser,
  }) => {
    const ctx = await browser.newContext({ userAgent: FLAGSHIP_UA });
    const page = await ctx.newPage();
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'storage', {
        configurable: true,
        value: {
          persist: () => Promise.resolve(true),
          estimate: () => Promise.resolve({ quota: 4_000_000_000, usage: 0 }),
        },
      });
      Object.defineProperty(navigator, 'deviceMemory', {
        configurable: true,
        value: 8,
      });
    });

    await page.goto('/');
    await pushV5Route(page);

    // The Step 1 heading is the canonical signal that the gate let us
    // through; it's the first heading rendered after the gate resolves.
    await expect(
      page.getByRole('heading', { name: /Connect your wallet/i }),
    ).toBeVisible({ timeout: 5_000 });
    await expect(page.getByTestId('use-desktop-page')).toHaveCount(0);

    await ctx.close();
  });
});
