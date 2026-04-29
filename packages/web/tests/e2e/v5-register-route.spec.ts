// Smoke test for the V5 register-flow route. Confirms Step 1 renders,
// that no JS errors fire on initial load, and that the step-indicator
// is present — without requiring a wallet to actually connect.
//
// Important: the production vite build uses `base: './'` for relative
// asset paths, which means deep-linking to `/ua/registerV5` 404s the JS
// bundle (`/ua/assets/...` instead of `/assets/...`). All existing
// flow.spec.ts files navigate via `/` first, then use the SPA router.
// We follow that convention: load `/`, then push the V5 route through
// `history.pushState` and let TanStack Router pick it up. The full
// happy path (with mock wallet + mock prover) lives in v5-flow.spec.ts
// (Task 11).
//
// As of spec amendment 9c866ad the route is gated by
// assessDeviceCapability(); headless Chromium would otherwise be
// rerouted to /ua/use-desktop. We stub the storage manager up-front in
// each test so the gate clears and Step 1 renders.
import { expect, test } from '@playwright/test';

async function stubDeviceGate(page: import('@playwright/test').Page) {
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
}

async function gotoV5Route(page: import('@playwright/test').Page) {
  await stubDeviceGate(page);
  await page.goto('/');
  await page.evaluate(() => {
    window.history.pushState({}, '', '/ua/registerV5');
    window.dispatchEvent(new PopStateEvent('popstate'));
  });
}

test.describe('/ua/registerV5', () => {
  test('renders Step 1 (Connect your wallet) by default', async ({ page }) => {
    await gotoV5Route(page);
    await expect(
      page.getByRole('heading', { name: /Connect your wallet/i }),
    ).toBeVisible();
  });

  test('renders the 4-step indicator on initial load', async ({ page }) => {
    await gotoV5Route(page);
    // The step indicator labels: 1 — Connect, 2 — Generate, 3 — Sign,
    // 4 — Prove + register. All 4 should be present even before the
    // user advances.
    await expect(page.getByText(/1 — Connect/i)).toBeVisible();
    await expect(page.getByText(/2 — Generate/i)).toBeVisible();
    await expect(page.getByText(/3 — Sign/i)).toBeVisible();
    await expect(page.getByText(/4 — Prove \+ register/i)).toBeVisible();
  });

  test('does not throw uncaught JS errors on initial load', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await gotoV5Route(page);
    await page.waitForLoadState('networkidle');
    expect(errors).toEqual([]);
  });

  test('exposes the RainbowKit Connect-Wallet button', async ({ page }) => {
    await gotoV5Route(page);
    // RainbowKit's default button text is "Connect Wallet".
    await expect(page.getByRole('button', { name: /Connect Wallet/i })).toBeVisible();
  });
});
