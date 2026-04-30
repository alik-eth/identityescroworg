// Route smoke coverage for the surfaces that don't have a dedicated
// flow spec. Each route gets:
//   - a render assertion (heading or stable testid),
//   - a no-uncaught-error assertion,
//   - one piece of structural content that proves the page wired up
//     correctly (table rows, QR image, etc.).
//
// Routes covered here:
//   /integrations         — V4-era integrators landing.
//   /ua/use-desktop       — direct load (the redirect-target case is
//                           covered by v5-device-gating.spec.ts).
//
// Production-mode SPA caveat: the vite build sets `base: './'`, so deep
// paths can't load the JS bundle from `/integrations/assets/...`. We
// follow the convention used elsewhere in this suite — load `/`, then
// push the route via `history.pushState` and let TanStack Router pick
// it up.
import { expect, test } from '@playwright/test';

async function pushRoute(
  page: import('@playwright/test').Page,
  path: string,
) {
  await page.evaluate((p) => {
    window.history.pushState({}, '', p);
    window.dispatchEvent(new PopStateEvent('popstate'));
  }, path);
}

test.describe('/integrations', () => {
  test('renders heading + Solidity / TypeScript code blocks', async ({ page }) => {
    await page.goto('/');
    await pushRoute(page, '/integrations');
    await expect(
      page.getByRole('heading', { name: /Integrate QKB verification/i }),
    ).toBeVisible({ timeout: 5_000 });
    await expect(page.getByRole('heading', { name: /Solidity/i })).toBeVisible();
    await expect(
      page.getByRole('heading', { name: /TypeScript \(viem\)/i }),
    ).toBeVisible();
  });

  test('renders the deployments table with the sepolia + base rows', async ({
    page,
  }) => {
    await page.goto('/');
    await pushRoute(page, '/integrations');
    // The deployments table is the source of truth for "where to point
    // your client" — both the live (sepolia) and zero-addressed (base)
    // entries must be visible. If either row drops out the integrators
    // page silently goes wrong.
    const table = page.getByRole('table');
    await expect(table).toBeVisible({ timeout: 5_000 });
    await expect(table.getByRole('cell', { name: /^sepolia$/ })).toBeVisible();
    await expect(table.getByRole('cell', { name: /^base$/ })).toBeVisible();
  });

  test('back link returns to /', async ({ page }) => {
    await page.goto('/');
    await pushRoute(page, '/integrations');
    await page.getByRole('link', { name: /^← back$/ }).click();
    await expect(page).toHaveURL(/\/$/);
    await expect(
      page.getByRole('heading', { name: /Verified Identity/i }),
    ).toBeVisible();
  });

  test('does not throw uncaught JS errors on initial load', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await page.goto('/');
    await pushRoute(page, '/integrations');
    await page.waitForLoadState('networkidle');
    expect(errors).toEqual([]);
  });
});

test.describe('/ua/use-desktop direct render', () => {
  test('renders the use-desktop testid + QR image + URL', async ({ page }) => {
    await page.goto('/');
    await pushRoute(page, '/ua/use-desktop');
    // The testid is the canonical signal that the gate-target page
    // mounted, regardless of locale. The QR image is its own
    // testid. Both must be visible on a direct load (no redirect).
    await expect(page.getByTestId('use-desktop-page')).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByTestId('use-desktop-qr')).toBeVisible();
    // The bare URL is rendered in a mono block so users can copy it
    // by hand if the QR is unavailable.
    await expect(
      page.getByText(/identityescrow\.org\/ua\/registerV5/),
    ).toBeVisible();
  });

  test('back link returns to /', async ({ page }) => {
    await page.goto('/');
    await pushRoute(page, '/ua/use-desktop');
    await page.getByRole('link', { name: /^← back$/ }).click();
    await expect(page).toHaveURL(/\/$/);
  });

  test('does not throw uncaught JS errors on initial load', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await page.goto('/');
    await pushRoute(page, '/ua/use-desktop');
    await page.waitForLoadState('networkidle');
    expect(errors).toEqual([]);
  });
});
