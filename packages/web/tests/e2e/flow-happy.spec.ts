import { test, expect } from '@playwright/test';
import { injectMockWallet } from './helpers/walletMock';

// Post-Task-10: the primary "Begin verification" CTA now routes to the
// V5 browser-side flow (/ua/registerV5). The V4 CLI/submit flow is
// reachable via the secondary "Use the CLI instead" link surfaced
// beneath the primary CTA when the user is unregistered. This V4
// regression test exercises that secondary path so the V4 plumbing
// stays validated through the migration.
test('flow — V4 secondary path: landing → cli → submit navigation works connected', async ({ page }) => {
  await injectMockWallet(page, {
    address: ('0x' + 'a'.repeat(40)) as `0x${string}`,
    chainId: 11155111,
  });
  await page.goto('/');
  // Primary CTA points to V5 register flow; we want the V4 secondary path.
  await page.getByRole('link', { name: /Use the CLI instead/i }).click();
  await expect(page).toHaveURL(/\/ua\/cli/);
  await page.getByRole('link', { name: /I have proof\.json/i }).click();
  await expect(page).toHaveURL(/\/ua\/submit/);
  await expect(page.getByText(/Drag proof\.json here/i)).toBeVisible();
});
