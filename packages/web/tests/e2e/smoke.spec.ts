import { test, expect } from '@playwright/test';

test('boots and renders title', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle(/QKB/);
  await expect(page.getByRole('heading', { name: /Verified Identity/i })).toBeVisible();
});
