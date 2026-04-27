import { test, expect, devices } from '@playwright/test';

test.use({ ...devices['iPhone 14'] });

test('landing layout works on iPhone 14', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: /Verified Identity/i })).toBeVisible();
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth,
  );
  expect(overflow).toBe(false);
});
