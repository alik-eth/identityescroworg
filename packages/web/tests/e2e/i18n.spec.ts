import { test, expect } from '@playwright/test';

test('UK locale renders Ukrainian copy', async ({ page }) => {
  await page.addInitScript(() => {
    try {
      window.localStorage.setItem('qkb.lang', 'uk');
    } catch {
      /* ignore */
    }
  });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: /Підтверджена особа/i })).toBeVisible();
});

test('EN locale renders English copy', async ({ page }) => {
  await page.addInitScript(() => {
    try {
      window.localStorage.setItem('qkb.lang', 'en');
    } catch {
      /* ignore */
    }
  });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: /Verified Identity/i })).toBeVisible();
});
