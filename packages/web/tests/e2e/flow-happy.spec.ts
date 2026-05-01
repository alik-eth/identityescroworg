import { test, expect } from '@playwright/test';
import { injectMockWallet } from './helpers/walletMock';

test('flow — landing → cli → submit navigation works connected', async ({ page }) => {
  await injectMockWallet(page, {
    address: ('0x' + 'a'.repeat(40)) as `0x${string}`,
    chainId: 11155111,
  });
  await page.goto('/');
  await page.getByRole('button', { name: /begin verification/i }).click();
  await expect(page).toHaveURL(/\/ua\/cli/);
  await page.getByRole('link', { name: /I have proof\.json/i }).click();
  await expect(page).toHaveURL(/\/ua\/submit/);
  await expect(page.getByText(/Drag proof\.json here/i)).toBeVisible();
});
