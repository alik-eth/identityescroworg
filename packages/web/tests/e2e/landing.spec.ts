import { test, expect } from '@playwright/test';
import { injectMockWallet } from './helpers/walletMock';

test('landing — disconnected shows ConnectButton', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: /Verified Identity/i })).toBeVisible();
  await expect(page.getByRole('button', { name: /connect wallet/i })).toBeVisible();
});

test('landing — connected wrong-chain shows switch CTA', async ({ page }) => {
  await injectMockWallet(page, {
    address: ('0x' + 'a'.repeat(40)) as `0x${string}`,
    chainId: 8453,
  });
  await page.goto('/');
  await expect(page.getByRole('button', { name: /switch network/i })).toBeVisible({
    timeout: 10_000,
  });
});
