import { test, expect } from '@playwright/test';
import { injectMockWallet } from './helpers/walletMock';
import { stubSepoliaRpc } from './helpers/rpcMock';

test('after deadline, mint button shows closed copy', async ({ page }) => {
  await injectMockWallet(page, {
    address: ('0x' + 'a'.repeat(40)) as `0x${string}`,
    chainId: 11155111,
  });
  await page.addInitScript(() => {
    const realNow = Date.now;
    Date.now = () => realNow() + 365 * 24 * 60 * 60 * 1000 * 10;
  });
  await stubSepoliaRpc(page, {
    registry: '0xd33B73EB9c78d7AcE7AB84adAF4c518573Ce47a6',
    identityEscrowNft: '0x30E13c76D0BB02Ab4a65048B6546ABC3ADDabA48',
    nullifierFor: () => '00'.repeat(31) + 'aa',
    tokenIdForNullifier: () => '00'.repeat(32),
  });
  await page.goto('/');
  await expect(page.getByRole('button', { name: /mint window closed/i })).toBeVisible({
    timeout: 10_000,
  });
});
