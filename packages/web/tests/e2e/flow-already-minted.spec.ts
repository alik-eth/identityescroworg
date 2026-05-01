import { test, expect } from '@playwright/test';
import { injectMockWallet } from './helpers/walletMock';
import { stubSepoliaRpc } from './helpers/rpcMock';

test('returning holder sees view-certificate state', async ({ page }) => {
  await injectMockWallet(page, {
    address: ('0x' + 'a'.repeat(40)) as `0x${string}`,
    chainId: 11155111,
  });
  await stubSepoliaRpc(page, {
    registry: '0xd33B73EB9c78d7AcE7AB84adAF4c518573Ce47a6',
    identityEscrowNft: '0x30E13c76D0BB02Ab4a65048B6546ABC3ADDabA48',
    nullifierFor: () => '00'.repeat(31) + 'aa',
    tokenIdForNullifier: () => '00'.repeat(31) + '07',
  });
  await page.goto('/');
  await expect(page.getByRole('button', { name: /view your certificate/i })).toBeVisible({
    timeout: 10_000,
  });
});
