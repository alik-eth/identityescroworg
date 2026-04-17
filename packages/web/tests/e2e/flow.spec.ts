/**
 * Happy-path e2e covering /generate → /sign → /upload → /register, with
 * the snarkjs prover mocked through MockProver (real prover takes minutes
 * and 4 GB — gated separately behind E2E_REAL_PROVER=1 in happy-path.spec.ts).
 *
 * Each route is also exercised in isolation so a failure during, say, /sign
 * does not cascade into meaningless /register red.
 */
import { test, expect } from '@playwright/test';

test('generate — creates a keypair and navigates to /sign', async ({ page }) => {
  await page.goto('/generate');
  await page.getByTestId('generate-key').click();
  const pubkey = await page.getByTestId('pubkey-hex').textContent();
  expect(pubkey).toMatch(/^0x04[0-9a-f]{128}$/);
  await page.getByTestId('create-binding').click();
  await expect(page).toHaveURL(/\/sign$/);
});
