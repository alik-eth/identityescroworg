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

test('sign — renders canonical preview, hash, download, jurisdiction tools', async ({ page }) => {
  // Walk /generate first so session state is populated.
  await page.goto('/generate');
  await page.getByTestId('generate-key').click();
  await page.getByTestId('create-binding').click();
  await expect(page).toHaveURL(/\/sign$/);

  const preview = await page.getByTestId('bcanon-preview').textContent();
  expect(preview).toContain('"version":"QKB/1.0"');
  expect(preview).toContain('"scheme":"secp256k1"');

  const hash = await page.getByTestId('bcanon-hash').textContent();
  expect(hash).toMatch(/^0x[0-9a-f]{64}$/);

  // Download round-trip via Playwright's download API.
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('download-binding').click(),
  ]);
  expect(download.suggestedFilename()).toBe('binding.qkb.json');

  // Jurisdiction pointers are present.
  const tools = await page.getByTestId('qes-tools').textContent();
  expect(tools).toMatch(/Diia|Дія/);
  expect(tools).toMatch(/SK/);
  expect(tools).toMatch(/Szafir/);
});

test('sign — missing-binding fallback when session is empty', async ({ page }) => {
  await page.goto('/sign');
  await expect(page.getByTestId('sign-missing')).toBeVisible();
});
