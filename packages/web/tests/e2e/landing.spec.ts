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

test('landing — privacy-escrow section renders the three labels', async ({ page }) => {
  await page.addInitScript(() => {
    try {
      window.localStorage.setItem('qkb.lang', 'en');
    } catch {
      /* ignore */
    }
  });
  await page.goto('/');
  // Each label exists once in EN locale and is the canonical signal
  // that the privacy section rendered without falling back to default
  // i18next strings or skipping the dl entirely.
  await expect(page.getByText(/What is on the ledger/i)).toBeVisible();
  await expect(page.getByText(/What is not on the ledger/i)).toBeVisible();
  await expect(
    page.getByText(/What can be recovered, by whom, under what process/i),
  ).toBeVisible();
  await expect(
    page.getByRole('heading', { name: /Identity, escrowed\./i }),
  ).toBeVisible();
});

test('landing — ceremony footer link is visible and routes to /ceremony', async ({
  page,
}) => {
  await page.addInitScript(() => {
    try {
      window.localStorage.setItem('qkb.lang', 'en');
    } catch {
      /* ignore */
    }
  });
  await page.goto('/');
  // Stable testid surfaced exactly once on the landing page; the link
  // is the only entry point to /ceremony from the public-facing flow.
  const ceremonyEntry = page.getByTestId('landing-ceremony-link');
  await expect(ceremonyEntry).toBeVisible();
  const link = ceremonyEntry.getByRole('link', {
    name: /trusted setup ceremony/i,
  });
  await expect(link).toHaveAttribute('href', '/ceremony');
  await link.click();
  await expect(page).toHaveURL(/\/ceremony$/);
  await expect(
    page.getByRole('heading', { name: /A trusted setup\. In public\./i }),
  ).toBeVisible({ timeout: 5_000 });
});
