// V5 mint-flow smoke tests. Pre-deploy state only (Sepolia/Base V5
// registry both zero-address until orchestration §9.4 closes), so the
// flow renders the "Awaiting V5 registry deployment" state. Real-mint
// happy path lives in v5-flow.spec.ts (Task 11) once the V5 registry
// is on-chain and a registration tx is in the test fixture.
import { expect, test } from '@playwright/test';

async function gotoMintNft(page: import('@playwright/test').Page) {
  await page.goto('/');
  await page.evaluate(() => {
    window.history.pushState({}, '', '/ua/mintNft');
    window.dispatchEvent(new PopStateEvent('popstate'));
  });
}

test.describe('/ua/mintNft', () => {
  test('renders the awaiting-deployment state pre-§9.4', async ({ page }) => {
    await gotoMintNft(page);
    // The V5 registry is zero-addressed in deployments.ts pre-deploy;
    // the mint step should surface the "awaiting" copy rather than a
    // disabled button (different remediation path for the user).
    await expect(page.getByTestId('v5-mint-pending-deploy')).toBeVisible();
  });

  test('does not throw uncaught JS errors on initial load', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await gotoMintNft(page);
    await page.waitForLoadState('networkidle');
    expect(errors).toEqual([]);
  });
});
