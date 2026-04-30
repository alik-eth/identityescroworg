// /ceremony route tests — coordination page for the V5 Phase 2 ceremony.
//
// Coverage:
//   - Landing renders the why/what/nav sections.
//   - Contribute page surfaces the four CLI commands + 32 GB RAM
//     requirement + "phones not supported" copy.
//   - Status feed handles the tri-state cleanly via JSON fixtures
//     intercepted at /ceremony/status.json:
//        planned     → no contributors yet
//        in-progress → some contributors, finalZkeySha256 = null
//        complete    → finalZkeySha256 non-null
//   - Verify page surfaces the "ceremony pending" state when no final
//     hash is published.
import { expect, test, type Route } from '@playwright/test';

const STATUS_PLANNED = {
  round: 0,
  totalRounds: 10,
  contributors: [],
  finalZkeySha256: null,
  beaconBlockHeight: null,
  beaconHash: null,
};

const STATUS_IN_PROGRESS = {
  round: 3,
  totalRounds: 10,
  contributors: [
    {
      name: 'alice@pse.dev',
      round: 1,
      attestation: '0xaaaa',
      completedAt: '2026-05-02T14:00:00Z',
    },
    {
      name: 'bob@ef.foundation',
      round: 2,
      attestation: '0xbbbb',
      completedAt: '2026-05-04T09:30:00Z',
    },
  ],
  currentRoundOpenedAt: '2026-05-08T09:00:00Z',
  finalZkeySha256: null,
  beaconBlockHeight: null,
  beaconHash: null,
};

const STATUS_COMPLETE = {
  round: 11,
  totalRounds: 10,
  contributors: [
    { name: 'alice@pse.dev', round: 1, completedAt: '2026-05-02T14:00:00Z' },
    { name: 'bob@ef.foundation', round: 2, completedAt: '2026-05-04T09:30:00Z' },
  ],
  finalZkeySha256:
    'deadbeefcafebabe0000000000000000000000000000000000000000deadbeef',
  beaconBlockHeight: 850000,
  beaconHash:
    '00000000000000000000fedcba9876543210fedcba9876543210fedcba987654',
};

async function pushCeremonyRoute(
  page: import('@playwright/test').Page,
  path: string,
) {
  await page.evaluate((p) => {
    window.history.pushState({}, '', p);
    window.dispatchEvent(new PopStateEvent('popstate'));
  }, path);
}

async function stubStatus(
  page: import('@playwright/test').Page,
  payload: unknown,
) {
  await page.route('**/ceremony/status.json*', (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(payload),
    }),
  );
}

test.describe('/ceremony', () => {
  test('landing renders why/trust/nav sections', async ({ page }) => {
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony');
    await expect(
      page.getByRole('heading', { name: /A trusted setup\. In public\./i }),
    ).toBeVisible({ timeout: 5_000 });
    await expect(page.getByTestId('ceremony-why')).toBeVisible();
    await expect(page.getByTestId('ceremony-trust')).toBeVisible();
    await expect(page.getByTestId('ceremony-nav')).toBeVisible();
  });

  test('contribute page surfaces all four commands + 32 GB requirement', async ({
    page,
  }) => {
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    await expect(
      page.getByRole('heading', { name: /Contribute on your machine/i }),
    ).toBeVisible({ timeout: 5_000 });
    // The four commands all render with their copy buttons.
    await expect(page.getByTestId('ceremony-cmd-download')).toBeVisible();
    await expect(page.getByTestId('ceremony-cmd-contribute')).toBeVisible();
    await expect(page.getByTestId('ceremony-cmd-verify')).toBeVisible();
    await expect(page.getByTestId('ceremony-cmd-upload')).toBeVisible();
    await expect(page.getByTestId('ceremony-copy-download')).toBeVisible();
    // The 32 GB RAM requirement is explicit.
    await expect(page.getByTestId('ceremony-requirements')).toContainText(
      /32 GB RAM/,
    );
    // "Phones not supported" is explicit.
    await expect(page.getByTestId('ceremony-not-supported')).toBeVisible();
    await expect(page.getByTestId('ceremony-not-supported')).toContainText(
      /Phones, tablets, and Chromebooks/,
    );
  });

  test('status page renders the planned state', async ({ page }) => {
    await stubStatus(page, STATUS_PLANNED);
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/status');
    await expect(page.getByTestId('ceremony-state-planned')).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByTestId('ceremony-chain-empty')).toBeVisible();
  });

  test('status page renders the in-progress state with chain', async ({ page }) => {
    await stubStatus(page, STATUS_IN_PROGRESS);
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/status');
    await expect(page.getByTestId('ceremony-state-in-progress')).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByTestId('ceremony-state-blurb')).toContainText(
      /Round 3 of 10/i,
    );
    await expect(page.getByTestId('ceremony-chain-list')).toBeVisible();
    await expect(page.getByTestId('ceremony-contributor-1')).toContainText(
      /alice@pse\.dev/,
    );
    await expect(page.getByTestId('ceremony-contributor-2')).toContainText(
      /bob@ef\.foundation/,
    );
  });

  test('status page renders the complete state with final hash', async ({ page }) => {
    await stubStatus(page, STATUS_COMPLETE);
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/status');
    await expect(page.getByTestId('ceremony-state-complete')).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByTestId('ceremony-final')).toBeVisible();
    await expect(page.getByTestId('ceremony-final-hash')).toContainText(
      /deadbeefcafebabe/,
    );
  });

  test('verify page surfaces the "ceremony pending" state when no final hash', async ({
    page,
  }) => {
    await stubStatus(page, STATUS_PLANNED);
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/verify');
    await expect(
      page.getByRole('heading', { name: /Verify your zkey/i }),
    ).toBeVisible({ timeout: 5_000 });
    await expect(page.getByTestId('ceremony-verify-pending')).toBeVisible();
  });

  test('verify page shows the published hash when ceremony complete', async ({
    page,
  }) => {
    await stubStatus(page, STATUS_COMPLETE);
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/verify');
    await expect(page.getByTestId('ceremony-verify-expected')).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByTestId('ceremony-verify-expected')).toContainText(
      /deadbeefcafebabe/,
    );
  });
});
