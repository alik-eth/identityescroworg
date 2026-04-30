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

  test('contribute → back link returns to /ceremony', async ({ page }) => {
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    await page.getByRole('link', { name: /back to overview/i }).click();
    await expect(page).toHaveURL(/\/ceremony$/);
    await expect(
      page.getByRole('heading', { name: /A trusted setup\. In public\./i }),
    ).toBeVisible({ timeout: 5_000 });
  });

  test('contribute copy button writes the actual command to clipboard', async ({
    browser,
  }) => {
    // Clipboard API requires explicit permissions in headless Chromium.
    // We grant clipboard-read so the test can verify the bytes that
    // landed; clipboard-write is implicit on user gesture but we grant
    // it for parity with strict permission models.
    const ctx = await browser.newContext({
      permissions: ['clipboard-read', 'clipboard-write'],
    });
    const page = await ctx.newPage();
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    const copy = page.getByTestId('ceremony-copy-download');
    await expect(copy).toBeVisible({ timeout: 5_000 });
    await copy.click();
    // Label swap to "Copied" is the user-visible signal; assert it
    // before the 1.6 s timeout snaps it back to "Copy".
    await expect(copy).toHaveText(/Copied/i, { timeout: 1_500 });
    // The actual bytes on the clipboard must match what the page's
    // <pre> renders — otherwise the user copies the label, not the
    // command.
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    expect(clip).toContain('curl -O https://prove.identityescrow.org/ceremony/');
    expect(clip).toContain('-prev.zkey');
    await ctx.close();
  });

  test('contribute → Fly launcher form renders all four inputs + command pre', async ({
    page,
  }) => {
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    const form = page.getByTestId('ceremony-fly-form');
    await expect(form).toBeVisible({ timeout: 5_000 });
    await expect(
      form.getByRole('heading', { name: /Or launch on Fly\.io/i }),
    ).toBeVisible();
    // All four inputs are present and addressable by their stable testids.
    await expect(page.getByTestId('ceremony-fly-handle')).toBeVisible();
    await expect(page.getByTestId('ceremony-fly-round')).toBeVisible();
    await expect(page.getByTestId('ceremony-fly-url')).toBeVisible();
    await expect(page.getByTestId('ceremony-fly-entropy')).toBeVisible();
    await expect(
      page.getByTestId('ceremony-fly-generate-entropy'),
    ).toBeVisible();
    // Command block renders the placeholder shape pre-fill, including
    // the "apps destroy" terminal step (the dispatch's named contract).
    const cmd = page.getByTestId('ceremony-fly-command');
    await expect(cmd).toBeVisible();
    await expect(cmd).toContainText(/flyctl auth login/);
    await expect(cmd).toContainText(/flyctl apps create/);
    await expect(cmd).toContainText(/flyctl secrets set/);
    await expect(cmd).toContainText(/flyctl deploy/);
    await expect(cmd).toContainText(/flyctl apps destroy/);
  });

  test('contribute → Generate-entropy button populates the entropy field with 64 hex chars', async ({
    page,
  }) => {
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    const entropy = page.getByTestId('ceremony-fly-entropy');
    await expect(entropy).toHaveValue('');
    await page.getByTestId('ceremony-fly-generate-entropy').click();
    // 32 bytes hex = 64 chars; strict regex prevents subtle bugs like
    // accidentally emitting an Uint8Array literal or base64 instead.
    const value = await entropy.inputValue();
    expect(value).toMatch(/^[0-9a-f]{64}$/);
    // The command block must reflect the generated entropy verbatim.
    await expect(page.getByTestId('ceremony-fly-command')).toContainText(
      value,
    );
    // Pressing again yields different bytes (sanity-check that the
    // generator isn't accidentally seeded to a constant).
    const firstValue = value;
    await page.getByTestId('ceremony-fly-generate-entropy').click();
    const secondValue = await entropy.inputValue();
    expect(secondValue).toMatch(/^[0-9a-f]{64}$/);
    expect(secondValue).not.toBe(firstValue);
  });

  test('contribute → Fly form filled in renders a complete command + copy puts it on clipboard', async ({
    browser,
  }) => {
    const ctx = await browser.newContext({
      permissions: ['clipboard-read', 'clipboard-write'],
    });
    const page = await ctx.newPage();
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    await page.getByTestId('ceremony-fly-handle').fill('alice');
    await page.getByTestId('ceremony-fly-round').fill('3');
    await page
      .getByTestId('ceremony-fly-url')
      .fill('https://prove.identityescrow.org/ceremony/round-3-signed');
    await page.getByTestId('ceremony-fly-entropy').fill('cafebabe'.repeat(8));
    const cmd = page.getByTestId('ceremony-fly-command');
    // App name slug is sanitised from the handle.
    await expect(cmd).toContainText(/qkb-ceremony-alice-round-3/);
    // The signed URL, handle, entropy and round all land in the
    // secrets-set call exactly as typed.
    await expect(cmd).toContainText(
      "QKB_SIGNED_URL='https://prove.identityescrow.org/ceremony/round-3-signed'",
    );
    await expect(cmd).toContainText("QKB_HANDLE='alice'");
    await expect(cmd).toContainText(`QKB_ENTROPY='${'cafebabe'.repeat(8)}'`);
    await expect(cmd).toContainText("QKB_ROUND='3'");
    // Click copy and read back from the clipboard. The bytes that
    // hit the clipboard MUST be the same string the <pre> renders —
    // otherwise the user copies the label, not the command.
    await page.getByTestId('ceremony-copy-fly').click();
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    expect(clip).toContain('flyctl auth login');
    expect(clip).toContain('qkb-ceremony-alice-round-3');
    expect(clip).toContain(
      "QKB_SIGNED_URL='https://prove.identityescrow.org/ceremony/round-3-signed'",
    );
    expect(clip).toContain('flyctl apps destroy qkb-ceremony-alice-round-3');
    await ctx.close();
  });

  test('contribute → Fly form sanitises hostile handles into a Fly-safe slug', async ({
    page,
  }) => {
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    // Spaces, apostrophes, and uppercase: all illegal in Fly app
    // names. The slug must collapse them into a-z0-9- only.
    await page.getByTestId('ceremony-fly-handle').fill("Alice O'Neill");
    await page.getByTestId('ceremony-fly-round').fill('1');
    const cmd = page.getByTestId('ceremony-fly-command');
    await expect(cmd).toContainText(/qkb-ceremony-alice-o-neill-round-1/);
    // The original handle still goes into the QKB_HANDLE env verbatim
    // (the slug is only used for the Fly app name).
    await expect(cmd).toContainText("QKB_HANDLE='Alice O'Neill'");
  });

  test('UK locale renders Ukrainian ceremony copy', async ({ page }) => {
    await page.addInitScript(() => {
      try {
        window.localStorage.setItem('qkb.lang', 'uk');
      } catch {
        /* ignore */
      }
    });
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony');
    // The UK heading is the canonical signal that the i18n bundle
    // resolved correctly; if it falls back to EN the heading text
    // changes wholesale rather than partially.
    await expect(
      page.getByRole('heading', { name: /Довірчий сетап\. Привселюдно\./i }),
    ).toBeVisible({ timeout: 5_000 });
    // Verify a sub-page also resolves UK copy (catches per-route
    // locale mistakes where the landing page is bundled but the
    // sub-pages aren't).
    await pushCeremonyRoute(page, '/ceremony/contribute');
    await expect(
      page.getByRole('heading', { name: /Зробіть внесок зі свого комп/ }),
    ).toBeVisible({ timeout: 5_000 });
  });
});
