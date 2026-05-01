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

  test('contribute → Fly launcher form is gated behind a CTA, not the default surface', async ({
    page,
  }) => {
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    // The CTA renders by default; the form does NOT.
    await expect(page.getByTestId('fly-launch-cta')).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByTestId('fly-launch-form')).toHaveCount(0);
    // Click the CTA — the form expands; the CTA goes away.
    await page.getByRole('button', { name: /generate a launch command/i }).click();
    await expect(page.getByTestId('fly-launch-form')).toBeVisible();
    await expect(page.getByTestId('fly-launch-cta')).toHaveCount(0);
    // All five fields are present.
    await expect(page.getByTestId('fly-launch-signed-url')).toBeVisible();
    await expect(page.getByTestId('fly-launch-round')).toBeVisible();
    await expect(page.getByTestId('fly-launch-name')).toBeVisible();
    await expect(page.getByTestId('fly-launch-profile-url')).toBeVisible();
    await expect(page.getByTestId('fly-launch-entropy')).toBeVisible();
    await expect(page.getByTestId('fly-launch-generate-entropy')).toBeVisible();
    // Both security warning paragraphs are visible.
    const warnings = page.getByTestId('fly-launch-warnings');
    await expect(warnings).toContainText(/runs entirely in your browser/i);
    await expect(warnings).toContainText(/contribution receipt/i);
    // Output block renders the canonical six-step sequence even with
    // empty inputs — users should see the shape before they fill in.
    const out = page.getByTestId('fly-launch-output');
    await expect(out).toBeVisible();
    await expect(out).toContainText(/APP="qkb-ceremony-/);
    await expect(out).toContainText(/flyctl apps create "\$APP" --org personal/);
    await expect(out).toContainText(/flyctl secrets set/);
    await expect(out).toContainText(/flyctl deploy/);
    await expect(out).toContainText(/flyctl logs -a "\$APP" --follow/);
    await expect(out).toContainText(/flyctl apps destroy "\$APP" --yes/);
  });

  test('contribute → generate-fresh-entropy button populates a 64-hex value and is reflected in the output', async ({
    page,
  }) => {
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    await page.getByRole('button', { name: /generate a launch command/i }).click();
    const entropy = page.getByTestId('fly-launch-entropy');
    await expect(entropy).toHaveValue('');
    await page.getByTestId('fly-launch-generate-entropy').click();
    const value = await entropy.inputValue();
    expect(value).toMatch(/^[0-9a-f]{64}$/);
    // The output block must reflect the generated entropy verbatim
    // and unquoted (cookbook contract).
    await expect(page.getByTestId('fly-launch-output')).toContainText(
      `CONTRIBUTOR_ENTROPY=${value}`,
    );
  });

  test('contribute → typed entropy that is not 64 hex chars surfaces the inline error', async ({
    page,
  }) => {
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    await page.getByRole('button', { name: /generate a launch command/i }).click();
    const entropy = page.getByTestId('fly-launch-entropy');
    // Typing too-short hex triggers the inline alert and aria-invalid.
    await entropy.fill('abc');
    await expect(
      page.getByText(/exactly 64 lowercase hex characters/i),
    ).toBeVisible();
    await expect(entropy).toHaveAttribute('aria-invalid', 'true');
    // Typing a valid 64-hex string clears the error.
    await entropy.fill('cafebabe'.repeat(8));
    await expect(
      page.getByText(/exactly 64 lowercase hex characters/i),
    ).toHaveCount(0);
  });

  test('contribute → signed URL containing /round-N.zkey auto-fills the round field', async ({
    page,
  }) => {
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    await page.getByRole('button', { name: /generate a launch command/i }).click();
    await page
      .getByTestId('fly-launch-signed-url')
      .fill(
        'https://prove.identityescrow.org/upload/round-7.zkey?sig=abc&exp=1234',
      );
    await expect(page.getByTestId('fly-launch-round')).toHaveValue('7');
  });

  test('contribute → fully-filled form renders the canonical command + copy puts it on the clipboard', async ({
    browser,
  }) => {
    const ctx = await browser.newContext({
      permissions: ['clipboard-read', 'clipboard-write'],
    });
    const page = await ctx.newPage();
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    await page.getByRole('button', { name: /generate a launch command/i }).click();

    const url =
      'https://prove.identityescrow.org/upload/round-3.zkey?sig=abc&exp=1234';
    const entropyHex = 'cafebabe'.repeat(8);
    await page.getByTestId('fly-launch-signed-url').fill(url);
    await page.getByTestId('fly-launch-name').fill('alice');
    await page.getByTestId('fly-launch-entropy').fill(entropyHex);

    // Output reflects every input verbatim, in the canonical order.
    const out = page.getByTestId('fly-launch-output');
    await expect(out).toContainText('APP="qkb-ceremony-alice"');
    await expect(out).toContainText('ROUND="3"');
    await expect(out).toContainText(
      'PREV_ROUND_URL="https://prove.identityescrow.org/ceremony/rounds/round-2.zkey"',
    );
    await expect(out).toContainText(
      'R1CS_URL="https://prove.identityescrow.org/ceremony/main.r1cs"',
    );
    await expect(out).toContainText(
      'PTAU_URL="https://prove.identityescrow.org/ceremony/pot/pot23.ptau"',
    );
    await expect(out).toContainText(`SIGNED_PUT_URL='${url}'`);
    await expect(out).toContainText(`CONTRIBUTOR_NAME='alice'`);
    await expect(out).toContainText(`CONTRIBUTOR_ENTROPY=${entropyHex}`);
    await expect(out).toContainText(
      '--image ghcr.io/identityescroworg/qkb-ceremony:v1',
    );
    await expect(out).toContainText('flyctl apps destroy "$APP" --yes');

    // Copy and read back. The clipboard bytes MUST equal the rendered
    // <pre> verbatim — otherwise the user pastes a corrupted command.
    await page.getByTestId('fly-launch-copy').click();
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    expect(clip).toContain('APP="qkb-ceremony-alice"');
    expect(clip).toContain(`SIGNED_PUT_URL='${url}'`);
    expect(clip).toContain(`CONTRIBUTOR_ENTROPY=${entropyHex}`);
    expect(clip).toContain('flyctl apps destroy "$APP" --yes');
    await ctx.close();
  });

  test('contribute → hostile contributor names slugify into a Fly-safe app slug while CONTRIBUTOR_NAME stays original', async ({
    page,
  }) => {
    await page.goto('/');
    await pushCeremonyRoute(page, '/ceremony/contribute');
    await page.getByRole('button', { name: /generate a launch command/i }).click();
    await page.getByTestId('fly-launch-name').fill("Alice O'Neill");
    await page.getByTestId('fly-launch-round').fill('1');
    const out = page.getByTestId('fly-launch-output');
    // Slug collapses the apostrophe + space into hyphens.
    await expect(out).toContainText('APP="qkb-ceremony-alice-o-neill"');
    // Original name preserved verbatim in CONTRIBUTOR_NAME.
    await expect(out).toContainText(`CONTRIBUTOR_NAME='Alice O'Neill'`);
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
