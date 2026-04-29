import { test, expect, type Response, type Page } from '@playwright/test';

const PROD = 'https://identityescrow.org';
const SCREENSHOT_DIR = 'tests/e2e/screenshots/prod-baseline';

interface Captured {
  url: string;
  status: number;
  contentType: string;
}

interface Viewport {
  name: 'desktop' | 'tablet' | 'mobile';
  width: number;
  height: number;
}

const VIEWPORTS: Viewport[] = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'mobile', width: 390, height: 844 },
];

async function captureNetwork(page: Page) {
  const captured: Captured[] = [];
  const consoleErrors: string[] = [];
  const consoleWarnings: string[] = [];
  const pageErrors: string[] = [];
  page.on('response', (resp: Response) => {
    captured.push({
      url: resp.url(),
      status: resp.status(),
      contentType: resp.headers()['content-type'] ?? '',
    });
  });
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
    if (msg.type() === 'warning') consoleWarnings.push(msg.text());
  });
  page.on('pageerror', (err) => pageErrors.push(err.message));
  return { captured, consoleErrors, consoleWarnings, pageErrors };
}

async function assertNoOverflow(page: Page, label: string) {
  const dims = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    innerWidth: window.innerWidth,
  }));
  console.log(
    `[overflow:${label}] scrollWidth=${dims.scrollWidth} innerWidth=${dims.innerWidth}`,
  );
  expect(
    dims.scrollWidth,
    `${label}: scrollWidth (${dims.scrollWidth}) must be ≤ innerWidth (${dims.innerWidth})`,
  ).toBeLessThanOrEqual(dims.innerWidth);
}

async function dumpNetworkErrors(
  monitor: { captured: Captured[]; pageErrors: string[]; consoleErrors: string[] },
  label: string,
) {
  const non2xx = monitor.captured.filter((r) => r.status >= 400);
  for (const r of non2xx) console.log(`[${label} non-2xx]`, r.status, r.url);
  for (const e of monitor.pageErrors) console.log(`[${label} pageError]`, e);
  for (const e of monitor.consoleErrors) console.log(`[${label} consoleError]`, e);
  expect(non2xx.length, `${label}: 4xx/5xx responses`).toBe(0);
  expect(monitor.pageErrors, `${label}: pageErrors`).toEqual([]);
  expect(monitor.consoleErrors, `${label}: consoleErrors`).toEqual([]);
}

interface RouteSpec {
  slug: string;
  path: string;
  heading: RegExp;
  /** further per-viewport per-route assertions; lead-defined contract */
  extraAssert?: (page: Page) => Promise<void>;
}

const ROUTES: RouteSpec[] = [
  {
    slug: 'landing',
    path: '/',
    heading: /Verified Identity|Підтверджена особа/,
    extraAssert: async (page) => {
      await expect(
        page.getByRole('heading', {
          level: 2,
          name: /Identity, escrowed|Депонована ідентичність/,
        }),
      ).toBeVisible({ timeout: 10_000 });
    },
  },
  {
    slug: 'ua-cli',
    path: '/ua/cli',
    heading: /install the cli|встановіть cli/i,
  },
  {
    slug: 'ua-submit',
    path: '/ua/submit',
    heading: /submit your proof|надіслати доказ/i,
  },
  {
    slug: 'ua-mint',
    path: '/ua/mint',
    heading: /mint your certificate|випустіть сертифікат/i,
  },
  {
    slug: 'integrations',
    path: '/integrations',
    heading: /integrate qkb verification/i,
  },
];

for (const viewport of VIEWPORTS) {
  test.describe(`viewport=${viewport.name} (${viewport.width}x${viewport.height})`, () => {
    test.use({ viewport: { width: viewport.width, height: viewport.height } });

    for (const route of ROUTES) {
      test(`prod — ${route.slug} on ${viewport.name}`, async ({ page }) => {
        const monitor = await captureNetwork(page);
        await page.goto(`${PROD}${route.path}`, {
          waitUntil: 'networkidle',
          timeout: 30_000,
        });
        await expect(page.getByRole('heading', { name: route.heading })).toBeVisible({
          timeout: 15_000,
        });
        if (route.extraAssert) await route.extraAssert(page);
        await page.evaluate(
          () =>
            (document as Document & { fonts: { ready: Promise<void> } }).fonts.ready,
        );
        await page.screenshot({
          path: `${SCREENSHOT_DIR}/${viewport.name}/${route.slug}.png`,
          fullPage: true,
        });
        await assertNoOverflow(page, `${route.slug}@${viewport.name}`);
        await dumpNetworkErrors(monitor, `${route.slug}@${viewport.name}`);
      });
    }
  });
}

// Style/asset audit: keep the rich landing-on-desktop check that earlier
// commits depended on (font loading, palette, bundle types). Runs once per
// suite at desktop only — the per-viewport tests above cover the
// scrollWidth + per-route load surface across all 15 (5 × 3) captures.
test.describe('viewport=desktop-audit (1440x900)', () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  test('prod — landing audit (fonts loaded, palette correct, no errors)', async ({
    page,
  }) => {
    const monitor = await captureNetwork(page);
    await page.goto(`${PROD}/`, { waitUntil: 'networkidle', timeout: 30_000 });
    await expect(page.getByRole('heading', { name: /Verified Identity/i })).toBeVisible({
      timeout: 15_000,
    });
    await page.evaluate(
      () => (document as Document & { fonts: { ready: Promise<void> } }).fonts.ready,
    );

    const computed = await page.evaluate(() => {
      const body = getComputedStyle(document.body);
      const h1 = document.querySelector('h1');
      return {
        body: {
          fontFamily: body.fontFamily,
          backgroundColor: body.backgroundColor,
          color: body.color,
        },
        h1: h1
          ? {
              text: h1.textContent?.slice(0, 80),
              fontFamily: getComputedStyle(h1).fontFamily,
              fontSize: getComputedStyle(h1).fontSize,
              color: getComputedStyle(h1).color,
            }
          : null,
      };
    });
    console.log('[BODY]', JSON.stringify(computed.body));
    console.log('[H1]', JSON.stringify(computed.h1));

    const css = monitor.captured.find((r) => /\/assets\/index-.*\.css$/.test(r.url));
    const js = monitor.captured.find((r) => /\/assets\/index-.*\.js$/.test(r.url));
    const fontsCss = monitor.captured.find((r) =>
      /fonts\.googleapis\.com\/css2/.test(r.url),
    );
    const fontAssets = monitor.captured.filter((r) =>
      /fonts\.gstatic\.com\//.test(r.url),
    );
    const ebGaramond = fontAssets.find((r) => /ebgaramond/.test(r.url.toLowerCase()));
    const interTight = fontAssets.find((r) => /intertight/.test(r.url.toLowerCase()));

    expect(css?.status).toBe(200);
    expect(css?.contentType).toContain('text/css');
    expect(js?.status).toBe(200);
    expect(js?.contentType).toContain('javascript');
    expect(fontsCss?.status).toBe(200);
    expect(ebGaramond?.status).toBe(200);
    expect(interTight?.status).toBe(200);

    // Style requirements (lead's criteria)
    expect(computed.body.backgroundColor, 'body bg = bone').toBe('rgb(244, 239, 230)');
    expect(computed.body.color, 'body color = ink').toBe('rgb(20, 19, 14)');
    expect(computed.h1?.color, 'h1 color = ink').toBe('rgb(20, 19, 14)');
    expect(computed.body.fontFamily).toMatch(
      /(Söhne|Inter Tight|Helvetica Neue|system-ui|sans-serif)/,
    );
    expect(computed.h1?.fontFamily).toMatch(
      /(GT Sectra Display|Tiempos|EB Garamond|serif)/,
    );
    const px = parseFloat(computed.h1?.fontSize ?? '0');
    expect(px, 'desktop h1 ≥ 60px').toBeGreaterThan(60);

    expect(await page.getByRole('button', { name: /connect wallet/i }).isVisible()).toBe(
      true,
    );
  });
});
