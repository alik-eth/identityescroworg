import { test, expect, type Response, type Page } from '@playwright/test';

const PROD = 'https://identityescrow.org';
const SCREENSHOT_DIR = 'tests/e2e/screenshots/prod-baseline';

interface Captured {
  url: string;
  status: number;
  contentType: string;
}

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

test('prod — landing fully styled, fonts loaded, no errors', async ({ page }) => {
  const monitor = await captureNetwork(page);
  await page.goto(`${PROD}/`, { waitUntil: 'networkidle', timeout: 30_000 });
  await expect(page.getByRole('heading', { name: /Verified Identity/i })).toBeVisible({
    timeout: 15_000,
  });
  await page.evaluate(() => (document as Document & { fonts: { ready: Promise<void> } }).fonts.ready);
  await page.screenshot({ path: `${SCREENSHOT_DIR}/landing.png`, fullPage: true });

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
  const fontsCss = monitor.captured.find((r) => /fonts\.googleapis\.com\/css2/.test(r.url));
  const fontAssets = monitor.captured.filter((r) => /fonts\.gstatic\.com\//.test(r.url));
  const ebGaramond = fontAssets.find((r) => /ebgaramond/.test(r.url.toLowerCase()));
  const interTight = fontAssets.find((r) => /intertight/.test(r.url.toLowerCase()));
  const jetBrains = fontAssets.find((r) => /jetbrainsmono/.test(r.url.toLowerCase()));
  console.log('[CSS bundle]', css?.url, css?.status, css?.contentType);
  console.log('[JS bundle]', js?.url, js?.status, js?.contentType);
  console.log('[Fonts CSS]', fontsCss?.status);
  console.log('[gstatic count]', fontAssets.length);
  console.log('[EB Garamond]', ebGaramond?.status);
  console.log('[Inter Tight]', interTight?.status);
  console.log('[JetBrains]', jetBrains?.status);

  const non2xx = monitor.captured.filter((r) => r.status >= 400);
  console.log('[Non-2xx]', non2xx.length);
  for (const r of non2xx) console.log('  ', r.status, r.url);
  console.log('[pageErrors]', monitor.pageErrors.length);
  for (const e of monitor.pageErrors) console.log('  ', e);
  console.log('[consoleErrors]', monitor.consoleErrors.length);
  for (const e of monitor.consoleErrors) console.log('  ', e);

  // Hard requirements
  expect(css?.status).toBe(200);
  expect(css?.contentType).toContain('text/css');
  expect(js?.status).toBe(200);
  expect(js?.contentType).toContain('javascript');
  expect(fontsCss?.status).toBe(200);
  expect(non2xx.length).toBe(0);
  expect(monitor.pageErrors).toEqual([]);
  expect(monitor.consoleErrors).toEqual([]);
  expect(ebGaramond?.status).toBe(200);
  expect(interTight?.status).toBe(200);

  // Style requirements (lead's criteria)
  expect(computed.body.backgroundColor, 'body bg = bone').toBe('rgb(244, 239, 230)');
  expect(computed.body.color, 'body color = ink').toBe('rgb(20, 19, 14)');
  expect(computed.h1?.color, 'h1 color = ink').toBe('rgb(20, 19, 14)');
  expect(computed.body.fontFamily).toMatch(/(Söhne|Inter Tight|Helvetica Neue|system-ui|sans-serif)/);
  expect(computed.h1?.fontFamily).toMatch(/(GT Sectra Display|Tiempos|EB Garamond|serif)/);
  const px = parseFloat(computed.h1?.fontSize ?? '0');
  expect(px).toBeGreaterThan(60);

  expect(await page.getByRole('button', { name: /connect wallet/i }).isVisible()).toBe(true);
});

test('prod — /ua/cli styled', async ({ page }) => {
  const monitor = await captureNetwork(page);
  await page.goto(`${PROD}/ua/cli`, { waitUntil: 'networkidle', timeout: 30_000 });
  await expect(page.getByRole('heading', { name: /install the cli/i })).toBeVisible({
    timeout: 15_000,
  });
  await page.evaluate(() => (document as Document & { fonts: { ready: Promise<void> } }).fonts.ready);
  await page.screenshot({ path: `${SCREENSHOT_DIR}/ua-cli.png`, fullPage: true });
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  console.log('[/ua/cli body bg]', bg);
  expect(bg).toBe('rgb(244, 239, 230)');
  const non2xx = monitor.captured.filter((r) => r.status >= 400);
  for (const r of non2xx) console.log('  ', r.status, r.url);
  expect(non2xx.length).toBe(0);
  expect(monitor.pageErrors).toEqual([]);
  expect(monitor.consoleErrors).toEqual([]);
});

test('prod — /integrations styled', async ({ page }) => {
  const monitor = await captureNetwork(page);
  await page.goto(`${PROD}/integrations`, { waitUntil: 'networkidle', timeout: 30_000 });
  await expect(page.locator('#root *').first()).toBeVisible({ timeout: 15_000 });
  await page.evaluate(() => (document as Document & { fonts: { ready: Promise<void> } }).fonts.ready);
  await page.screenshot({ path: `${SCREENSHOT_DIR}/integrations.png`, fullPage: true });
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  console.log('[/integrations body bg]', bg);
  expect(bg).toBe('rgb(244, 239, 230)');
  const non2xx = monitor.captured.filter((r) => r.status >= 400);
  for (const r of non2xx) console.log('  ', r.status, r.url);
  expect(non2xx.length).toBe(0);
  expect(monitor.pageErrors).toEqual([]);
  expect(monitor.consoleErrors).toEqual([]);
});

test('prod — /ua/mint disconnected renders mint chrome', async ({ page }) => {
  const monitor = await captureNetwork(page);
  await page.goto(`${PROD}/ua/mint`, { waitUntil: 'networkidle', timeout: 30_000 });
  // Disconnected: route renders the mint heading + an inline ConnectButton
  // (the route gates on isConnected — see f49c317).
  await expect(page.getByRole('heading', { name: /Mint your certificate/i })).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByText(/Connect a wallet to mint/i)).toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole('button', { name: /connect wallet/i })).toBeVisible({
    timeout: 10_000,
  });
  await page.evaluate(() => (document as Document & { fonts: { ready: Promise<void> } }).fonts.ready);
  await page.screenshot({ path: `${SCREENSHOT_DIR}/mint.png`, fullPage: true });
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  console.log('[/ua/mint body bg]', bg);
  console.log('[/ua/mint consoleErrors]', monitor.consoleErrors.length);
  for (const e of monitor.consoleErrors) console.log('  err:', e);
  expect(bg).toBe('rgb(244, 239, 230)');
  const non2xx = monitor.captured.filter((r) => r.status >= 400);
  for (const r of non2xx) console.log('  ', r.status, r.url);
  expect(non2xx.length).toBe(0);
  expect(monitor.pageErrors).toEqual([]);
  expect(monitor.consoleErrors).toEqual([]);
});
