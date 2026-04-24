/**
 * Regression: `/ua/upload` was fetching `./trusted-cas/*` — a relative URL
 * that, under the two-segment `/ua/upload` path, resolves to
 * `/ua/trusted-cas/*`. Vite (and the file:// SPA build) serve index.html
 * for unknown paths, which lands `JSON.parse` on `<!doctype html>` and
 * throws at line 1 column 1. The fix walks one level up via
 * `../trusted-cas/*`.
 *
 * This spec gates two things:
 *   1. The static-fetch guard: from `/ua/upload`, `../trusted-cas/*.json`
 *      must return a JSON body (not HTML). That alone pins the regression.
 *   2. (Optional, opt-in) When a real Diia `.p7s` + binding pair is
 *      pointed at via `E2E_UA_REAL_DIIA_DIR`, exercise the upload pipeline
 *      past the trusted-list fetch. The check here is specifically "the
 *      first-stage failure is not a JSON parse" — downstream V2 verifier
 *      work is tracked separately.
 */
import { expect, test } from '@playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REAL_DIIA_DIR = process.env.E2E_UA_REAL_DIIA_DIR;

const SAMPLE_PK_HEX =
  '04aa1cd4d92aef29df5644f29d79bae2f81ba3c2ae347075fbec1301b84db712b4a0683ffcdf9b4a5eebdaaf74f0719510044d40961854901f44ce31e88b27ff2b';

const SYNTHETIC_BINDING_V2 = {
  version: 'QKB/2.0',
  statementSchema: 'qkb-binding-core/v1',
  scheme: 'secp256k1',
  pk: `0x${SAMPLE_PK_HEX}`,
  context: '0x',
  timestamp: 1_777_014_872,
  nonce: `0x${'ef'.repeat(32)}`,
  policy: {
    bindingSchema: 'qkb-binding-core/v1',
    leafHash:
      '0x2d00e73da8dd4dc99f04371d3ce01ecbcf4ad8e476c9017a304c57873494f812',
    policyId: 'qkb-default-ua',
    policyVersion: 1,
  },
  assertions: {
    acceptsAttribution: true,
    bindsContext: true,
    keyControl: true,
    revocationRequired: true,
  },
  display: {
    lang: 'uk',
    template: 'qkb-default-ua/v1',
    text: 'placeholder',
  },
} as const;

async function seedV2AndGotoUpload(page: import('@playwright/test').Page): Promise<void> {
  await page.goto('/');
  await page.waitForFunction(
    () => typeof window !== 'undefined' && !!document.querySelector('header'),
  );
  await page.evaluate(
    ({ binding, pk }) => {
      const bcanon = JSON.stringify(binding);
      const utf8 = new TextEncoder().encode(bcanon);
      let bin = '';
      for (const b of utf8) bin += String.fromCharCode(b);
      sessionStorage.setItem(
        'qkb.session.v1',
        JSON.stringify({
          country: 'UA',
          pubkeyUncompressedHex: pk,
          bindingV2: binding,
          bcanonV2B64: btoa(bin),
        }),
      );
      window.history.pushState({}, '', '/ua/upload');
      window.dispatchEvent(new PopStateEvent('popstate'));
    },
    { binding: SYNTHETIC_BINDING_V2, pk: SAMPLE_PK_HEX },
  );
}

test.describe('/ua/upload — trusted-cas path regression', () => {
  test('trusted-list fetch path resolves under /ua/upload (no SPA fallback)', async ({
    page,
  }) => {
    await seedV2AndGotoUpload(page);
    // The bug: a plain `fetch('./trusted-cas/…')` from /ua/upload
    // resolves to /ua/trusted-cas/… and the SPA serves index.html
    // (HTML → `JSON.parse` blows up on "<"). The fix walks one level
    // up. This test pins the baseline (broken) and the fix side-by-side
    // in the same page context so it catches either direction of drift.
    const probe = await page.evaluate(async () => {
      async function peek(u: string): Promise<{ url: string; firstChar: string }> {
        const r = await fetch(u);
        const t = await r.text();
        return { url: r.url, firstChar: t.slice(0, 1) };
      }
      return {
        relative: await peek('./trusted-cas/trusted-cas.json'),
        parent: await peek('../trusted-cas/trusted-cas.json'),
      };
    });
    expect(
      probe.relative.firstChar,
      `baseline: \`./trusted-cas/*\` under /ua/upload MUST hit the SPA fallback (HTML). got url=${probe.relative.url}`,
    ).toBe('<');
    expect(
      probe.parent.firstChar,
      `fix: \`../trusted-cas/*\` MUST resolve to the public JSON asset. got url=${probe.parent.url}`,
    ).toBe('{');

    // Static-source guard: pin the code path so nobody reintroduces the
    // SPA-fallback trap. Reading the .tsx from disk side-steps whether
    // playwright runs against dev server or preview (neither serves
    // /src/* from the preview build).
    const here = dirname(fileURLToPath(import.meta.url));
    const routePath = resolve(here, '../../src/routes/ua/upload.tsx');
    const routeText = readFileSync(routePath, 'utf8');
    expect(
      /fetch\(['"]\.\/trusted-cas\//.test(routeText),
      'regression guard: /ua/upload must not use `./trusted-cas/` (SPA fallback trap)',
    ).toBe(false);
    expect(
      /fetch\(['"]\.\.\/trusted-cas\//.test(routeText),
      '/ua/upload should fetch trusted-list assets via `../trusted-cas/`',
    ).toBe(true);
  });

  test('real-Diia .p7s upload past the trusted-list fetch (no JSON.parse failure)', async ({
    page,
  }) => {
    test.skip(
      !REAL_DIIA_DIR,
      'set E2E_UA_REAL_DIIA_DIR to a dir containing binding.qkb.json + binding.qkb.json.p7s',
    );
    const dir = resolve(REAL_DIIA_DIR!);
    const jsonPath = join(dir, 'binding.qkb.json');
    const p7sPath = join(dir, 'binding.qkb.json.p7s');
    if (!existsSync(jsonPath) || !existsSync(p7sPath)) {
      test.skip(true, `expected binding.qkb.json + .p7s under ${dir}`);
    }
    const bindingJson = readFileSync(jsonPath, 'utf8');
    const binding = JSON.parse(bindingJson) as { pk: string };
    const p7s = readFileSync(p7sPath);
    const pkHex = binding.pk.replace(/^0x/, '');

    await page.goto('/');
    await page.waitForFunction(
      () => typeof window !== 'undefined' && !!document.querySelector('header'),
    );
    await page.evaluate(
      ({ bindingObj, bcanonB64, pk }) => {
        sessionStorage.setItem(
          'qkb.session.v1',
          JSON.stringify({
            country: 'UA',
            pubkeyUncompressedHex: pk,
            bindingV2: bindingObj,
            bcanonV2B64: bcanonB64,
          }),
        );
        window.history.pushState({}, '', '/ua/upload');
        window.dispatchEvent(new PopStateEvent('popstate'));
      },
      {
        bindingObj: binding,
        bcanonB64: Buffer.from(bindingJson, 'utf8').toString('base64'),
        pk: pkHex,
      },
    );

    await page.setInputFiles('[data-testid="p7s-input"]', {
      name: 'binding.qkb.json.p7s',
      mimeType: 'application/pkcs7-signature',
      buffer: p7s,
    });

    // Status must advance past `parsing` (idle/parsing/verifying/...). If
    // the trusted-cas fetch still landed on index.html, we'd hit a
    // JSON.parse error during `verifying` and the UI would surface the
    // generic parse message — the thing we're explicitly pinning against.
    await expect(page.getByTestId('upload-status')).not.toHaveText(/status: idle/);
    const errorLocator = page.getByTestId('upload-error');
    if (await errorLocator.isVisible()) {
      const text = (await errorLocator.textContent()) ?? '';
      expect(text, 'upload error must not be a JSON.parse of an HTML body').not.toMatch(
        /unexpected (token|character).*JSON/i,
      );
      expect(text, 'upload error must not be a doctype HTML fragment').not.toMatch(
        /<!doctype/i,
      );
    }
  });
});
