/**
 * Browser wasm-prover feasibility benchmark.
 *
 * Drives `snarkjs.groth16.fullProve` against the live UA V4 leaf ceremony
 * artifacts (R2-hosted wasm + 3.8 GB zkey, 6.54M constraints) using the
 * synthetic input fixture from `@qkb/circuits`. The test is gated behind
 * `E2E_WASM_BENCH=1` because:
 *
 *   - It downloads ~4 GB of artifacts
 *   - It runs for 5–15 minutes (or OOMs)
 *   - It hits a third-party CDN (R2)
 *
 * The point is to capture empirical behavior — wall time, peak heap, and
 * (most likely) the OOM/wasm-allocation failure that motivates the offline
 * `@qkb/cli` proving path. The test logs results to
 * `tests/e2e/results/wasm-prover-benchmark.json` (gitignored) and asserts
 * only that the harness ran end-to-end, not that proving succeeded.
 */
import { test, expect } from '@playwright/test';
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  statSync,
  createReadStream,
} from 'node:fs';
import { resolve, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '../../../..');

const INPUT_PATH = resolve(
  REPO_ROOT,
  'packages/circuits/fixtures/integration/ua-v4/leaf-synthetic-qkb2.input.json',
);
const SNARKJS_UMD = resolve(
  REPO_ROOT,
  'node_modules/.pnpm/snarkjs@0.7.6/node_modules/snarkjs/build/snarkjs.min.js',
);

// UA V4 leaf ceremony URLs. Mirrored from packages/sdk/src/country/index.ts —
// keep in sync if the ceremony refreshes.
const WASM_URL =
  'https://prove.identityescrow.org/ua-leaf-v4-v2/QKBPresentationEcdsaLeafV4_UA.wasm';
const ZKEY_URL = 'https://prove.identityescrow.org/ua-leaf-v4-v2/ua_leaf_final.zkey';

test.describe('UA V4 leaf — browser wasm prover benchmark', () => {
  test.skip(!process.env.E2E_WASM_BENCH, 'set E2E_WASM_BENCH=1 to run');
  test.setTimeout(20 * 60_000);

  // The R2 bucket doesn't serve CORS for cross-origin browser fetches, and
  // the 3.8 GB zkey body is too large to round-trip through Playwright's
  // CDP-based `route.fulfill`. Workaround: spin up a tiny CORS-enabled HTTP
  // server that streams cached files from disk, then 302-redirect any
  // `prove.identityescrow.org` request to it. The cache survives across
  // runs so the (slow, ~5–15 min) initial R2 download only happens once.
  const cacheDir = resolve(__dirname, '.r2-cache');
  let fixtureServer: Server | null = null;
  let fixturePort = 0;

  test.beforeAll(async () => {
    mkdirSync(cacheDir, { recursive: true });
    fixtureServer = createServer((req, res) => {
      const filename = basename(req.url ?? '/');
      const filePath = resolve(cacheDir, filename);
      if (!existsSync(filePath)) {
        res.statusCode = 404;
        res.end(`not in cache: ${filename}`);
        return;
      }
      const stats = statSync(filePath);
      res.statusCode = 200;
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader(
        'Content-Type',
        filename.endsWith('.wasm') ? 'application/wasm' : 'application/octet-stream',
      );
      res.setHeader('Content-Length', String(stats.size));
      res.setHeader('Cache-Control', 'public, max-age=86400');
      createReadStream(filePath).pipe(res);
    });
    await new Promise<void>((r) => fixtureServer!.listen(0, '127.0.0.1', r));
    fixturePort = (fixtureServer!.address() as AddressInfo).port;
    console.log(`[fixture-server] listening on http://127.0.0.1:${fixturePort}`);
  });

  test.afterAll(async () => {
    if (fixtureServer) {
      await new Promise<void>((r) => fixtureServer!.close(() => r()));
    }
  });

  test('snarkjs.groth16.fullProve against synthetic input + R2 artifacts', async ({
    page,
  }) => {
    const input = JSON.parse(readFileSync(INPUT_PATH, 'utf-8')) as Record<string, unknown>;
    const snarkjsContent = readFileSync(SNARKJS_UMD, 'utf-8');

    page.on('console', (msg) => {
      console.log(`[browser:${msg.type()}]`, msg.text());
    });
    page.on('pageerror', (err) => {
      console.error('[browser:pageerror]', err.message);
    });

    // For each prove.identityescrow.org request: ensure the cache is warm
    // (fetch from R2 once) then 302-redirect to the local fixture server.
    // The browser follows the redirect, the fixture server streams from
    // disk with CORS headers, snarkjs gets the bytes.
    await page.route('**/prove.identityescrow.org/**', async (route) => {
      const url = route.request().url();
      const filename = basename(new URL(url).pathname);
      const cachePath = resolve(cacheDir, filename);
      if (!existsSync(cachePath)) {
        console.log(`[r2-cache] MISS ${filename} — fetching ${url}`);
        const t0 = Date.now();
        const res = await fetch(url);
        if (!res.ok) {
          await route.abort();
          throw new Error(`R2 fetch failed: ${res.status} ${res.statusText} for ${url}`);
        }
        // Stream the response body to disk so we don't hold 3.8 GB resident
        // in the Node heap on the cold path. Reusing a Buffer is fine for
        // the 40 MB wasm; for the 3.8 GB zkey we flush as we go.
        const body = Buffer.from(await res.arrayBuffer());
        writeFileSync(cachePath, body);
        const wall = ((Date.now() - t0) / 1000).toFixed(1);
        console.log(
          `[r2-cache] STORED ${filename} (${(body.byteLength / 1024 / 1024).toFixed(1)} MB in ${wall}s)`,
        );
      } else {
        const size = statSync(cachePath).size;
        console.log(
          `[r2-cache] HIT ${filename} (${(size / 1024 / 1024).toFixed(1)} MB)`,
        );
      }
      await route.fulfill({
        status: 302,
        headers: {
          Location: `http://127.0.0.1:${fixturePort}/${filename}`,
          'Access-Control-Allow-Origin': '*',
        },
        body: '',
      });
    });

    // Boot the SPA preview server so the wasm/zkey fetch happens from a
    // realistic HTTPS-style origin. The page content itself is irrelevant —
    // we replace it by injecting the snarkjs UMD bundle.
    await page.goto('/');
    await page.addScriptTag({ content: snarkjsContent });

    const result = await page.evaluate(
      async ({
        input,
        wasmUrl,
        zkeyUrl,
      }: {
        input: Record<string, unknown>;
        wasmUrl: string;
        zkeyUrl: string;
      }) => {
        const start = performance.now();
        let peakHeapMB = 0;
        const sample = () => {
          const mem = (
            performance as unknown as { memory?: { usedJSHeapSize: number } }
          ).memory;
          if (mem) {
            const mb = mem.usedJSHeapSize / 1024 / 1024;
            if (mb > peakHeapMB) peakHeapMB = mb;
          }
        };
        const interval = setInterval(sample, 500);
        try {
          const sj = (globalThis as unknown as { snarkjs: { groth16: {
            fullProve: (
              i: Record<string, unknown>,
              w: string,
              z: string,
            ) => Promise<{ proof: unknown; publicSignals: string[] }>;
          } } }).snarkjs;
          if (!sj?.groth16?.fullProve) {
            throw new Error('snarkjs UMD bundle did not expose globalThis.snarkjs');
          }
          const { proof, publicSignals } = await sj.groth16.fullProve(
            input,
            wasmUrl,
            zkeyUrl,
          );
          clearInterval(interval);
          sample();
          return {
            ok: true as const,
            wallMs: performance.now() - start,
            peakHeapMB,
            publicSignalsLength: publicSignals.length,
            firstPublicSignal: publicSignals[0],
            lastPublicSignal: publicSignals[publicSignals.length - 1],
            proofPresent: !!proof,
          };
        } catch (err) {
          clearInterval(interval);
          sample();
          const e = err as Error;
          return {
            ok: false as const,
            wallMs: performance.now() - start,
            peakHeapMB,
            errorName: e.name,
            errorMessage: e.message,
            errorStack: e.stack?.slice(0, 1500),
          };
        }
      },
      { input, wasmUrl: WASM_URL, zkeyUrl: ZKEY_URL },
    );

    const resultsDir = resolve(__dirname, 'results');
    mkdirSync(resultsDir, { recursive: true });
    const resultPath = resolve(resultsDir, 'wasm-prover-benchmark.json');
    writeFileSync(
      resultPath,
      JSON.stringify(
        {
          ...result,
          timestamp: new Date().toISOString(),
          wasmUrl: WASM_URL,
          zkeyUrl: ZKEY_URL,
        },
        null,
        2,
      ),
    );
    console.log('benchmark result:', JSON.stringify(result, null, 2));
    console.log('wrote', resultPath);

    // Assert only that the harness completed — not that proving succeeded.
    expect(result).toHaveProperty('wallMs');
  });
});
