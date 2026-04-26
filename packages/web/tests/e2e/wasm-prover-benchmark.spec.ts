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
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

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
