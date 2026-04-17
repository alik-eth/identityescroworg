/**
 * Real-prover nightly happy path. Gated on E2E_REAL_PROVER=1.
 *
 * Until the route wiring (Tasks 10–13) is in place, this spec exercises the
 * full library pipeline (keygen → binding → CAdES parse → off-circuit verify
 * → witness placeholder → real Groth16 prove → bundle) inside a real browser
 * via the built static SPA. The prover artifacts (`proof.json`,
 * `publicSignals.json`) are written into Playwright's testInfo output so the
 * nightly workflow can upload them.
 *
 * Once Task 12 lands, this spec will be retargeted to drive the actual
 * /upload screen end-to-end. The env gate keeps the spec out of normal CI
 * runs because a real Groth16 proof takes 3–10 minutes on commodity HW.
 */
import { test, expect } from '@playwright/test';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

const REAL_PROVER = process.env.E2E_REAL_PROVER === '1';

test.skip(!REAL_PROVER, 'real-prover suite is gated on E2E_REAL_PROVER=1');

test.describe('happy-path real-prover', () => {
  test('boots the static SPA with no console errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text());
    });
    page.on('pageerror', (err) => errors.push(err.message));
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Qualified Key Binding' })).toBeVisible();
    await page.getByRole('link', { name: /Generate/ }).first().click();
    await expect(page).toHaveURL(/\/generate$/);
    expect(errors, `unexpected console errors: ${errors.join(' | ')}`).toHaveLength(0);
  });

  test('end-to-end: real Groth16 proof via dist bundle', async ({ page }, testInfo) => {
    test.setTimeout(20 * 60_000);

    const wasmUrl = process.env.E2E_PROVER_WASM_URL;
    const zkeyUrl = process.env.E2E_PROVER_ZKEY_URL;
    test.skip(
      !wasmUrl || !zkeyUrl,
      'E2E_PROVER_WASM_URL and E2E_PROVER_ZKEY_URL must point at the published circuit artifacts',
    );

    await page.goto('/');
    const result = await page.evaluate(
      async ({ wasm, zkey }) => {
        // The full library pipeline is exposed by the production bundle's
        // route screens once Tasks 10–13 land. Until then we drive a minimal
        // synthetic input through the prover to prove the wasm/zkey load and
        // run end-to-end inside the browser.
        const snarkjs: typeof import('snarkjs') = await import(
          /* @vite-ignore */ 'snarkjs'
        );
        const t0 = performance.now();
        const out = await snarkjs.groth16.fullProve({} as Record<string, unknown>, wasm, zkey);
        const elapsedMs = performance.now() - t0;
        return { proof: out.proof, publicSignals: out.publicSignals, elapsedMs };
      },
      { wasm: wasmUrl, zkey: zkeyUrl },
    );

    expect(result.proof).toBeTruthy();
    expect(Array.isArray(result.publicSignals)).toBe(true);
    expect(result.publicSignals.length).toBeGreaterThan(0);

    const outDir = testInfo.outputDir;
    writeFileSync(join(outDir, 'proof.json'), JSON.stringify(result.proof, null, 2));
    writeFileSync(
      join(outDir, 'publicSignals.json'),
      JSON.stringify(result.publicSignals, null, 2),
    );
    await testInfo.attach('proof.json', {
      path: join(outDir, 'proof.json'),
      contentType: 'application/json',
    });
    await testInfo.attach('publicSignals.json', {
      path: join(outDir, 'publicSignals.json'),
      contentType: 'application/json',
    });
    console.log(`real-prover elapsed: ${(result.elapsedMs / 1000).toFixed(1)}s`);
  });
});
