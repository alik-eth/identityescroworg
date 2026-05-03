// V5.4 T7 — Playwright happy-path E2E against the pumped @qkb/cli tarball.
//
// Plan ref: docs/superpowers/plans/2026-05-03-qkb-cli-server-web-eng.md T7.
//
// **Opt-in via env var.** This spec gates on `T7_DEV_MANIFEST` pointing
// at a signed dev manifest (matches the `E2E_REAL_PROVER` carve-out
// pattern in playwright.config.ts). Test skips when unset, so the
// suite stays green on machines without the V5.2 stub artefacts. Local
// dev: `export T7_DEV_MANIFEST=/tmp/dev-manifest.json` after lead's
// re-sign. CI: pipeline sets the env var with whatever paths the
// runner has provisioned.
//
// What we cover:
//   1. /status returns a §1.1-conforming CliStatus (sanity — proves
//      the spawn worked + serve loaded the zkey).
//   2. POST a real V5.2 stub-ceremony witness from
//      packages/sdk/fixtures/v5_2/witness-input-sample.json directly
//      to :9080/prove; verify the returned proof against the pumped
//      vkey via SDK's verifyGroth16. This exercises the full server
//      pipeline (rapidsnark prove against a known-valid witness)
//      without needing wallet mocks / Diia .p7s / binding-bytes
//      fixtures.
//
// **Webserver carve-out (playwright.config.ts):** when T7_DEV_MANIFEST
// is set, the global webServer (`pnpm run build && pnpm run preview`)
// is skipped — assertions here are fetch-only and don't navigate the
// SPA. Avoids coupling T7 to a transient web-build hiccup (e.g. the
// pre-existing argon2-browser ESM-wasm blocker that's tracked
// separately).
//
// **Out of scope, by design:**
//   - UI banner-suppression on detection: pinned at unit level by
//     packages/web/tests/unit/CliBanner.test.tsx (which directly
//     mocks useCliPresence at every status and asserts the conditional
//     render). A Playwright integration would be redundant.
//   - Full UI click-through (user clicks Generate Proof → CLI dispatch
//     → register submit): requires wallet + Diia .p7s + binding-bytes
//     fixtures we don't have. The dispatcher's CLI-vs-browser branch
//     is unit-tested (uaProofPipelineV5_2-cli.test.ts, 10 tests
//     pinning every fallback mode). The /status + /prove pair below
//     covers the real-server-real-witness contract that the
//     dispatcher delegates to.
import { spawn, type ChildProcess } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { verifyGroth16 } from '@qkb/sdk/prover/verify';

const MANIFEST_PATH = process.env.T7_DEV_MANIFEST;

test.skip(
  !MANIFEST_PATH,
  'T7 requires T7_DEV_MANIFEST pointing at a signed dev manifest. ' +
    'Local: export T7_DEV_MANIFEST=/tmp/dev-manifest.json. ' +
    'See docs/superpowers/plans/2026-05-03-qkb-cli-server-web-eng.md T7.',
);

const SDK_FIXTURES = resolve(
  fileURLToPath(import.meta.url),
  '../../../../sdk/fixtures/v5_2',
);

interface CliManifest {
  readonly circuits: {
    readonly 'v5.2': {
      readonly zkeyUrl: string;
      readonly wasmUrl: string;
      readonly vkeyUrl: string;
    };
  };
}

function fileUrlToPath(u: string): string {
  // Manifest stores file:// URLs; the CLI's `serve` accepts paths.
  return u.startsWith('file://') ? u.slice('file://'.length) : u;
}

function waitForStatus(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolveP, rejectP) => {
    const tick = (): void => {
      if (Date.now() > deadline) {
        rejectP(new Error(`waitForStatus timeout after ${timeoutMs}ms (${url})`));
        return;
      }
      fetch(url)
        .then((r) => (r.ok ? resolveP() : setTimeout(tick, 200)))
        .catch(() => setTimeout(tick, 200));
    };
    tick();
  });
}

let cliProc: ChildProcess | null = null;

// Override the project-level 30s default. /prove against the V5.2 stub
// witness measures ~13s on lead's reference; we assert <60s as a CI
// ceiling. Slower runners can push past the default Playwright timeout
// and die before the spec's own assertion gets to run, so bump the
// per-test timeout to 120s here. The describe-level setTimeout wins
// over the project default.
test.describe.configure({ mode: 'serial', timeout: 120_000 });

test.describe('V5.4 T7 — CLI-served happy path', () => {
  test.beforeAll(async () => {
    if (!MANIFEST_PATH) return; // belt + suspenders against test.skip()
    const manifest = JSON.parse(
      readFileSync(MANIFEST_PATH, 'utf8'),
    ) as CliManifest;
    const zkey = fileUrlToPath(manifest.circuits['v5.2'].zkeyUrl);
    const wasm = fileUrlToPath(manifest.circuits['v5.2'].wasmUrl);
    const vkey = fileUrlToPath(manifest.circuits['v5.2'].vkeyUrl);

    // Spawn `qkb serve` directly via the installed bin entry. Using
    // node + the dist entrypoint avoids pnpm-exec wrapper chatter that
    // can confuse Playwright's stdout capture.
    cliProc = spawn(
      'node',
      [
        'node_modules/@qkb/cli/dist/src/index.js',
        'serve',
        '--zkey', zkey,
        '--wasm', wasm,
        '--vkey', vkey,
        '--port', '9080',
        // Allow the Playwright preview origin in addition to the
        // production pin so test 2 (UI banner check) doesn't get
        // 403'd. The CLI's --allowed-origin replaces, doesn't append,
        // the default — fine for test isolation.
        '--allowed-origin', 'http://127.0.0.1:4173',
      ],
      {
        cwd: resolve(fileURLToPath(import.meta.url), '../../..'),
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );

    // Surface CLI stderr to test logs for triage when the spec fails.
    cliProc.stderr?.on('data', (chunk: Buffer) => {
      process.stderr.write(`[qkb-cli] ${chunk.toString()}`);
    });

    // 30 s ceiling — generous for first-run zkey load + sidecar warm-up
    // on slower CI machines. Healthy local dev resolves in <2 s.
    await waitForStatus('http://127.0.0.1:9080/status', 30_000);
  });

  test.afterAll(() => {
    if (cliProc && !cliProc.killed) cliProc.kill('SIGTERM');
  });

  test('test 1: /status returns a §1.1-conforming CliStatus', async () => {
    const res = await fetch('http://127.0.0.1:9080/status');
    expect(res.ok).toBe(true);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({
      ok: true,
      circuit: 'v5.2',
      zkeyLoaded: true,
    });
    // Frozen schema (orchestration §1.1) — every field must be present.
    expect(typeof body.version).toBe('string');
    expect(typeof body.busy).toBe('boolean');
    expect(typeof body.provesCompleted).toBe('number');
    expect(typeof body.uptimeSec).toBe('number');
    expect('downloadProgress' in body).toBe(true);
  });

  test('test 2: /prove accepts the V5.2 stub witness and returns a verifiable proof', async () => {
    // Real V5.2 stub-ceremony witness from circuits-eng's T3 pump.
    // Same fixture the SDK's ceremony-stub-v5_2 test verifies against.
    const witness = JSON.parse(
      readFileSync(resolve(SDK_FIXTURES, 'witness-input-sample.json'), 'utf8'),
    ) as Record<string, unknown>;

    const proveStart = Date.now();
    const res = await fetch('http://127.0.0.1:9080/prove', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Origin pin — match the --allowed-origin we passed to qkb serve.
        Origin: 'http://127.0.0.1:4173',
      },
      body: JSON.stringify(witness),
    });
    const proveElapsedSec = (Date.now() - proveStart) / 1000;
    expect(res.ok, `expected 2xx, got ${res.status}`).toBe(true);
    const body = (await res.json()) as {
      proof: Record<string, unknown>;
      publicSignals: string[];
      verifyOk: boolean;
      timings: Record<string, number>;
    };

    // Server-side verifyOk is observed but never trusted alone (T1
    // contract). We re-verify locally below.
    expect(body.verifyOk).toBe(true);
    expect(body.publicSignals).toHaveLength(22);
    expect(body.timings).toMatchObject({
      wtnsCalculateSec: expect.any(Number),
      groth16ProveSec: expect.any(Number),
      groth16VerifySec: expect.any(Number),
      totalSec: expect.any(Number),
    });

    // Belt-and-suspenders: re-verify the proof against the pumped vkey
    // using the SDK's snarkjs-backed verifier. This is what the browser
    // would do post-CLI-prove before submitting to register().
    const vkey = JSON.parse(
      readFileSync(resolve(SDK_FIXTURES, 'verification_key.json'), 'utf8'),
    ) as Record<string, unknown>;
    const ok = await verifyGroth16({
      verificationKey: vkey,
      publicSignals: body.publicSignals,
      proof: body.proof as unknown as Parameters<typeof verifyGroth16>[0]['proof'],
    });
    expect(ok, 'browser-side verifyGroth16 against pumped vkey').toBe(true);

    // Performance smoke — log the wall time so a regression in
    // rapidsnark or the prove pipeline surfaces in CI logs even when
    // the assertion still passes. Native rapidsnark on the V5.2 stub
    // measures ~13.86 s end-to-end on lead's reference machine; we
    // assert <60 s as a generous CI ceiling.
    process.stderr.write(`[T7] /prove wall time: ${proveElapsedSec.toFixed(2)}s\n`);
    expect(proveElapsedSec).toBeLessThan(60);
  });
});
