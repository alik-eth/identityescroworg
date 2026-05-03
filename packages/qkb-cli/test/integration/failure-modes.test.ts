// Failure-mode integration tests — T9 of the plan.
//
// Many failure modes are already covered by unit tests in their
// respective module suites (manifest-verify covers sig + schema
// failures; zkey-download covers sha mismatch + scheme rejects;
// cache-commands covers status unreachable; serve-prove-roundtrip
// covers bad Origin → 403).  This file fills the remaining gaps
// surfaced by plan T9 step 1:
//
//   - rapidsnark binary missing → actionable CLI error
//   - witness JSON malformed → /prove returns 5xx with parseable error
//   - concurrent /prove requests → second returns 429
//   - manifest URL unreachable (HTTP 404) → fetchAndVerifyManifest
//     surfaces a clear error
//
// Concurrent-/prove and witness-malformed tests stand up a real
// CliServer against the V5.2 fixtures; gated on local fixture
// availability (same pattern as serve-prove-roundtrip.test.ts).

import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { fetchAndVerifyManifest } from '../../src/manifest/fetch.js';
import {
  resolveSidecarPathOrThrow,
} from '../../src/rapidsnark/sidecar-path.js';
import { CliServer } from '../../src/server/http.js';

const __dirname = resolve(fileURLToPath(import.meta.url), '..');
const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..');
const CEREMONY = resolve(REPO_ROOT, 'packages/circuits/ceremony/v5_2');
const BUILD = resolve(REPO_ROOT, 'packages/circuits/build/v5_2-stub');

const ZKEY_PATH = resolve(CEREMONY, 'qkb-v5_2-stub.zkey');
const WASM_PATH = resolve(BUILD, 'QKBPresentationV5_js/QKBPresentationV5.wasm');
const VKEY_PATH = resolve(CEREMONY, 'verification_key.json');
const WITNESS_INPUT_PATH = resolve(CEREMONY, 'witness-input-sample.json');
const RAPIDSNARK_BIN =
  process.env.QKB_RAPIDSNARK_BIN ??
  '/home/alikvovk/.cache/qkb-bin/rapidsnark-linux-x86_64-v0.0.8/bin/prover';

const haveAllFixtures =
  existsSync(ZKEY_PATH) &&
  existsSync(WASM_PATH) &&
  existsSync(VKEY_PATH) &&
  existsSync(WITNESS_INPUT_PATH) &&
  existsSync(RAPIDSNARK_BIN);

const describeIfFixtures = haveAllFixtures ? describe : describe.skip;

describe('resolveSidecarPathOrThrow — sidecar missing', () => {
  it('throws an actionable error when the sidecar path does not exist', () => {
    expect(() =>
      resolveSidecarPathOrThrow({
        platform: 'linux-x86_64',
        isPkg: false,
        // home points at a tempdir without any cache contents — file
        // can't exist, throw must fire.
        home: join(tmpdir(), `qkb-cli-no-sidecar-${Math.random()}`),
      }),
    ).toThrow(/rapidsnark sidecar not found/);
    expect(() =>
      resolveSidecarPathOrThrow({
        platform: 'linux-x86_64',
        isPkg: false,
        home: join(tmpdir(), `qkb-cli-no-sidecar-${Math.random()}`),
      }),
    ).toThrow(/Run `qkb cache` to inspect cache, or re-install/);
  });
});

describe('fetchAndVerifyManifest — manifest URL unreachable', () => {
  let server: Server;
  let serverUrl: string;

  beforeAll(async () => {
    server = createServer((_req, res) => {
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((res) => {
      server.listen(0, '127.0.0.1', () => res());
    });
    const addr = server.address();
    if (typeof addr !== 'object' || addr === null) throw new Error('no addr');
    serverUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((res) => server.close(() => res()));
  });

  it('surfaces HTTP 404 with a clear error message', async () => {
    await expect(
      fetchAndVerifyManifest({
        manifestUrl: `${serverUrl}/missing-manifest.json`,
        verifySignature: false,
      }),
    ).rejects.toThrow(/HTTP 404/);
  });

  it('surfaces unreachable host (ECONNREFUSED) cleanly', async () => {
    // Port 1 is reserved (TCPMUX) and never listens; reliable
    // unreachable target.
    await expect(
      fetchAndVerifyManifest({
        manifestUrl: 'http://127.0.0.1:1/manifest.json',
        verifySignature: false,
      }),
    ).rejects.toThrow();
  });
});

describeIfFixtures('CliServer — runtime failure modes', () => {
  const TEST_TIMEOUT_MS = 60_000;
  let server: CliServer;
  let baseUrl: string;
  let tmpHome: string;

  beforeEach(async () => {
    tmpHome = await mkdtemp(join(tmpdir(), 'qkb-cli-fail-modes-'));
    server = new CliServer({
      zkeyPath: ZKEY_PATH,
      wasmPath: WASM_PATH,
      vkeyPath: VKEY_PATH,
      rapidsnarkBinPath: RAPIDSNARK_BIN,
      port: 0, // ephemeral
      host: '127.0.0.1',
      allowedOrigin: 'https://identityescrow.org',
      version: 'qkb-cli@test',
      circuit: 'v5.2',
      log: () => {
        // sink — don't pollute test output with intentional-error logs
      },
    });
    const addr = await server.start();
    baseUrl = `http://${addr.host}:${addr.port}`;
  }, TEST_TIMEOUT_MS);

  afterEach(async () => {
    await server.stop();
    await rm(tmpHome, { recursive: true, force: true });
  });

  it('POST /prove with malformed JSON body returns 5xx with parseable error', async () => {
    const res = await fetch(`${baseUrl}/prove`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not valid json {{{',
    });
    expect(res.status).toBe(500);
    const body = (await res.json()) as { error: string };
    expect(typeof body.error).toBe('string');
    expect(body.error.length).toBeGreaterThan(0);
    // Surfaced error mentions JSON-parse failure (snarkjs throws on
    // non-JSON witness input).
    expect(body.error.toLowerCase()).toMatch(/json|unexpected/);
  });

  it('POST /prove with witness missing required fields returns 5xx', async () => {
    const res = await fetch(`${baseUrl}/prove`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ unrelatedField: 1 }),
    });
    expect(res.status).toBe(500);
    const body = (await res.json()) as { error: string };
    expect(typeof body.error).toBe('string');
  }, TEST_TIMEOUT_MS);

  it('two concurrent POST /prove requests: second returns 429', async () => {
    // Read the real witness — first prove takes ~13s so the second
    // POST has time to fire while the first holds the busy mutex.
    const { readFile } = await import('node:fs/promises');
    const witness = JSON.parse(await readFile(WITNESS_INPUT_PATH, 'utf8'));

    // Fire both proves; the first acquires the mutex, the second
    // (issued ~10ms later to ensure ordering) must see busy=true and
    // get 429.
    const firstPromise = fetch(`${baseUrl}/prove`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(witness),
    });
    // Tiny delay to guarantee the first POST has started server-side
    // (mutex acquired) before the second hits.
    await new Promise((res) => setTimeout(res, 200));
    const secondRes = await fetch(`${baseUrl}/prove`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(witness),
    });

    // Second should be 429 immediately while first is still proving.
    expect(secondRes.status).toBe(429);
    const secondBody = (await secondRes.json()) as { error: string };
    expect(secondBody.error).toMatch(/busy/i);

    // First eventually completes.
    const firstRes = await firstPromise;
    expect(firstRes.status).toBe(200);
    const firstBody = (await firstRes.json()) as { verifyOk: boolean };
    expect(firstBody.verifyOk).toBe(true);
  }, TEST_TIMEOUT_MS);
});
