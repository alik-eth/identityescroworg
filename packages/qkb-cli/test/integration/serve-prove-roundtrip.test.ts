// `qkb serve` end-to-end integration test.
//
// Boots a `CliServer` instance directly (in-process; faster + cleaner
// teardown than spawning the binary), POSTs the V5.2 sample witness
// to /prove, asserts the response shape per orchestration §1.1
// contract, and tears down.
//
// Gating: skips entirely if any of the heavy V5.2 fixtures aren't on
// disk (zkey is gitignored at ~2.16 GB; rapidsnark sidecar is in
// ~/.cache; wasm is built locally).  CI without these runs the unit
// tests only.  Local devs with `pnpm -F @qkb/circuits ceremony:v5_2:stub`
// already run will hit this test on every `pnpm -F @qkb/cli test`.

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CliServer } from '../../src/server/http.js';

const __dirname = resolve(fileURLToPath(import.meta.url), '..');

// Fixtures live in the V5.2 ceremony output (committed except for the
// 2 GB zkey itself, which is gitignored).  Cross-package paths walk up
// from this test file to the workspace root, then back down.
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

describeIfFixtures('qkb serve — /prove end-to-end against V5.2 stub', () => {
  // Long timeout: rapidsnark prove on V5.2 is ~6.5 s + wtns calc ~7 s,
  // so the whole thing is ~13-14 s on a workstation.  CI machines may
  // run slower; cap at 60 s.
  const TEST_TIMEOUT_MS = 60_000;

  let server: CliServer;
  let baseUrl: string;
  const logs: string[] = [];

  beforeAll(async () => {
    server = new CliServer({
      zkeyPath: ZKEY_PATH,
      wasmPath: WASM_PATH,
      vkeyPath: VKEY_PATH,
      rapidsnarkBinPath: RAPIDSNARK_BIN,
      port: 0, // ephemeral port — avoids collision with anything else on :9080
      host: '127.0.0.1',
      allowedOrigin: 'https://identityescrow.org',
      version: 'qkb-cli@test',
      circuit: 'v5.2',
      log: (msg) => {
        logs.push(msg);
      },
    });
    const addr = await server.start();
    baseUrl = `http://${addr.host}:${addr.port}`;
  }, TEST_TIMEOUT_MS);

  afterAll(async () => {
    await server.stop();
  });

  it('GET /status returns the full §1.1 shape', async () => {
    const res = await fetch(`${baseUrl}/status`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    // Orchestration §1.1: full shape required for web-eng's
    // detectCli strict gate. Adding a field here without surface
    // discipline is an interface-contract drift.
    expect(body['ok']).toBe(true);
    expect(typeof body['version']).toBe('string');
    expect(body['circuit']).toBe('v5.2');
    expect(body['zkeyLoaded']).toBe(true);
    expect(body['busy']).toBe(false);
    expect(body['provesCompleted']).toBe(0);
    expect(typeof body['uptimeSec']).toBe('number');
    // downloadProgress is null while the zkey is preloaded; T6 will
    // populate the object during the manifest-driven download window.
    expect(body['downloadProgress']).toBeNull();
  });

  it('POST /prove without origin header succeeds (curl-equivalent path)', async () => {
    // Origin pin §1.1: empty Origin is exempt because hostile-origin
    // browser requests always carry one.  Curl smoke tests work.
    const witness = await readJson(WITNESS_INPUT_PATH);
    const res = await fetch(`${baseUrl}/prove`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(witness),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      proof: unknown;
      publicSignals: unknown;
      verifyOk: unknown;
      timings: { totalSec: number };
    };
    expect(Array.isArray(body.publicSignals)).toBe(true);
    expect((body.publicSignals as unknown[]).length).toBe(22);
    expect(body.verifyOk).toBe(true);
    expect(body.timings.totalSec).toBeGreaterThan(0);
    expect(body.timings.totalSec).toBeLessThan(60);
    // Proof is opaque; just check it parsed.
    expect(body.proof).toBeTruthy();
  }, TEST_TIMEOUT_MS);

  it('POST /prove with allowed Origin header succeeds', async () => {
    const witness = await readJson(WITNESS_INPUT_PATH);
    const res = await fetch(`${baseUrl}/prove`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'https://identityescrow.org',
      },
      body: JSON.stringify(witness),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe(
      'https://identityescrow.org',
    );
    expect(res.headers.get('access-control-allow-private-network')).toBe('true');
    const body = (await res.json()) as { verifyOk: unknown };
    expect(body.verifyOk).toBe(true);
  }, TEST_TIMEOUT_MS);

  it('POST /prove with bad Origin returns 403', async () => {
    const res = await fetch(`${baseUrl}/prove`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'https://evil.example.com',
      },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string; allowed: string };
    expect(body.error).toBe('origin not allowed');
    expect(body.allowed).toBe('https://identityescrow.org');
  });

  it('OPTIONS /prove returns 204 with PNA + CORS headers', async () => {
    const res = await fetch(`${baseUrl}/prove`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://identityescrow.org',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Private-Network': 'true',
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-private-network')).toBe('true');
    expect(res.headers.get('access-control-allow-methods')).toContain('POST');
  });

  it('GET /unknown returns 404', async () => {
    const res = await fetch(`${baseUrl}/notarealpath`);
    expect(res.status).toBe(404);
  });
});

async function readJson<T = unknown>(path: string): Promise<T> {
  const { readFile } = await import('node:fs/promises');
  const raw = await readFile(path, 'utf8');
  return JSON.parse(raw) as T;
}
