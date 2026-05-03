#!/usr/bin/env node
/**
 * `v5_2-prove-server` — local HTTP prove helper.
 *
 * Mirrors the protocol shape of iden3's rapidsnark `proverServer` binary
 * (which is build-from-source only — this Node wrapper around the
 * prebuilt `prover` CLI gets the same architecture without a fresh
 * cmake/gmp toolchain).  Once we validate the pattern end-to-end,
 * production deployment can swap to iden3's actual proverServer or
 * stay on this wrapper — the HTTP surface is identical from the
 * browser-adapter's POV.
 *
 * Endpoints:
 *   POST /prove           body: witness-input JSON
 *                         response: { proof, publicSignals, verifyOk, timings }
 *   GET  /status          response: { ok: true, version, zkeyLoaded, busy }
 *
 * Security model:
 *   - Bind 127.0.0.1 only (no LAN exposure).
 *   - Origin pinning: only accept requests from the configured
 *     ALLOWED_ORIGIN (default: identityescrow.org).  Any other Origin
 *     header → 403.  Mitigates "any tab on the machine probing the
 *     helper."
 *   - Chrome Private Network Access: emit
 *     `Access-Control-Allow-Private-Network: true` on preflight so
 *     the browser permits public-origin → localhost requests.
 *   - No auth token: this is a single-user local helper, the loopback
 *     bind + origin pin is the trust boundary.
 *
 * Usage:
 *   node scripts/v5_2-prove-server.mjs \
 *     --zkey ceremony/v5_2/qkb-v5_2-stub.zkey \
 *     --wasm build/v5_2-stub/QKBPresentationV5_js/QKBPresentationV5.wasm \
 *     --vkey ceremony/v5_2/verification_key.json \
 *     --rapidsnark-bin /home/alikvovk/.cache/qkb-bin/rapidsnark-linux-x86_64-v0.0.8/bin/prover
 *
 *   # Then in another terminal:
 *   curl -X POST -H 'Content-Type: application/json' \
 *     --data @ceremony/v5_2/witness-input-sample.json \
 *     http://127.0.0.1:9080/prove
 */

import { createServer } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';

function parseArgs(argv) {
  const a = {
    port: 9080,
    host: '127.0.0.1',
    'allowed-origin': 'https://identityescrow.org',
  };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if (k === '--help' || k === '-h') {
      a.help = true;
      continue;
    }
    if (!k.startsWith('--')) throw new Error(`unexpected positional: ${k}`);
    a[k.slice(2)] = argv[i + 1];
    i++;
  }
  return a;
}

const args = parseArgs(process.argv);
if (args.help || !args.zkey || !args.wasm || !args.vkey || !args['rapidsnark-bin']) {
  console.error(`v5_2-prove-server — local rapidsnark prove helper

Required:
  --zkey <path>            V5.2 proving key
  --wasm <path>            V5.2 witness-calc WASM
  --vkey <path>            V5.2 verification key
  --rapidsnark-bin <path>  iden3 rapidsnark prover binary

Optional:
  --port <n>               default 9080
  --host <addr>            default 127.0.0.1 (loopback only — DO NOT bind 0.0.0.0)
  --allowed-origin <url>   default https://identityescrow.org
`);
  process.exit(args.help ? 0 : 2);
}

const ZKEY = resolve(args.zkey);
const WASM = resolve(args.wasm);
const VKEY = resolve(args.vkey);
const RS_BIN = resolve(args['rapidsnark-bin']);
const PORT = Number(args.port);
const HOST = args.host;
const ALLOWED_ORIGIN = args['allowed-origin'];

// Preload vkey at boot — verify happens for every prove anyway.
const vkey = JSON.parse(await readFile(VKEY, 'utf8'));
if (vkey.nPublic !== 22) {
  console.error(`[FATAL] vkey.nPublic=${vkey.nPublic} expected 22 (V5.2)`);
  process.exit(1);
}

// Preload snarkjs at boot — first request would otherwise pay ~3 GB
// V8 heap warmup + pkg loader cost.
const snarkjs = await import('snarkjs');

let busy = false;
let provesCompleted = 0;

const server = createServer(async (req, res) => {
  // Common CORS + PNA headers on every response.
  const origin = req.headers.origin ?? '';
  const corsHeaders = {
    'Access-Control-Allow-Origin': origin === ALLOWED_ORIGIN ? origin : '',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Private-Network': 'true', // Chrome 117+ PNA
    'Vary': 'Origin',
  };

  // CORS preflight.
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  // Origin gate (skip for status to allow `curl` smoke tests).
  if (req.url !== '/status' && origin && origin !== ALLOWED_ORIGIN) {
    res.writeHead(403, { ...corsHeaders, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'origin not allowed', allowed: ALLOWED_ORIGIN, got: origin }));
    return;
  }

  if (req.method === 'GET' && req.url === '/status') {
    res.writeHead(200, { ...corsHeaders, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      version: 'v5_2-prove-server@dev',
      zkeyLoaded: true,
      busy,
      provesCompleted,
    }));
    return;
  }

  if (req.method === 'POST' && req.url === '/prove') {
    if (busy) {
      res.writeHead(429, { ...corsHeaders, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'helper busy with another prove' }));
      return;
    }
    busy = true;
    const t0 = performance.now();
    let dir;
    try {
      const body = await readBody(req);
      const witnessInput = JSON.parse(body);
      log(`prove request: ${Object.keys(witnessInput).length} witness fields`);

      dir = await mkdtemp(join(tmpdir(), 'v5_2-prove-'));
      const wtnsPath = join(dir, 'witness.wtns');
      const proofPath = join(dir, 'proof.json');
      const publicPath = join(dir, 'public.json');

      const tWtns0 = performance.now();
      await snarkjs.wtns.calculate(witnessInput, WASM, wtnsPath);
      const tWtns = performance.now() - tWtns0;

      const tProve0 = performance.now();
      await runRapidsnark(RS_BIN, [ZKEY, wtnsPath, proofPath, publicPath]);
      const tProve = performance.now() - tProve0;

      const [proof, publicSignals] = await Promise.all([
        readFile(proofPath, 'utf8').then(JSON.parse),
        readFile(publicPath, 'utf8').then(JSON.parse),
      ]);

      // Sanity check shape before returning.
      if (!Array.isArray(publicSignals) || publicSignals.length !== 22) {
        throw new Error(`expected 22 public signals (V5.2), got ${publicSignals?.length}`);
      }

      const tVerify0 = performance.now();
      const verifyOk = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      const tVerify = performance.now() - tVerify0;

      provesCompleted += 1;
      const tTotal = performance.now() - t0;
      log(`prove ok in ${(tTotal / 1000).toFixed(2)} s  (wtns=${(tWtns / 1000).toFixed(2)}s prove=${(tProve / 1000).toFixed(2)}s verify=${(tVerify * 1000).toFixed(0)}ms)`);

      res.writeHead(200, { ...corsHeaders, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        proof,
        publicSignals,
        verifyOk,
        timings: {
          wtnsCalculateSec: +(tWtns / 1000).toFixed(3),
          groth16ProveSec: +(tProve / 1000).toFixed(3),
          groth16VerifySec: +(tVerify / 1000).toFixed(4),
          totalSec: +(tTotal / 1000).toFixed(3),
        },
      }));
    } catch (e) {
      log(`prove FAIL: ${e.message}`);
      res.writeHead(500, { ...corsHeaders, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    } finally {
      if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
      busy = false;
    }
    return;
  }

  res.writeHead(404, { ...corsHeaders, 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(PORT, HOST, () => {
  log(`listening on http://${HOST}:${PORT}`);
  log(`zkey:           ${ZKEY}`);
  log(`wasm:           ${WASM}`);
  log(`vkey:           ${VKEY}`);
  log(`rapidsnark bin: ${RS_BIN}`);
  log(`allowed origin: ${ALLOWED_ORIGIN}`);
  log(`endpoints:      GET /status   POST /prove`);
});

function readBody(req) {
  return new Promise((res, rej) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => res(buf));
    req.on('error', rej);
  });
}

function runRapidsnark(binPath, args) {
  return new Promise((resolve, reject) => {
    const proc = spawn(binPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let err = '';
    proc.stderr.on('data', (b) => (err += b.toString()));
    proc.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`rapidsnark exited ${code}: ${err.trim()}`));
    });
    proc.on('error', reject);
  });
}

function log(msg) {
  console.error(`[prove-server] ${msg}`);
}
