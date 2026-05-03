#!/usr/bin/env node
/**
 * Local CORS + HTTP-Range fixture server for the in-browser
 * fullProve benchmark.  Adapted from the V4 leaf wasm-prover-benchmark
 * fixture server (arch-fly tree).
 *
 * Defaults to **V5.2** (current).  Set `BENCH_VERSION=v5_1` to serve the
 * V5.1 archive harness + artifacts (used to regenerate the V5.1 baseline
 * report at `benchmarks/v5_1-browser-fullprove-2026-05-01.md`).
 *
 * Why a custom server instead of `python3 -m http.server`:
 *   - All artifacts are served from the same origin (127.0.0.1:8765),
 *     so basic CORS isn't strictly required for THIS harness — but the
 *     headers cost nothing and let the page be loaded from a separate
 *     origin (e.g., a Vite dev server) without a second pass.
 *   - HTTP Range support is retained as defensive infrastructure.  The
 *     installed snarkjs@0.7.6 UMD bundle does NOT issue Range requests
 *     for the zkey load — it does single-shot `fetch().arrayBuffer()`,
 *     which is what THIS benchmark exposes as the feasibility blocker
 *     (see results doc).  But a custom chunked-loader shim — the
 *     workaround we recommend in the results doc — would issue Range
 *     reads, and this server is already prepared for that.  It is also
 *     a port of the V4-era pattern that DID see Range traffic from
 *     ffjavascript FastFile in some configurations.
 *   - python's stdlib http.server doesn't emit CORS headers and doesn't
 *     understand Range; either omission alone would break the V4-style
 *     benchmark, so we ship a minimal Node alternative.
 *
 * Usage:
 *   node packages/circuits/benchmarks/serve-fixtures.mjs
 *   # listens on http://127.0.0.1:8765/
 *
 * Routes (V5.2 default):
 *   GET /                   → benchmarks/v5_2-fullprove-harness.html
 *   GET /harness.html       → same
 *   GET /snarkjs.min.js     → node_modules/.pnpm/snarkjs@0.7.6/.../snarkjs.min.js
 *   GET /v5_2.wasm          → build/v5_2-stub/QKBPresentationV5_js/QKBPresentationV5.wasm
 *   GET /v5_2.zkey          → ceremony/v5_2/qkb-v5_2-stub.zkey   (Range-honoring)
 *   GET /witness-input.json → ceremony/v5_2/witness-input-sample.json
 *   GET /verification_key.json → ceremony/v5_2/verification_key.json
 *   GET /proof-sample.json  → ceremony/v5_2/proof-sample.json
 *   GET /public-sample.json → ceremony/v5_2/public-sample.json
 *
 * Set `BENCH_VERSION=v5_1` for the archive routes (v5_1.wasm, v5_1.zkey,
 * etc., served from build/v5_1-stub/ + ceremony/v5_1/).
 */

import { createServer } from 'node:http';
import { createReadStream, statSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_DIR = resolve(__dirname, '..');
const REPO_ROOT = resolve(PKG_DIR, '../..');

// Resolve snarkjs UMD bundle path (pnpm content-addressed, so wildcard
// is not feasible — match the version we have).
const SNARKJS_UMD = resolve(
  REPO_ROOT,
  'node_modules/.pnpm/snarkjs@0.7.6/node_modules/snarkjs/build/snarkjs.min.js',
);

// Version selector — default V5.2.  Set BENCH_VERSION=v5_1 to serve the
// archived V5.1 baseline routes.
const VERSION = process.env.BENCH_VERSION === 'v5_1' ? 'v5_1' : 'v5_2';
const HARNESS = resolve(__dirname, `${VERSION}-fullprove-harness.html`);
const ROUTES = {
  '/': HARNESS,
  '/harness.html': HARNESS,
  '/snarkjs.min.js': SNARKJS_UMD,
  [`/${VERSION}.wasm`]: resolve(
    PKG_DIR,
    `build/${VERSION}-stub/QKBPresentationV5_js/QKBPresentationV5.wasm`,
  ),
  [`/${VERSION}.zkey`]: resolve(
    PKG_DIR,
    `ceremony/${VERSION}/qkb-${VERSION}-stub.zkey`,
  ),
  '/witness-input.json': resolve(
    PKG_DIR,
    `ceremony/${VERSION}/witness-input-sample.json`,
  ),
  '/verification_key.json': resolve(
    PKG_DIR,
    `ceremony/${VERSION}/verification_key.json`,
  ),
  '/proof-sample.json': resolve(PKG_DIR, `ceremony/${VERSION}/proof-sample.json`),
  '/public-sample.json': resolve(PKG_DIR, `ceremony/${VERSION}/public-sample.json`),
};

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm',
};

function contentTypeFor(path) {
  for (const [ext, ct] of Object.entries(CONTENT_TYPES)) {
    if (path.endsWith(ext)) return ct;
  }
  return 'application/octet-stream';
}

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
  const filePath = ROUTES[url.pathname];

  // CORS headers on EVERY response — including errors.
  // No COEP/COOP — snarkjs is single-threaded and doesn't need
  // SharedArrayBuffer; adding require-corp without `Cross-Origin-Resource-
  // Policy: cross-origin` on every response was blocking some fetches.
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Range, Content-Type',
    'Access-Control-Expose-Headers':
      'Accept-Ranges, Content-Length, Content-Range',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
  };

  // Lightweight request log so we can correlate browser-side failures
  // with what the server actually saw.
  const t0 = Date.now();
  res.on('finish', () => {
    const dt = Date.now() - t0;
    const rangeStr = req.headers['range'] ? ` range=${req.headers['range']}` : '';
    console.log(
      `${req.method} ${url.pathname} → ${res.statusCode}${rangeStr} (${dt}ms)`,
    );
  });

  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  if (!filePath || !existsSync(filePath)) {
    res.writeHead(404, { ...corsHeaders, 'Content-Type': 'text/plain' });
    res.end(`not found: ${url.pathname} (mapped to ${filePath ?? 'no route'})`);
    return;
  }

  const stats = statSync(filePath);
  const total = stats.size;
  const ct = contentTypeFor(filePath);
  const baseHeaders = {
    ...corsHeaders,
    'Content-Type': ct,
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'public, max-age=86400',
  };

  // Honor HTTP Range — kept as defensive infrastructure for a future
  // chunked-loader shim.  Stock snarkjs 0.7.6 does not issue Range
  // requests for the zkey load (it does single-shot fetch().arrayBuffer);
  // this branch is exercised by curl -H "Range: …" smoke tests and
  // by any downstream code that wants partial reads.
  const range = req.headers['range'];
  if (typeof range === 'string') {
    const m = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
    if (m) {
      const startStr = m[1] ?? '';
      const endStr = m[2] ?? '';
      let start;
      let end;
      if (startStr === '' && endStr !== '') {
        // suffix-length form: bytes=-N → last N bytes
        const suffix = Number(endStr);
        start = Math.max(0, total - suffix);
        end = total - 1;
      } else {
        start = startStr === '' ? 0 : Number(startStr);
        end = endStr === '' ? total - 1 : Number(endStr);
      }
      if (
        !Number.isFinite(start) ||
        !Number.isFinite(end) ||
        start < 0 ||
        end >= total ||
        start > end
      ) {
        res.writeHead(416, {
          ...baseHeaders,
          'Content-Range': `bytes */${total}`,
        });
        res.end();
        return;
      }
      const chunkLen = end - start + 1;
      res.writeHead(206, {
        ...baseHeaders,
        'Content-Range': `bytes ${start}-${end}/${total}`,
        'Content-Length': String(chunkLen),
      });
      createReadStream(filePath, { start, end }).pipe(res);
      return;
    }
  }

  res.writeHead(200, {
    ...baseHeaders,
    'Content-Length': String(total),
  });
  createReadStream(filePath).pipe(res);
});

const PORT = Number(process.env.PORT ?? 8765);
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[fixture-server] listening on http://127.0.0.1:${PORT}`);
  console.log('[fixture-server] routes:');
  for (const [route, path] of Object.entries(ROUTES)) {
    const exists = existsSync(path) ? '✓' : '✗';
    const size = existsSync(path)
      ? ` (${(statSync(path).size / 1024 / 1024).toFixed(1)} MB)`
      : '';
    console.log(`  ${exists} ${route}  →  ${path}${size}`);
  }
});

process.on('SIGINT', () => {
  console.log('\n[fixture-server] shutting down');
  server.close(() => process.exit(0));
});
