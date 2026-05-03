// `CliServer` — localhost HTTP API for `qkb serve`.
//
// Lifted from the validated prototype at
// `packages/circuits/scripts/v5_2-prove-server.mjs` (252 LOC; measured
// 12.94 s end-to-end against the V5.2 stub zkey).  Major changes
// during the lift:
//   - Promoted from a CommonJS-style top-level script to an exported
//     `CliServer` class with `start()` / `stop()` for testability
//     (boots a server on an ephemeral port in tests; tears down per
//     test rather than per process).
//   - Origin-pin + CORS headers extracted into `./origin-pin.ts` and
//     unit-testable in isolation.
//   - Busy-flag extracted into `./busy-flag.ts`.
//   - rapidsnark spawn extracted into `../circuit/prove.ts`.
//   - Strict TypeScript types on the request/response shapes per
//     orchestration plan §1.1 contract.
//
// The HTTP routing logic itself is byte-equivalent semantics to the
// prototype — same status codes, same error messages, same CORS
// preflight response, same /status JSON shape.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { proveWithRapidsnark } from '../circuit/prove.js';
import { BusyFlag } from './busy-flag.js';
import { corsHeaders, originGate, originRejectionPayload } from './origin-pin.js';

export interface CliServerConfig {
  /** Filesystem path to the V5.2 zkey. */
  readonly zkeyPath: string;
  /** Filesystem path to the V5.2 witness-calculator WASM. */
  readonly wasmPath: string;
  /** Filesystem path to the V5.2 verification key (loaded once at boot). */
  readonly vkeyPath: string;
  /** Filesystem path to the iden3 rapidsnark prover binary. */
  readonly rapidsnarkBinPath: string;
  /** TCP port to bind. */
  readonly port: number;
  /** Bind address — MUST be loopback. */
  readonly host: string;
  /** Origin allowed to /prove.  /status accepts any origin. */
  readonly allowedOrigin: string;
  /** Reported in /status responses. */
  readonly version: string;
  /** Reported in /status responses. */
  readonly circuit: string;
  /** Where to write log lines.  Tests pass a sink to silence stderr. */
  readonly log?: (msg: string) => void;
}

interface ProveTimings {
  readonly wtnsCalculateSec: number;
  readonly groth16ProveSec: number;
  readonly groth16VerifySec: number;
  readonly totalSec: number;
}

interface ProveResponse {
  readonly proof: unknown;
  readonly publicSignals: string[];
  readonly verifyOk: boolean;
  readonly timings: ProveTimings;
}

interface SnarkjsModule {
  readonly wtns: {
    readonly calculate: (
      input: Record<string, unknown>,
      wasmPath: string,
      wtnsPath: string,
    ) => Promise<void>;
  };
  readonly groth16: {
    readonly verify: (
      vkey: unknown,
      publicSignals: string[],
      proof: unknown,
    ) => Promise<boolean>;
  };
}

export class CliServer {
  private readonly cfg: CliServerConfig;
  private readonly busy = new BusyFlag();
  private startedAt = 0;
  private provesCompleted = 0;
  private vkey: unknown = null;
  private snarkjs: SnarkjsModule | null = null;
  private server: Server | null = null;

  constructor(cfg: CliServerConfig) {
    this.cfg = cfg;
  }

  /**
   * Load vkey + snarkjs into memory, bind the configured port.
   * Resolves once the server is listening; rejects on bind failure
   * or vkey shape mismatch.
   */
  async start(): Promise<{ port: number; host: string }> {
    // Preload vkey at boot — verify happens on every prove anyway, and
    // a malformed vkey should fail at startup (operator gets immediate
    // feedback) rather than on the first prove (browser sees 500
    // mid-flow).
    const vkeyRaw = await readFile(this.cfg.vkeyPath, 'utf8');
    const vkey = JSON.parse(vkeyRaw) as { nPublic?: number };
    if (vkey.nPublic !== 22) {
      throw new Error(
        `vkey.nPublic=${String(vkey.nPublic)} expected 22 (V5.2)`,
      );
    }
    this.vkey = vkey;

    // Preload snarkjs at boot — first-request latency would otherwise
    // pay the snarkjs UMD-bundle parse + V8 warmup (~3 GB heap touch).
    this.snarkjs = (await import('snarkjs')) as unknown as SnarkjsModule;

    const server = createServer((req, res) => {
      // Each request is wrapped — never bubble exceptions to the Node
      // default handler (which would spew to stderr without sending
      // a response, leaving the browser hanging).
      this.handle(req, res).catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        this.log(`unhandled: ${msg}`);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: msg }));
        }
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.cfg.port, this.cfg.host, () => {
        server.off('error', reject);
        resolve();
      });
    });

    this.server = server;
    this.startedAt = Date.now();

    const addr = server.address();
    const boundPort =
      typeof addr === 'object' && addr !== null ? addr.port : this.cfg.port;

    this.log(`listening on http://${this.cfg.host}:${boundPort}`);
    this.log(`zkey:           ${this.cfg.zkeyPath}`);
    this.log(`wasm:           ${this.cfg.wasmPath}`);
    this.log(`vkey:           ${this.cfg.vkeyPath}`);
    this.log(`rapidsnark bin: ${this.cfg.rapidsnarkBinPath}`);
    this.log(`allowed origin: ${this.cfg.allowedOrigin}`);
    this.log(`endpoints:      GET /status   POST /prove`);

    return { port: boundPort, host: this.cfg.host };
  }

  /** Close the server cleanly.  Idempotent. */
  async stop(): Promise<void> {
    if (!this.server) return;
    const server = this.server;
    this.server = null;
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const origin = req.headers.origin ?? '';
    const headers = corsHeaders(origin, this.cfg.allowedOrigin);

    if (req.method === 'OPTIONS') {
      res.writeHead(204, headers);
      res.end();
      return;
    }

    const gate = originGate({
      url: req.url,
      origin,
      allowedOrigin: this.cfg.allowedOrigin,
    });
    if (!gate.allowed) {
      res.writeHead(403, { ...headers, 'Content-Type': 'application/json' });
      res.end(JSON.stringify(originRejectionPayload(origin, this.cfg.allowedOrigin)));
      return;
    }

    if (req.method === 'GET' && req.url === '/status') {
      res.writeHead(200, { ...headers, 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          ok: true,
          version: this.cfg.version,
          circuit: this.cfg.circuit,
          zkeyLoaded: true,
          busy: this.busy.isBusy(),
          provesCompleted: this.provesCompleted,
          uptimeSec: Math.floor((Date.now() - this.startedAt) / 1000),
          // Per orchestration §1.1, downloadProgress is `null` while
          // zkey is loaded (V1 CliServer takes pre-cached zkey path
          // explicitly; manifest-driven download lives in T6+ and will
          // populate this object during the download window).  The
          // field MUST be present for web-eng's detectCli strict
          // shape gate.
          downloadProgress: null,
        }),
      );
      return;
    }

    if (req.method === 'POST' && req.url === '/prove') {
      await this.handleProve(req, res, headers);
      return;
    }

    res.writeHead(404, { ...headers, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  }

  private async handleProve(
    req: IncomingMessage,
    res: ServerResponse,
    headers: Record<string, string>,
  ): Promise<void> {
    if (!this.busy.tryAcquire()) {
      res.writeHead(429, { ...headers, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'helper busy with another prove' }));
      return;
    }

    const t0 = performance.now();
    let dir: string | null = null;
    try {
      const body = await readBody(req);
      const witnessInput = JSON.parse(body) as Record<string, unknown>;
      this.log(`prove request: ${Object.keys(witnessInput).length} witness fields`);

      dir = await mkdtemp(join(tmpdir(), 'qkb-prove-'));
      const wtnsPath = join(dir, 'witness.wtns');
      const proofPath = join(dir, 'proof.json');
      const publicPath = join(dir, 'public.json');

      const snarkjs = this.snarkjs;
      if (!snarkjs) throw new Error('snarkjs not loaded (server not started?)');

      const tWtns0 = performance.now();
      await snarkjs.wtns.calculate(witnessInput, this.cfg.wasmPath, wtnsPath);
      const tWtns = performance.now() - tWtns0;

      const tProve0 = performance.now();
      await proveWithRapidsnark({
        binaryPath: this.cfg.rapidsnarkBinPath,
        zkeyPath: this.cfg.zkeyPath,
        wtnsPath,
        proofOutPath: proofPath,
        publicOutPath: publicPath,
      });
      const tProve = performance.now() - tProve0;

      const [proofRaw, publicRaw] = await Promise.all([
        readFile(proofPath, 'utf8'),
        readFile(publicPath, 'utf8'),
      ]);
      const proof = JSON.parse(proofRaw) as unknown;
      const publicSignals = JSON.parse(publicRaw) as string[];

      if (!Array.isArray(publicSignals) || publicSignals.length !== 22) {
        throw new Error(
          `expected 22 public signals (V5.2), got ${String(publicSignals?.length)}`,
        );
      }

      const tVerify0 = performance.now();
      const verifyOk = await snarkjs.groth16.verify(this.vkey, publicSignals, proof);
      const tVerify = performance.now() - tVerify0;

      this.provesCompleted += 1;
      const tTotal = performance.now() - t0;
      this.log(
        `prove ok in ${(tTotal / 1000).toFixed(2)} s ` +
          `(wtns=${(tWtns / 1000).toFixed(2)}s prove=${(tProve / 1000).toFixed(2)}s ` +
          `verify=${tVerify.toFixed(0)}ms)`,
      );

      const response: ProveResponse = {
        proof,
        publicSignals,
        verifyOk,
        timings: {
          wtnsCalculateSec: roundTo(tWtns / 1000, 3),
          groth16ProveSec: roundTo(tProve / 1000, 3),
          groth16VerifySec: roundTo(tVerify / 1000, 4),
          totalSec: roundTo(tTotal / 1000, 3),
        },
      };
      res.writeHead(200, { ...headers, 'Content-Type': 'application/json' });
      res.end(JSON.stringify(response));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.log(`prove FAIL: ${msg}`);
      res.writeHead(500, { ...headers, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: msg }));
    } finally {
      // Release busy BEFORE awaiting tempdir cleanup.  Otherwise the
      // window between `res.end()` and `busy.release()` is wide enough
      // (the rm is async, yields to the event loop) for a fast
      // follow-up POST to see busy=true and get 429.  Caught by the
      // T2 integration test on first run: two back-to-back proves,
      // second came back 429.  Cleanup fires-and-forgets — errors
      // are intentionally swallowed (cleanup of a process-private
      // tempdir failing is non-fatal; OS will GC at reboot).
      this.busy.release();
      if (dir) {
        void rm(dir, { recursive: true, force: true }).catch(() => {});
      }
    }
  }

  private log(msg: string): void {
    if (this.cfg.log) {
      this.cfg.log(msg);
    } else {
      process.stderr.write(`[qkb-serve] ${msg}\n`);
    }
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = '';
    req.on('data', (chunk: Buffer) => {
      buf += chunk.toString('utf8');
    });
    req.on('end', () => resolve(buf));
    req.on('error', reject);
  });
}

function roundTo(n: number, places: number): number {
  const factor = 10 ** places;
  return Math.round(n * factor) / factor;
}
