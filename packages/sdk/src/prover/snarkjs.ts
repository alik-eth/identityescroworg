/**
 * Direct (non-Worker) SnarkjsProver — runs `snarkjs.groth16.fullProve` in
 * the calling thread. Suitable for Node consumers and CLIs. Browser
 * consumers should wrap this in a Web Worker so the main thread stays
 * responsive during the multi-minute prove step.
 *
 * `snarkjs` is an optional peer dependency; importing this file requires
 * the consumer to install it.
 */
// @ts-expect-error — snarkjs ships no .d.ts of its own; consumer installs it.
import { groth16 } from 'snarkjs';
import { QkbError } from '../errors/index.js';
import type {
  IProver,
  ProofStage,
  ProveOptions,
  ProveResult,
} from './index.js';

export interface SnarkjsProverOptions {
  /** If your snarkjs build can read URLs directly (browser), set false.
   *  In Node, leave true so the prover fetches into Buffers first. */
  fetchToBytes?: boolean;
  fetch?: (url: string) => Promise<ArrayBuffer>;
}

const HEARTBEAT_MS = 2000;

export class SnarkjsProver implements IProver {
  constructor(private readonly cfg: SnarkjsProverOptions = {}) {}

  async prove(
    input: Record<string, unknown>,
    opts: ProveOptions,
  ): Promise<ProveResult> {
    const start = Date.now();
    const tick = (stage: ProofStage, pct: number): void => {
      opts.onProgress?.({ stage, pct, elapsedMs: Date.now() - start });
    };

    if (opts.signal?.aborted) {
      throw new QkbError('prover.cancelled');
    }

    tick('witness', 10);

    const wasm = await this.resolve(opts.wasmUrl);
    const zkey = await this.resolve(opts.zkeyUrl);

    if (opts.signal?.aborted) {
      throw new QkbError('prover.cancelled');
    }

    tick('prove', 20);
    let heartbeatTimer: ReturnType<typeof setInterval> | null = null;
    let elapsed = 0;
    if (opts.onProgress) {
      heartbeatTimer = setInterval(() => {
        elapsed += HEARTBEAT_MS;
        opts.onProgress?.({
          stage: 'prove',
          pct: Math.min(95, 20 + Math.floor(elapsed / 1000)),
          elapsedMs: Date.now() - start,
        });
      }, HEARTBEAT_MS);
    }

    let res: { proof: unknown; publicSignals: unknown };
    try {
      res = (await groth16.fullProve(input, wasm as never, zkey as never)) as {
        proof: unknown;
        publicSignals: unknown;
      };
    } catch (cause) {
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      const msg = cause instanceof Error ? cause.message : String(cause);
      throw new QkbError('prover.wasmOOM', { message: msg });
    } finally {
      if (heartbeatTimer) clearInterval(heartbeatTimer);
    }

    if (opts.signal?.aborted) {
      throw new QkbError('prover.cancelled');
    }

    tick('finalize', 100);
    return {
      proof: res.proof as ProveResult['proof'],
      publicSignals: (res.publicSignals as unknown[]).map((v) => String(v)),
    };
  }

  private async resolve(url: string): Promise<Uint8Array | string> {
    if (this.cfg.fetchToBytes === false) return url;
    const fetcher = this.cfg.fetch ?? defaultFetch;
    const buf = await fetcher(url);
    return new Uint8Array(buf);
  }
}

async function defaultFetch(url: string): Promise<ArrayBuffer> {
  const r = await fetch(url);
  if (!r.ok) {
    throw new QkbError('prover.artifactMismatch', {
      reason: `HTTP ${r.status} fetching ${url}`,
    });
  }
  return r.arrayBuffer();
}
