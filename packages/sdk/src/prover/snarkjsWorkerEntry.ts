/**
 * Worker-side entry-point for SnarkjsWorkerProver.
 *
 * Consumer wires this in their Worker file:
 * ```ts
 * // packages/web/src/workers/snarkjsWorker.ts
 * import { startSnarkjsWorker } from '@zkqes/sdk/prover/snarkjsWorkerEntry';
 * startSnarkjsWorker();
 * ```
 *
 * Then on the main thread:
 * ```ts
 * import { SnarkjsWorkerProver } from '@zkqes/sdk/prover/snarkjsWorker';
 * const worker = new Worker(
 *   new URL('./workers/snarkjsWorker.ts', import.meta.url),
 *   { type: 'module' },
 * );
 * const prover = new SnarkjsWorkerProver({ worker });
 * ```
 *
 * The split is necessary because the SDK is consumer-bundle-agnostic
 * (Vite vs webpack vs esbuild each have different "this URL is a Worker
 * entry" conventions); the consumer composes the Worker URL the way
 * their bundler expects, then forwards execution into our handler.
 *
 * Implements the protocol declared in `./snarkjsWorker` —
 * `SnarkjsWorkerMessage` inbound, `SnarkjsWorkerReply` outbound.
 */
// @ts-expect-error — snarkjs ships no .d.ts of its own; consumer installs it.
import { groth16 } from 'snarkjs';
import type {
  SnarkjsWorkerMessage,
  SnarkjsWorkerReply,
} from './snarkjsWorker.js';

const HEARTBEAT_MS = 2000;

// `DedicatedWorkerGlobalScope` lives in lib.webworker.d.ts, which the SDK
// tsconfig doesn't include (the SDK targets DOM by default). Cast `self`
// to the minimum surface we need (`addEventListener`/`postMessage`) so
// the file typechecks under the SDK's tsconfig without pulling in the
// full WebWorker lib.
type WorkerScope = {
  addEventListener<K extends 'message'>(
    type: K,
    listener: (e: MessageEvent<SnarkjsWorkerMessage>) => void,
  ): void;
  postMessage(data: SnarkjsWorkerReply): void;
};
declare const self: WorkerScope;

interface InflightProve {
  cancelled: boolean;
}

const inflight = new Map<number, InflightProve>();

export function startSnarkjsWorker(): void {
  self.addEventListener('message', (e: MessageEvent<SnarkjsWorkerMessage>) => {
    const msg = e.data;
    if (msg.kind === 'cancel') {
      const slot = inflight.get(msg.id);
      if (slot) slot.cancelled = true;
      return;
    }
    if (msg.kind !== 'prove') return;

    const slot: InflightProve = { cancelled: false };
    inflight.set(msg.id, slot);

    const start = Date.now();
    const post = (reply: SnarkjsWorkerReply): void => {
      self.postMessage(reply);
    };
    const tick = (pct: number, message?: string): void => {
      post({
        kind: 'progress',
        v: 1,
        id: msg.id,
        progress: {
          stage: 'prove',
          pct,
          elapsedMs: Date.now() - start,
          ...(message ? { message } : {}),
        },
      });
    };

    // Heartbeat — snarkjs.groth16.fullProve doesn't emit progress events,
    // so we approximate via wall-clock ticks. Useful for the UI to
    // distinguish "still running" from "hung".
    let heartbeatPct = 20;
    const heartbeatTimer = setInterval(() => {
      heartbeatPct = Math.min(95, heartbeatPct + 2);
      tick(heartbeatPct);
    }, HEARTBEAT_MS);

    tick(10, 'loading wasm + zkey');

    // Pass URLs directly (not pre-fetched bytes) so snarkjs streams the
    // zkey rather than buffering 2.2 GB into V8 heap.
    groth16
      .fullProve(msg.input as never, msg.wasmUrl as never, msg.zkeyUrl as never)
      .then((res: { proof: unknown; publicSignals: unknown }) => {
        clearInterval(heartbeatTimer);
        if (slot.cancelled) {
          inflight.delete(msg.id);
          post({
            kind: 'error',
            v: 1,
            id: msg.id,
            message: 'cancelled',
          });
          return;
        }
        inflight.delete(msg.id);
        post({
          kind: 'result',
          v: 1,
          id: msg.id,
          proof: res.proof as SnarkjsWorkerReply extends { kind: 'result'; proof: infer P } ? P : never,
          publicSignals: (res.publicSignals as unknown[]).map((v) => String(v)),
        });
      })
      .catch((cause: unknown) => {
        clearInterval(heartbeatTimer);
        inflight.delete(msg.id);
        const message = cause instanceof Error ? cause.message : String(cause);
        post({ kind: 'error', v: 1, id: msg.id, message });
      });
  });
}
