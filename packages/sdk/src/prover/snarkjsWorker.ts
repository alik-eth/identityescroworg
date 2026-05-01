/**
 * SnarkjsWorkerProver — wraps a consumer-supplied Web Worker around the
 * blocking `snarkjs.groth16.fullProve` call so the main thread stays
 * responsive during the multi-minute prove step (V5 stub zkey ~2.2 GB,
 * prove takes ~3-10 minutes on commodity hardware).
 *
 * Why consumer-supplied Worker: the SDK is platform-agnostic. Vite,
 * webpack, esbuild + Node, etc. each have a different "create Worker
 * with this entry" pattern. We accept an already-created Worker and
 * speak a stable message protocol over postMessage. Pair with
 * `startSnarkjsWorker()` (re-exported from `./snarkjsWorkerEntry`) on
 * the Worker side.
 *
 * 2.2 GB zkey OOM mitigation (per circuits-eng's surfacing):
 *   1. `fetchToBytes: false` — pass URLs to snarkjs and let it stream
 *      the zkey via fetch+ReadableStream rather than buffering whole.
 *      Reduces peak heap pressure; default in this wrapper.
 *   2. Pre-cache zkey to OPFS / IndexedDB and serve via a service-worker
 *      URL — same fetch pattern but no network round-trip per prove.
 *   3. `terminateAfterProve: true` — kill the Worker after each prove
 *      so the heap is released back to the OS rather than retained
 *      across a long-lived tab. Set this for tabs that prove repeatedly.
 *
 * The actual streaming-load knob is exercised by snarkjs internally via
 * URL inputs; we just avoid materializing zkey/wasm into bytes here.
 */
import { QkbError } from '../errors/index.js';
import type {
  IProver,
  ProofProgress,
  ProveOptions,
  ProveResult,
} from './index.js';

/**
 * Stable message protocol between main thread and Worker. Versioned via
 * the `v` field so future amendments don't break in-flight Workers.
 */
export type SnarkjsWorkerMessage =
  | { kind: 'prove'; v: 1; id: number; input: Record<string, unknown>; wasmUrl: string; zkeyUrl: string }
  | { kind: 'cancel'; v: 1; id: number };

export type SnarkjsWorkerReply =
  | { kind: 'progress'; v: 1; id: number; progress: ProofProgress }
  | { kind: 'result'; v: 1; id: number; proof: ProveResult['proof']; publicSignals: string[] }
  | { kind: 'error'; v: 1; id: number; message: string };

export interface SnarkjsWorkerProverOptions {
  /** Already-created Worker instance. Must speak the protocol above
   *  (typically created with `new Worker(new URL('./worker.ts',
   *  import.meta.url), { type: 'module' })` and the entry calls
   *  `startSnarkjsWorker()`). */
  readonly worker: Worker;
  /** Terminate the Worker after each prove() to release the zkey heap.
   *  Default: false (keep the Worker alive across proves for warm
   *  zkey cache). Flip to true for tabs that prove sporadically. */
  readonly terminateAfterProve?: boolean;
}

let nextProveId = 0;

export class SnarkjsWorkerProver implements IProver {
  constructor(private readonly cfg: SnarkjsWorkerProverOptions) {}

  async prove(
    input: Record<string, unknown>,
    opts: ProveOptions,
  ): Promise<ProveResult> {
    const id = ++nextProveId;
    const { worker } = this.cfg;

    return new Promise<ProveResult>((resolve, reject) => {
      let settled = false;

      const cleanup = (): void => {
        worker.removeEventListener('message', handleMessage);
        worker.removeEventListener('error', handleError);
        opts.signal?.removeEventListener('abort', handleAbort);
        if (this.cfg.terminateAfterProve) worker.terminate();
      };

      const handleMessage = (e: MessageEvent<SnarkjsWorkerReply>): void => {
        const msg = e.data;
        if (msg.id !== id) return;
        if (msg.kind === 'progress') {
          opts.onProgress?.(msg.progress);
          return;
        }
        if (settled) return;
        settled = true;
        if (msg.kind === 'result') {
          cleanup();
          resolve({ proof: msg.proof, publicSignals: msg.publicSignals });
        } else if (msg.kind === 'error') {
          cleanup();
          reject(new QkbError('prover.wasmOOM', { message: msg.message }));
        }
      };

      const handleError = (e: ErrorEvent): void => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(new QkbError('prover.wasmOOM', { message: e.message }));
      };

      const handleAbort = (): void => {
        if (settled) return;
        settled = true;
        const cancelMsg: SnarkjsWorkerMessage = { kind: 'cancel', v: 1, id };
        worker.postMessage(cancelMsg);
        cleanup();
        reject(new QkbError('prover.cancelled'));
      };

      if (opts.signal?.aborted) {
        handleAbort();
        return;
      }

      worker.addEventListener('message', handleMessage);
      worker.addEventListener('error', handleError);
      opts.signal?.addEventListener('abort', handleAbort, { once: true });

      const proveMsg: SnarkjsWorkerMessage = {
        kind: 'prove',
        v: 1,
        id,
        input,
        wasmUrl: opts.wasmUrl,
        zkeyUrl: opts.zkeyUrl,
      };
      worker.postMessage(proveMsg);
    });
  }
}
