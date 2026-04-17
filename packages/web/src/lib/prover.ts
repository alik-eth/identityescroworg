/**
 * Swappable Groth16 prover interface.
 *
 * The default `SnarkjsProver` runs `snarkjs.groth16.fullProve` in a Web
 * Worker so the main thread stays responsive during the (3–10 minute on
 * commodity hardware) proving step. The worker is constructed lazily and
 * terminated when the caller's AbortSignal fires — snarkjs has no native
 * cancellation hook, so termination is the only way to actually stop work.
 *
 * Replacing the prover later (rapidsnark-wasm, for instance) only requires
 * implementing IProver elsewhere — routes consume the interface, never the
 * concrete class. `algorithmTag` is plumbed through so the route layer can
 * pick the matching `public/circuits/{rsa,ecdsa}/{wasm,zkey}` pair before
 * calling `prove()`; the prover itself just consumes the URLs handed in.
 *
 * snarkjs does not emit fine-grained progress; we synthesize a heartbeat
 * every 2s on the worker side so the UI shows elapsed-time progress
 * during the prove stage.
 */
import type { AlgorithmTag } from './cades';
import { QkbError } from './errors';

export type ProofStage = 'witness' | 'prove' | 'finalize';

export interface ProofProgress {
  stage: ProofStage;
  pct: number;
  elapsedMs?: number;
  message?: string;
}

export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol?: string;
  curve?: string;
}

export interface ProveResult {
  proof: Groth16Proof;
  publicSignals: string[];
}

export interface ProveOptions {
  wasmUrl: string;
  zkeyUrl: string;
  algorithmTag?: AlgorithmTag;
  onProgress?: (p: ProofProgress) => void;
  signal?: AbortSignal;
}

export interface IProver {
  prove(input: Record<string, unknown>, opts: ProveOptions): Promise<ProveResult>;
}

// ---------------------------------------------------------------------------
// MockProver — used by route-level Playwright tests so we don't have to ship
// a 30 MB zkey to every CI run. Resolves quickly with deterministic output
// after emitting witness/prove/finalize progress events.
// ---------------------------------------------------------------------------

export interface MockProverOptions {
  delayMs?: number;
  result?: ProveResult;
}

const DEFAULT_MOCK_RESULT: ProveResult = {
  proof: {
    pi_a: ['0x1', '0x2', '0x1'],
    pi_b: [
      ['0x3', '0x4'],
      ['0x5', '0x6'],
      ['0x1', '0x0'],
    ],
    pi_c: ['0x7', '0x8', '0x1'],
    protocol: 'groth16',
    curve: 'bn128',
  },
  publicSignals: Array.from({ length: 13 }, (_, i) => `0x${(i + 1).toString(16)}`),
};

export class MockProver implements IProver {
  constructor(private readonly cfg: MockProverOptions = {}) {}

  async prove(_input: Record<string, unknown>, opts: ProveOptions): Promise<ProveResult> {
    const totalDelay = this.cfg.delayMs ?? 30;
    const result = this.cfg.result ?? DEFAULT_MOCK_RESULT;
    const stages: ProofStage[] = ['witness', 'prove', 'finalize'];
    const start = Date.now();
    for (let i = 0; i < stages.length; i++) {
      checkAborted(opts.signal);
      await sleep(totalDelay / stages.length, opts.signal);
      const stage = stages[i] as ProofStage;
      opts.onProgress?.({
        stage,
        pct: ((i + 1) / stages.length) * 100,
        elapsedMs: Date.now() - start,
      });
    }
    checkAborted(opts.signal);
    return result;
  }
}

// ---------------------------------------------------------------------------
// SnarkjsProver — production prover, dispatches to a Web Worker.
// ---------------------------------------------------------------------------

interface WorkerProveRequest {
  type: 'prove';
  id: number;
  input: Record<string, unknown>;
  wasmUrl: string;
  zkeyUrl: string;
}

interface WorkerProgressMsg {
  type: 'progress';
  id: number;
  stage: ProofStage;
  pct: number;
  elapsedMs: number;
}

interface WorkerResultMsg {
  type: 'result';
  id: number;
  result: ProveResult;
}

interface WorkerErrorMsg {
  type: 'error';
  id: number;
  message: string;
  code?: string;
}

export type ProverWorkerMessage = WorkerProgressMsg | WorkerResultMsg | WorkerErrorMsg;

export type WorkerFactory = () => Worker;

export class SnarkjsProver implements IProver {
  private nextId = 1;

  constructor(private readonly workerFactory: WorkerFactory = defaultWorkerFactory) {}

  prove(input: Record<string, unknown>, opts: ProveOptions): Promise<ProveResult> {
    const worker = this.workerFactory();
    const id = this.nextId++;
    return new Promise<ProveResult>((resolve, reject) => {
      const cleanup = () => {
        worker.removeEventListener('message', onMessage);
        worker.removeEventListener('error', onError);
        if (opts.signal) opts.signal.removeEventListener('abort', onAbort);
        worker.terminate();
      };
      const onAbort = () => {
        cleanup();
        reject(new QkbError('prover.cancelled'));
      };
      const onError = (ev: ErrorEvent) => {
        cleanup();
        reject(new QkbError('prover.wasmOOM', { message: ev.message }));
      };
      const onMessage = (ev: MessageEvent<ProverWorkerMessage>) => {
        const msg = ev.data;
        if (msg.id !== id) return;
        if (msg.type === 'progress') {
          opts.onProgress?.({
            stage: msg.stage,
            pct: msg.pct,
            elapsedMs: msg.elapsedMs,
          });
          return;
        }
        if (msg.type === 'result') {
          cleanup();
          resolve(msg.result);
          return;
        }
        if (msg.type === 'error') {
          cleanup();
          const code = msg.code === 'prover.cancelled' ? 'prover.cancelled' : 'prover.wasmOOM';
          reject(new QkbError(code, { message: msg.message }));
        }
      };
      worker.addEventListener('message', onMessage);
      worker.addEventListener('error', onError);
      if (opts.signal) {
        if (opts.signal.aborted) {
          cleanup();
          reject(new QkbError('prover.cancelled'));
          return;
        }
        opts.signal.addEventListener('abort', onAbort, { once: true });
      }
      const req: WorkerProveRequest = {
        type: 'prove',
        id,
        input,
        wasmUrl: opts.wasmUrl,
        zkeyUrl: opts.zkeyUrl,
      };
      worker.postMessage(req);
    });
  }
}

function defaultWorkerFactory(): Worker {
  return new Worker(new URL('../workers/prover.worker.ts', import.meta.url), {
    type: 'module',
  });
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(new QkbError('prover.cancelled'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new QkbError('prover.cancelled'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function checkAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new QkbError('prover.cancelled');
}
