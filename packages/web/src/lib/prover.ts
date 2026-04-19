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
 * Split-proof (2026-04-18 pivot): each QES presentation needs TWO proofs —
 * leaf (13 public signals) + chain (3 public signals). Both are Groth16
 * against their own zkey. A browser tab cannot hold both zkeys resident
 * simultaneously (leaf ≈ 5.5 GB, chain ≈ 2.3 GB → ~8 GB peak = OOM on
 * most devices), so `proveSplit` drives them SERIALLY and terminates the
 * worker between runs so the VM reclaims the leaf zkey's heap before
 * chain proving starts. Trade-off: wall time is ~60 s instead of ~40 s
 * parallel, but the tab doesn't crash.
 *
 * snarkjs does not emit fine-grained progress; we synthesize a heartbeat
 * every 2s on the worker side so the UI shows elapsed-time progress
 * during the prove stage.
 */
import type { AlgorithmTag } from './cades';
import { QkbError } from './errors';
import type { ChainWitnessInput, LeafWitnessInput, Phase2Witness } from './witness';
import type { AlgorithmArtifactUrls, CircuitArtifactUrls } from './prover.config';

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
  /** Split-proof side — only consumed by MockProver to shape publicSignals
   *  to the circuit-specific length (leaf=13, chain=3). SnarkjsProver
   *  ignores it; the real circuit emits the correct length natively. */
  side?: 'leaf' | 'chain';
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

  async prove(input: Record<string, unknown>, opts: ProveOptions): Promise<ProveResult> {
    const totalDelay = this.cfg.delayMs ?? 30;
    const base = this.cfg.result ?? DEFAULT_MOCK_RESULT;
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
    // If the caller supplied a canned `result`, honor it verbatim — tests
    // rely on bit-for-bit determinism. Otherwise derive publicSignals from
    // the actual witness so downstream shape + equality asserts
    // (leaf-spki-commit-mismatch, hex32, lengths) pass in local dev.
    if (this.cfg.result) return base;
    const signals = derivePublicSignalsFromWitness(input, opts.side);
    if (!signals) return base;
    return { proof: base.proof, publicSignals: signals };
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
  // `/* @vite-ignore */` keeps this URL out of Vite's worker-bundling pass —
  // the worker imports snarkjs, which is an optional peer we intentionally do
  // NOT ship in the default static tarball (nightly-only). Callers that want
  // the real prover set `window.__QKB_REAL_PROVER__ = true` and accept the
  // snarkjs dependency being available at runtime.
  const url = new URL(/* @vite-ignore */ '../workers/prover.worker.ts', import.meta.url);
  return new Worker(url, { type: 'module' });
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

// ---------------------------------------------------------------------------
// Split-proof orchestration — leaf + chain Groth16 proofs in sequence.
// ---------------------------------------------------------------------------

export type ProofSide = 'leaf' | 'chain';

export interface SplitProgress extends ProofProgress {
  side: ProofSide;
}

export interface SplitProveOptions {
  /** Swappable IProver (defaults to SnarkjsProver). Same instance runs both
   *  proofs; `SnarkjsProver` terminates its worker after each prove so the
   *  zkey heap is reclaimed before the next zkey loads. */
  readonly prover: IProver;
  /** Leaf + chain artifact URLs from prover.config.ts (keyed per algorithm). */
  readonly artifacts: AlgorithmArtifactUrls;
  readonly algorithmTag?: AlgorithmTag;
  readonly signal?: AbortSignal;
  readonly onProgress?: (p: SplitProgress) => void;
}

export interface SplitProveResult {
  readonly proofLeaf: Groth16Proof;
  readonly publicLeaf: string[]; // 13 decimal-string field elements
  readonly proofChain: Groth16Proof;
  readonly publicChain: string[]; // 3 decimal-string field elements
}

/**
 * Run the two Groth16 provers serially (leaf first, chain second). Running
 * in parallel would blow a browser tab's RAM (each zkey is several GB);
 * serial trades ~15 s of wall time for reliability. The progress callback
 * tags each event with `side: 'leaf'|'chain'` so the UI can render a
 * two-step spinner.
 */
export async function proveSplit(
  witness: Phase2Witness,
  opts: SplitProveOptions,
): Promise<SplitProveResult> {
  const { prover, artifacts, algorithmTag, signal, onProgress } = opts;
  const leaf = await runSide(
    prover,
    'leaf',
    witness.leaf,
    artifacts.leaf,
    algorithmTag,
    signal,
    onProgress,
  );
  const chain = await runSide(
    prover,
    'chain',
    witness.chain,
    artifacts.chain,
    algorithmTag,
    signal,
    onProgress,
  );
  return {
    proofLeaf: leaf.proof,
    publicLeaf: leaf.publicSignals,
    proofChain: chain.proof,
    publicChain: chain.publicSignals,
  };
}

async function runSide(
  prover: IProver,
  side: ProofSide,
  witness: LeafWitnessInput | ChainWitnessInput,
  urls: CircuitArtifactUrls,
  algorithmTag: AlgorithmTag | undefined,
  signal: AbortSignal | undefined,
  onProgress: ((p: SplitProgress) => void) | undefined,
): Promise<ProveResult> {
  const input = witness as unknown as Record<string, unknown>;
  const opts: ProveOptions = {
    wasmUrl: urls.wasmUrl,
    zkeyUrl: urls.zkeyUrl,
    side,
    onProgress: (p) => onProgress?.({ ...p, side }),
  };
  if (algorithmTag !== undefined) opts.algorithmTag = algorithmTag;
  if (signal !== undefined) opts.signal = signal;
  return prover.prove(input, opts);
}

/**
 * Mirror the circuit's public-signal ordering so MockProver can emit a
 * shape + content that downstream registry asserts accept. Returns null
 * when the input doesn't match a recognized witness shape (tests pass
 * `Record<string, unknown>` fixtures) so the caller falls back to the
 * canned default.
 *
 * Leaf signals order (13): pkX[0..3], pkY[0..3], ctxHash, declHash,
 *   timestamp, nullifier, leafSpkiCommit — matches registry.ts
 *   leafInputsFromPublicSignals.
 * Chain signals order (3): rTL, algorithmTag, leafSpkiCommit — matches
 *   registry.ts chainInputsFromPublicSignals.
 */
function derivePublicSignalsFromWitness(
  input: Record<string, unknown>,
  side: 'leaf' | 'chain' | undefined,
): string[] | null {
  if (side === 'leaf') {
    const pkX = input.pkX;
    const pkY = input.pkY;
    if (!Array.isArray(pkX) || pkX.length !== 4 || !Array.isArray(pkY) || pkY.length !== 4) {
      return null;
    }
    const ctxHash = stringify(input.ctxHash);
    const declHash = stringify(input.declHash);
    const timestamp = stringify(input.timestamp);
    const nullifier = stringify(input.nullifier);
    const leafSpkiCommit = stringify(input.leafSpkiCommit);
    if (
      ctxHash === null ||
      declHash === null ||
      timestamp === null ||
      nullifier === null ||
      leafSpkiCommit === null
    ) {
      return null;
    }
    return [
      stringifyOrZero(pkX[0]),
      stringifyOrZero(pkX[1]),
      stringifyOrZero(pkX[2]),
      stringifyOrZero(pkX[3]),
      stringifyOrZero(pkY[0]),
      stringifyOrZero(pkY[1]),
      stringifyOrZero(pkY[2]),
      stringifyOrZero(pkY[3]),
      ctxHash,
      declHash,
      timestamp,
      nullifier,
      leafSpkiCommit,
    ];
  }
  if (side === 'chain') {
    const rTL = stringify(input.rTL);
    const algorithmTag = stringify(input.algorithmTag);
    const leafSpkiCommit = stringify(input.leafSpkiCommit);
    if (rTL === null || algorithmTag === null || leafSpkiCommit === null) return null;
    return [rTL, algorithmTag, leafSpkiCommit];
  }
  return null;
}

function stringify(v: unknown): string | null {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'bigint') return String(v);
  return null;
}

function stringifyOrZero(v: unknown): string {
  return stringify(v) ?? '0';
}
