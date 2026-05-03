/**
 * Swappable Groth16 prover interface.
 *
 * Two implementations ship with the SDK:
 *   - `MockProver` — deterministic stub for tests + dev. Resolves quickly
 *     with canned output after emitting witness/prove/finalize progress
 *     events. Use this in CI so you don't ship a multi-GB zkey to every run.
 *   - `SnarkjsProver` — production prover (subpath import — see
 *     `@qkb/sdk/prover/snarkjs`), runs `snarkjs.groth16.fullProve` in
 *     process. Adds snarkjs as a runtime dependency.
 *
 * For browser use we recommend pinning a Web Worker around `SnarkjsProver`
 * so the main thread stays responsive during the (3–10 minute on commodity
 * hardware) proving step. The worker shape is intentionally NOT bundled
 * here — every framework wires workers differently. Implement `IProver`
 * and call into your worker; routes consume the interface, never the
 * concrete class.
 *
 * Split-proof: each QES presentation needs TWO proofs — leaf (16 public
 * signals) + chain (3 public signals). Each runs against its own zkey;
 * a browser tab cannot hold both zkeys resident simultaneously without
 * OOM, so `proveSplit` drives them SERIALLY.
 */
import { QkbError } from '../errors/index.js';
import type {
  ChainWitnessInput,
  Groth16Proof,
  LeafWitnessInput,
  Phase2Witness,
} from '../core/index.js';
import type { AlgorithmTag } from '../cert/cades.js';

export type { Groth16Proof };

export type ProofStage = 'witness' | 'prove' | 'finalize';

export interface ProofProgress {
  stage: ProofStage;
  pct: number;
  elapsedMs?: number;
  message?: string;
}

export interface ProveResult {
  proof: Groth16Proof;
  publicSignals: string[];
}

export interface ProveOptions {
  wasmUrl: string;
  zkeyUrl: string;
  algorithmTag?: AlgorithmTag;
  /** V4 split-proof side (leaf=16, chain=3) or V5 single proof (v5=14).
   *  Only consumed by MockProver to shape publicSignals to the
   *  circuit-specific length. Real provers ignore it; the circuit emits
   *  the correct length natively. */
  side?: 'leaf' | 'chain' | 'v5';
  onProgress?: (p: ProofProgress) => void;
  signal?: AbortSignal;
}

export interface IProver {
  prove(input: Record<string, unknown>, opts: ProveOptions): Promise<ProveResult>;
}

// ===========================================================================
// Artifact URL types — pin (wasm, zkey, sha256) tuples per circuit, optionally
// per algorithm. Consumers read these from a JSON manifest committed to their
// repo (see @qkb/sdk's circuitArtifacts module for the validated loader).
// ===========================================================================

export interface CircuitArtifactUrls {
  readonly wasmUrl: string;
  readonly zkeyUrl: string;
  readonly zkeySha256: string;
}

export interface AlgorithmArtifactUrls {
  readonly leaf: CircuitArtifactUrls;
  readonly chain: CircuitArtifactUrls;
}

// ===========================================================================
// MockProver — deterministic stub for tests + dev.
// ===========================================================================

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
  publicSignals: Array.from({ length: 16 }, (_, i) => `0x${(i + 1).toString(16)}`),
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
    if (this.cfg.result) return base;
    const signals = derivePublicSignalsFromWitness(input, opts.side);
    if (!signals) return base;
    return { proof: base.proof, publicSignals: signals };
  }
}

// ===========================================================================
// V5 single-proof driver — wraps IProver.prove() with V5-specific URL pinning
// and public-signal-length validation. The V5 architecture collapses V4's
// leaf+chain split into a single Groth16 proof. The public-signal count
// shifts across V5 amendments:
//   V5   (orchestration §0.1)                        — 14 signals
//   V5.1 (privacy / wallet-bound nullifier)          — 19 signals
//   V5.2 (keccak-on-chain / cross-chain portability) — 22 signals
// ===========================================================================

/**
 * Allowed public-signal counts for any V5-family proof. Used by `proveV5`
 * to reject a V4 zkey leaking into the V5 path (V4 leaf emits 16 signals,
 * which is NOT in this set), while still admitting all current and prior
 * V5 amendments. Exported so the V5.2 web pipeline can sanity-check the
 * count post-prove without needing to hardcode literals at every call site.
 */
export const V5_PUBLIC_SIGNALS_LENGTHS = [14, 19, 22] as const;
export type V5PublicSignalsLength = (typeof V5_PUBLIC_SIGNALS_LENGTHS)[number];

export interface ProveV5Options {
  /** Swappable IProver — MockProver in tests, SnarkjsProver+Worker in prod. */
  readonly prover: IProver;
  readonly artifacts: CircuitArtifactUrls;
  readonly signal?: AbortSignal;
  readonly onProgress?: (p: ProofProgress) => void;
}

export interface ProveV5Result {
  readonly proof: Groth16Proof;
  /**
   * Decimal-string field elements. Shape varies by V5 amendment:
   * 14 (V5 baseline), 19 (V5.1), or 22 (V5.2). Callers should use the
   * version-specific `publicSignalsFromArray` / `publicSignalsV5_2FromArray`
   * helpers to assert + decode into a typed struct.
   */
  readonly publicSignals: string[];
}

/**
 * Run a V5-family Groth16 prover once and assert the public-signal count
 * is one of the V5 family's accepted lengths.
 *
 * Why a thin driver instead of calling `prover.prove()` directly:
 *  - Pins `side: 'v5'` so MockProver projects the witness into the
 *    V5 public-signal layout (callers don't have to remember the literal).
 *  - Length-checks `publicSignals.length` against `V5_PUBLIC_SIGNALS_LENGTHS`
 *    post-prove. A V4 zkey sneaking into the V5 path would emit 16 signals
 *    (rejected); a V5/V5.1/V5.2 zkey emits 14/19/22 (admitted). This fails
 *    fast on the V4-leakage case rather than letting the malformed array
 *    reach `register()` — but doesn't punish V5 amendments that grew the
 *    public-signal count by adding new gates (V5.1 wallet binding, V5.2
 *    keccak-on-chain).
 *  - Single seam for future V5-only behaviour (e.g., zkey signature
 *    validation, contract pre-flight reads).
 */
export async function proveV5(
  witness: Record<string, unknown>,
  opts: ProveV5Options,
): Promise<ProveV5Result> {
  const result = await opts.prover.prove(witness, {
    wasmUrl: opts.artifacts.wasmUrl,
    zkeyUrl: opts.artifacts.zkeyUrl,
    side: 'v5',
    ...(opts.onProgress ? { onProgress: opts.onProgress } : {}),
    ...(opts.signal ? { signal: opts.signal } : {}),
  });
  if (
    !(V5_PUBLIC_SIGNALS_LENGTHS as readonly number[]).includes(
      result.publicSignals.length,
    )
  ) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'v5-public-signals-length',
      got: result.publicSignals.length,
      want: [...V5_PUBLIC_SIGNALS_LENGTHS],
    });
  }
  return { proof: result.proof, publicSignals: result.publicSignals };
}

// ===========================================================================
// Split-proof orchestration — leaf + chain Groth16 proofs in sequence.
// ===========================================================================

export type ProofSide = 'leaf' | 'chain';

export interface SplitProgress extends ProofProgress {
  side: ProofSide;
}

export interface SplitProveOptions {
  /** Swappable IProver (MockProver in tests, SnarkjsProver in prod). The
   *  same instance runs both proofs; production provers should release
   *  the leaf zkey's heap before chain proving starts. */
  readonly prover: IProver;
  readonly artifacts: AlgorithmArtifactUrls;
  readonly algorithmTag?: AlgorithmTag;
  readonly signal?: AbortSignal;
  readonly onProgress?: (p: SplitProgress) => void;
}

export interface SplitProveResult {
  readonly proofLeaf: Groth16Proof;
  readonly publicLeaf: string[];
  readonly proofChain: Groth16Proof;
  readonly publicChain: string[];
}

/**
 * Run the two Groth16 provers serially (leaf first, chain second). Running
 * in parallel would blow a browser tab's RAM (each zkey is several GB);
 * serial trades ~15 s of wall time for reliability.
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

// ===========================================================================
// Internal helpers
// ===========================================================================

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

/**
 * Project a witness object into the circuit's public-signal layout so
 * MockProver can emit shape-correct output. Returns null when the input
 * doesn't match a recognized witness shape.
 *
 * Leaf signals (V4 16-signal layout): pkX[0..3], pkY[0..3], ctxHash,
 *   policyLeafHash, policyRoot, timestamp, nullifier, leafSpkiCommit,
 *   dobCommit, dobSupported.
 * Chain signals (3): rTL, algorithmTag, leafSpkiCommit.
 *
 * For V3 (13-signal) compatibility, callers that supply the V3 witness
 * shape get the V3 layout back via the same projection — the V3 fields
 * (declHash) are read from the witness if present.
 */
function derivePublicSignalsFromWitness(
  input: Record<string, unknown>,
  side: 'leaf' | 'chain' | 'v5' | undefined,
): string[] | null {
  if (side === 'v5') {
    // V5 single-circuit: 14 public signals per orchestration §0.1. The
    // witness builder (Task 8) produces a `publicSignals` field whose
    // values are bigints/decimal strings; we project them into the
    // declared §0.1 order. If `publicSignals` isn't present (callers
    // passing raw inputs to the mock), fall through to the canned
    // default — same behaviour as the V4 leaf/chain mismatched-witness
    // case.
    const ps = input.publicSignals;
    if (!ps || typeof ps !== 'object') return null;
    const r = ps as Record<string, unknown>;
    const order = [
      'msgSender', 'timestamp', 'nullifier',
      'ctxHashHi', 'ctxHashLo',
      'bindingHashHi', 'bindingHashLo',
      'signedAttrsHashHi', 'signedAttrsHashLo',
      'leafTbsHashHi', 'leafTbsHashLo',
      'policyLeafHash', 'leafSpkiCommit', 'intSpkiCommit',
    ] as const;
    const out: string[] = [];
    for (const k of order) {
      const v = stringify(r[k]);
      if (v === null) return null;
      out.push(v);
    }
    return out;
  }
  if (side === 'leaf') {
    const pkX = input.pkX;
    const pkY = input.pkY;
    if (!Array.isArray(pkX) || pkX.length !== 4 || !Array.isArray(pkY) || pkY.length !== 4) {
      return null;
    }
    const ctxHash = stringify(input.ctxHash);
    const timestamp = stringify(input.timestamp);
    const nullifier = stringify(input.nullifier);
    const leafSpkiCommit = stringify(input.leafSpkiCommit);
    if (
      ctxHash === null ||
      timestamp === null ||
      nullifier === null ||
      leafSpkiCommit === null
    ) {
      return null;
    }
    // V4 (16 signals) when policyLeafHash + policyRoot are present.
    const policyLeafHash = stringify(input.policyLeafHash);
    const policyRoot = stringify(input.policyRoot);
    if (policyLeafHash !== null && policyRoot !== null) {
      const dobCommit = stringify(input.dobCommit) ?? '0';
      const dobSupported = stringify(input.dobSupported) ?? '0';
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
        policyLeafHash,
        policyRoot,
        timestamp,
        nullifier,
        leafSpkiCommit,
        dobCommit,
        dobSupported,
      ];
    }
    // V3 fallback (13 signals) when declHash is present.
    const declHash = stringify(input.declHash);
    if (declHash !== null) {
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
    return null;
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
