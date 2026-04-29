/**
 * V5 proof pipeline — orchestrates the in-browser Diia QES → witness →
 * Groth16 proof → register() flow on top of the @qkb/sdk primitives.
 *
 * The flow has three deliberately separable stages so the Step 4
 * component can render granular progress and so the Playwright e2e
 * can stub each stage:
 *
 *   1. parse  — CAdES bundle (existing parseCades from V4)
 *   2. witness — buildV5Witness (gated on circuits-eng §7; Task 8)
 *   3. prove  — proveV5 driver (Task 6)
 *   4. encode — assemble RegisterArgsV5 calldata
 *
 * Until the real witness builder lands, callers can pass
 * `useMockProver: true` to bypass stages 2-3 entirely and use a canned
 * 14-signal output. This keeps the Step 4 component testable without
 * the real zkey; the Playwright e2e in Task 11 uses this toggle.
 */
import {
  MockProver,
  type IProver,
  type ProveOptions,
  type ProveResult,
  publicSignalsFromArray,
  proveV5,
  type CircuitArtifactUrls,
  type PublicSignalsV5,
  type RegisterArgsV5,
  type Groth16ProofV5,
} from '@qkb/sdk';
import { V5_PROVER_ARTIFACTS } from './circuitArtifacts';

export type V5PipelineStage =
  | 'parse-cades'
  | 'build-witness'
  | 'prove'
  | 'encode-calldata'
  | 'submit'
  | 'mined';

export interface V5PipelineProgress {
  stage: V5PipelineStage;
  pct: number;
  elapsedMs?: number;
  message?: string;
}

export interface V5PipelineOptions {
  /** Set true to bypass real witness build + prove with a canned mock.
   *  Used by Playwright e2e (`VITE_USE_MOCK_PROVER=1`) and for UI
   *  development without the ceremony zkey. Defaults to false. */
  readonly useMockProver?: boolean;
  readonly onProgress?: (p: V5PipelineProgress) => void;
  readonly signal?: AbortSignal;
}

export interface V5PipelineResult {
  readonly publicSignals: PublicSignalsV5;
  readonly proof: Groth16ProofV5;
  /** Assembled RegisterArgsV5 ready for `register()` calldata.
   *  Note: the witness-builder side (signedAttrs raw, leafSpki, intSpki,
   *  leafSig, intSig, merkle paths + bits) is filled with mock zeros
   *  when `useMockProver: true` — the Step 4 component skips submit in
   *  that case. Real values land once Task 8 (witness builder) ships. */
  readonly registerArgs: RegisterArgsV5;
}

const ZERO_BYTES32 = `0x${'00'.repeat(32)}` as const;
const ZERO_91_BYTES = `0x${'00'.repeat(91)}` as const;

/**
 * Drive the V5 pipeline end-to-end, emitting progress at each stage.
 *
 * Mock-prover path (used until ceremony + witness builder ship):
 *   - Skips parsing — caller passes any bytes; we don't introspect.
 *   - Skips witness build — feeds a canned 14-signal publicSignals into
 *     proveV5 via MockProver.
 *   - Returns RegisterArgsV5 with mock-zero raw bytes / merkle paths.
 *     The caller MUST NOT submit this to a live registry — Step 4 gates
 *     on `useMockProver` to skip the on-chain submit path.
 *
 * Real path (post-§9.6 ceremony pump + post-Task-8 witness builder):
 *   - parseCades(p7s) to extract leafCert, intermediateCert, signedAttrs, sig
 *   - buildV5Witness({ cades, ..., wallet }) to build the witness input
 *   - proveV5(witness, { prover: SnarkjsProver-via-Worker, artifacts: V5_PROVER_ARTIFACTS })
 *   - publicSignalsFromArray(result.publicSignals) → typed PublicSignalsV5
 *   - assemble RegisterArgsV5 with raw signedAttrs, leafSpki, intSpki,
 *     leafSig (r,s), intSig (r,s), merklePath + merklePathBits.
 */
export async function runV5Pipeline(
  p7s: Uint8Array,
  opts: V5PipelineOptions = {},
): Promise<V5PipelineResult> {
  const onProgress = opts.onProgress ?? (() => {});
  const start = Date.now();
  const tick = (stage: V5PipelineStage, pct: number, message?: string): void => {
    onProgress({
      stage,
      pct,
      elapsedMs: Date.now() - start,
      ...(message ? { message } : {}),
    });
  };

  if (opts.useMockProver) {
    return runMockPath(p7s, tick);
  }
  // Real path — gated until §9.6 ceremony pump + Task 8 witness builder.
  // For now we throw with a clear pointer; Step 4 inspects
  // isV5ArtifactsConfigured() before invoking the pipeline.
  throw new Error(
    'V5 real-prover pipeline requires ceremony artifacts (§9.6) + Task 8 ' +
      'witness builder (gated on circuits-eng §7). Pass useMockProver: true ' +
      'for UI development.',
  );
}

async function runMockPath(
  _p7s: Uint8Array,
  tick: (stage: V5PipelineStage, pct: number, message?: string) => void,
): Promise<V5PipelineResult> {
  tick('parse-cades', 10, 'mock-prover skips real CAdES parsing');
  await delay(20);
  tick('build-witness', 30, 'mock-prover skips real witness build');
  await delay(20);
  tick('prove', 40);

  // Canned 14-signal output — values are deterministic but synthetic.
  // Position-correct per orchestration §0.1, all values = decimal index+1.
  const cannedSignals: PublicSignalsV5 = {
    msgSender: 1n,
    timestamp: BigInt(Math.floor(Date.now() / 1000)),
    nullifier: 3n,
    ctxHashHi: 4n, ctxHashLo: 5n,
    bindingHashHi: 6n, bindingHashLo: 7n,
    signedAttrsHashHi: 8n, signedAttrsHashLo: 9n,
    leafTbsHashHi: 10n, leafTbsHashLo: 11n,
    policyLeafHash: 12n,
    leafSpkiCommit: 13n,
    intSpkiCommit: 14n,
  };
  const prover: IProver = new MockProver({
    delayMs: 30,
    result: {
      proof: {
        pi_a: ['0x1', '0x2', '0x1'],
        pi_b: [['0x3', '0x4'], ['0x5', '0x6'], ['0x1', '0x0']],
        pi_c: ['0x7', '0x8', '0x1'],
        protocol: 'groth16',
        curve: 'bn128',
      },
      publicSignals: [
        '1', String(cannedSignals.timestamp), '3', '4', '5', '6', '7', '8',
        '9', '10', '11', '12', '13', '14',
      ],
    },
  });
  const artifacts: CircuitArtifactUrls = {
    wasmUrl: V5_PROVER_ARTIFACTS.wasmUrl,
    zkeyUrl: V5_PROVER_ARTIFACTS.zkeyUrl,
    zkeySha256: V5_PROVER_ARTIFACTS.zkeySha256,
  };
  const proverInput = { publicSignals: cannedSignals } as Record<string, unknown>;
  const proveResult = await proveV5(proverInput, { prover, artifacts });
  tick('prove', 80);

  const publicSignals = publicSignalsFromArray(proveResult.publicSignals);

  tick('encode-calldata', 95);
  const proof: Groth16ProofV5 = {
    a: [BigInt(proveResult.proof.pi_a[0] ?? '0'), BigInt(proveResult.proof.pi_a[1] ?? '0')] as const,
    b: [
      [BigInt(proveResult.proof.pi_b[0]?.[0] ?? '0'), BigInt(proveResult.proof.pi_b[0]?.[1] ?? '0')] as const,
      [BigInt(proveResult.proof.pi_b[1]?.[0] ?? '0'), BigInt(proveResult.proof.pi_b[1]?.[1] ?? '0')] as const,
    ] as const,
    c: [BigInt(proveResult.proof.pi_c[0] ?? '0'), BigInt(proveResult.proof.pi_c[1] ?? '0')] as const,
  };

  const path16 = Array.from({ length: 16 }, (): `0x${string}` => ZERO_BYTES32) as unknown as RegisterArgsV5['trustMerklePath'];
  const registerArgs: RegisterArgsV5 = {
    proof,
    sig: publicSignals,
    leafSpki: ZERO_91_BYTES,
    intSpki: ZERO_91_BYTES,
    signedAttrs: '0x',
    leafSig: [ZERO_BYTES32, ZERO_BYTES32] as const,
    intSig: [ZERO_BYTES32, ZERO_BYTES32] as const,
    trustMerklePath: path16,
    trustMerklePathBits: 0n,
    policyMerklePath: path16,
    policyMerklePathBits: 0n,
  };

  return { publicSignals, proof, registerArgs };
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
