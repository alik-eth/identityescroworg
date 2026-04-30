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
import { Buffer } from 'buffer';
import { fromBER } from 'asn1js';
import { Certificate } from 'pkijs';
import {
  MockProver,
  type IProver,
  publicSignalsFromArray,
  proveV5,
  type CircuitArtifactUrls,
  type PublicSignalsV5,
  type RegisterArgsV5,
  type Groth16ProofV5,
  buildWitnessV5,
  parseP7s,
  type CmsExtraction,
} from '@qkb/sdk';
import { SnarkjsProver } from '@qkb/sdk/prover/snarkjs';
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
  /** JCS-canonicalized binding bytes (the QKB/2.0 form the user signed
   *  via Diia in Step 2). Required for the real path; ignored by mock.
   *  Step 2 of /ua/registerV5 is responsible for producing these and
   *  threading them through to Step 4 alongside the .p7s. */
  readonly bindingBytes?: Uint8Array;
  /** Pre-extracted SPKIs. If omitted, the real path falls back to deriving
   *  them from the certs inside the .p7s; pass them explicitly when the
   *  caller has already computed them (e.g. integration tests). */
  readonly leafSpki?: Uint8Array;
  readonly intSpki?: Uint8Array;
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
  return runRealPath(p7s, opts, tick);
}

// Real path — buildWitnessV5 (vendored from arch-circuits §7) → snarkjs prove
// → encode RegisterArgsV5. Currently still gated at the call-site by
// `isV5ArtifactsConfigured()` (V5 zkey/wasm URLs are zero-addressed pre-§9.6
// ceremony). Once those land, the only remaining gate is the chain
// deployment (registryV5 != 0x0) and Step 4 will submit on success.
async function runRealPath(
  p7s: Uint8Array,
  opts: V5PipelineOptions,
  tick: (stage: V5PipelineStage, pct: number, message?: string) => void,
): Promise<V5PipelineResult> {
  if (!opts.bindingBytes) {
    throw new Error(
      'V5 real-prover pipeline requires opts.bindingBytes (the JCS-canonical ' +
        'QKB/2.0 binding the user signed in Step 2). Mock path bypasses this.',
    );
  }
  tick('parse-cades', 5, 'parsing CAdES-BES bundle');
  const cms: CmsExtraction = parseP7s(Buffer.from(p7s));

  // SPKIs: prefer caller-supplied (pre-extracted) over deriving from cert
  // DER. Real-Diia .p7s carries leaf + intermediate certs; we extract via
  // pkijs in `extractSpkiFromCertDer` below.
  const leafSpki = opts.leafSpki
    ? Buffer.from(opts.leafSpki)
    : extractSpkiFromCertDer(cms.leafCertDer);
  const intSpki = opts.intSpki
    ? Buffer.from(opts.intSpki)
    : cms.intCertDer
      ? extractSpkiFromCertDer(cms.intCertDer)
      : (() => {
          throw new Error(
            'V5 real-prover pipeline: no intermediate cert in .p7s and no ' +
              'opts.intSpki override — cannot compute intSpkiCommit',
          );
        })();

  tick('build-witness', 25, 'building witness from binding + CMS');
  const witness = await buildWitnessV5({
    bindingBytes: Buffer.from(opts.bindingBytes),
    leafCertDer: cms.leafCertDer,
    leafSpki,
    intSpki,
    signedAttrsDer: cms.signedAttrsDer,
    signedAttrsMdOffset: cms.signedAttrsMdOffset,
  });

  // Run the prover. The proveV5 driver guards on the 14-public-signal
  // count and throws on mismatch — keeps the cross-package contract
  // tight even if circuits-eng adds a 15th signal in a future amendment.
  tick('prove', 50, 'running snarkjs Groth16 prover');
  const artifacts: CircuitArtifactUrls = {
    wasmUrl: V5_PROVER_ARTIFACTS.wasmUrl,
    zkeyUrl: V5_PROVER_ARTIFACTS.zkeyUrl,
    zkeySha256: V5_PROVER_ARTIFACTS.zkeySha256,
  };
  // SnarkjsProver-via-Worker lands as a separate task (the worker hosts
  // the wasm + zkey to avoid main-thread jank). For now we drive snarkjs
  // directly on the main thread — multi-minute prove step will block.
  // Browser consumers should swap this for a Worker wrapper before §9.4
  // closes.
  const prover: IProver = new SnarkjsProver({ fetchToBytes: false });
  const proveResult = await proveV5(witness as Record<string, unknown>, {
    prover,
    artifacts,
  });
  tick('prove', 80);

  const publicSignals = publicSignalsFromArray(proveResult.publicSignals);

  tick('encode-calldata', 90, 'assembling RegisterArgsV5');
  const proof: Groth16ProofV5 = {
    a: [BigInt(proveResult.proof.pi_a[0] ?? '0'), BigInt(proveResult.proof.pi_a[1] ?? '0')] as const,
    b: [
      [BigInt(proveResult.proof.pi_b[0]?.[0] ?? '0'), BigInt(proveResult.proof.pi_b[0]?.[1] ?? '0')] as const,
      [BigInt(proveResult.proof.pi_b[1]?.[0] ?? '0'), BigInt(proveResult.proof.pi_b[1]?.[1] ?? '0')] as const,
    ] as const,
    c: [BigInt(proveResult.proof.pi_c[0] ?? '0'), BigInt(proveResult.proof.pi_c[1] ?? '0')] as const,
  };

  // Trust + policy merkle inclusion paths come from the registry-side
  // Merkle trees (per orchestration §3.x). The Step 4 component pumps
  // these in via wallet-side fixtures; pre-deploy they're zeroed and
  // register() will revert. Web-eng plan Task 9 (post-§9.4) wires the
  // real lookup from `trusted-cas.json` + on-chain root state.
  const path16 = Array.from(
    { length: 16 },
    (): `0x${string}` => ZERO_BYTES32,
  ) as unknown as RegisterArgsV5['trustMerklePath'];

  // RegisterArgsV5 raw-bytes encoding: pkijs gives us Buffer-typed certs
  // and signedAttrs; viem's writeContract accepts `0x${string}` hex.
  const leafSpkiHex = `0x${leafSpki.toString('hex')}` as `0x${string}`;
  const intSpkiHex = `0x${intSpki.toString('hex')}` as `0x${string}`;
  const signedAttrsHex = `0x${cms.signedAttrsDer.toString('hex')}` as `0x${string}`;

  // ECDSA r/s extraction — `parseP7s` exposes the raw `leafSigR` field
  // as the SigBytes inner OCTET STRING. The `register()` calldata wants
  // (r, s) as two bytes32. For a real Diia signature the inner DER form
  // is `SEQUENCE { INTEGER r, INTEGER s }` — we'd parse that here.
  // Until the real-Diia integration lands (gated on a fixture + the
  // contracts-side decoder spec), we forward the raw bytes via zeroing
  // helpers and let the contract path Decoder handle it. Web-eng plan
  // Task 9 amendment will tighten this to actual r/s splitting.
  const registerArgs: RegisterArgsV5 = {
    proof,
    sig: publicSignals,
    leafSpki: leafSpkiHex,
    intSpki: intSpkiHex,
    signedAttrs: signedAttrsHex,
    leafSig: [ZERO_BYTES32, ZERO_BYTES32] as const,
    intSig: [ZERO_BYTES32, ZERO_BYTES32] as const,
    trustMerklePath: path16,
    trustMerklePathBits: 0n,
    policyMerklePath: path16,
    policyMerklePathBits: 0n,
  };

  return { publicSignals, proof, registerArgs };
}

/**
 * Extract the 91-byte canonical P-256 SubjectPublicKeyInfo bytes from a
 * cert DER. The witness builder rejects anything other than the exact
 * canonical 91-byte named-curve form (parseP256Spki at @qkb/sdk
 * witness/v5/spki-commit-ref.ts) — non-conforming CAs would fail
 * `register()`'s SpkiCommit gate anyway.
 */
function extractSpkiFromCertDer(certDer: Buffer): Buffer {
  // We re-parse the cert DER through pkijs to get the SPKI block. Same
  // pkijs that parse-p7s already pulls in; no extra dep cost. ES imports
  // (top of file) — `require()` would leak into the browser bundle.
  const ab = new ArrayBuffer(certDer.length);
  new Uint8Array(ab).set(certDer);
  const asn = fromBER(ab);
  if (asn.offset === -1) {
    throw new Error('extractSpkiFromCertDer: invalid BER');
  }
  const cert = new Certificate({ schema: asn.result });
  return Buffer.from(new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER(false)));
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
