/**
 * UA-specific V4 proof pipeline glue.
 *
 * Composes the existing V4 witness builder, the Diia DOB extractor, and a
 * Poseidon commitment to produce the 16-signal public-leaf array consumed
 * by the V4 UA leaf verifier on-chain.
 *
 * The ordering here MUST match `QKBPresentationEcdsaLeafV4_UA.circom`'s
 * public-signal declarations bit-for-bit; `tests/unit/uaProofPipeline.test.ts`
 * cross-pins against the committed `leaf-synthetic-qkb2.public.json` KAT
 * from the circuits worktree.
 */
import { buildPoseidon } from 'circomlibjs';
import { ZkqesError } from './errors';
import { extractDobFromDiiaUA } from './dob';
import type { BindingV2 } from './bindingV2';
import type { Phase2Witness } from './witness';
import type { PolicyInclusionProof } from './policyTree';
import {
  buildPhase2WitnessV4Draft,
  type LeafWitnessInputV4,
  type Phase2WitnessV4,
} from './witnessV4';

type Poseidon = ((inputs: unknown[]) => unknown) & {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
};

let poseidonP: Promise<Poseidon> | null = null;
function getPoseidon(): Promise<Poseidon> {
  if (poseidonP === null) poseidonP = buildPoseidon() as unknown as Promise<Poseidon>;
  return poseidonP;
}

/**
 * Poseidon(dobYmd, sourceTag) as a decimal string — the value the V4 leaf
 * circuit emits as public signal 14 (`dobCommit`). Exposed independently of
 * the witness builder so callers and tests can pin golden values without
 * running the whole pipeline.
 */
export async function computeDobCommit(dobYmd: bigint, sourceTag: bigint): Promise<string> {
  const p = await getPoseidon();
  const v = p.F.toObject(p([dobYmd, sourceTag]) as unknown);
  return v.toString();
}

export interface BuildUaLeafPublicSignalsV4Input {
  readonly baseWitness: Phase2Witness;
  readonly binding: BindingV2;
  readonly policyProof: PolicyInclusionProof;
  /** Raw leaf cert DER — the DOB extractor scans for OID 2.5.29.9. */
  readonly leafDER: Uint8Array;
}

export interface UaLeafPublicSignalsV4 {
  readonly publicLeafV4: string[];
  readonly witnessV4: Phase2WitnessV4;
  readonly leaf: LeafWitnessInputV4;
  readonly dobYmd: number;
  readonly dobSourceTag: number;
  readonly dobCommit: string;
  readonly dobSupported: 0 | 1;
}

/**
 * Drive the V4 witness builder + Diia DOB extractor + Poseidon commitment
 * and return the 16-string `publicLeafV4` array + the extracted DOB fields
 * in one shot. Order matches the V4 UA leaf verifier's public-input layout:
 *
 *   [0..3]   pkX limbs
 *   [4..7]   pkY limbs
 *   [8]      ctxHash
 *   [9]      policyLeafHash
 *   [10]     policyRoot
 *   [11]     timestamp
 *   [12]     nullifier
 *   [13]     leafSpkiCommit
 *   [14]     dobCommit      = Poseidon(dobYmd, sourceTag)
 *   [15]     dobSupported   = 0 | 1
 *
 * When the supplied leaf DER has no 2.5.29.9 anchor (non-Diia issuer), the
 * DOB fields fall through to `{supported: false, ymd: 0, sourceTag: 0}` and
 * `dobCommit` becomes `Poseidon(0, 0)` — NOT `Poseidon(0, 1)`. For UA-issued
 * leaves without the attribute, the circuit-side `DobExtractorDiiaUA` hard-
 * codes `sourceTag = 1`, so callers with a Diia-issued leaf but no DOB
 * attribute will see `Poseidon(0, 1) = 12583541437132735734108669866114103169564651237895298778035846191048104863326`
 * (the synthetic KAT golden). The TS extractor currently matches the
 * circuit by returning `sourceTag = 0` on the negative path — if a future
 * M2.3b circuit change pins `sourceTag = 1` unconditionally we'll need to
 * mirror that here.
 */
export async function buildUaLeafPublicSignalsV4(
  input: BuildUaLeafPublicSignalsV4Input,
): Promise<UaLeafPublicSignalsV4> {
  const witnessV4 = buildPhase2WitnessV4Draft({
    baseWitness: input.baseWitness,
    binding: input.binding,
    policyProof: input.policyProof,
  });

  const dob = extractDobFromDiiaUA(input.leafDER);

  // The UA circuit's DobExtractorDiiaUA hard-codes `sourceTag = 1`
  // regardless of whether the anchor is present (see circuits commit
  // `5abc98c`). Mirror that here: when the caller hands us a Diia leaf DER,
  // use sourceTag=1 — even if we couldn't find the inner PrintableString —
  // so our public signals agree with what the circuit would emit.
  //
  // We detect "Diia-shaped" by whether the extractor saw the outer 2.5.29.9
  // anchor. If absent, we still emit sourceTag=1 because this module is UA-
  // specific and the circuit hard-codes the tag. This matches the synthetic
  // KAT, which passes leaf DER with no 2.5.29.9 and still sees Poseidon(0,1).
  const dobSupported: 0 | 1 = dob.supported ? 1 : 0;
  const dobYmd = dob.supported ? dob.ymd : 0;
  const dobSourceTag = 1; // circuit-level constant for the UA leaf wrapper

  const dobCommit = await computeDobCommit(BigInt(dobYmd), BigInt(dobSourceTag));

  const publicLeafV4: string[] = [
    ...witnessV4.leaf.pkX,
    ...witnessV4.leaf.pkY,
    witnessV4.leaf.ctxHash,
    witnessV4.leaf.policyLeafHash,
    witnessV4.leaf.policyRoot,
    witnessV4.leaf.timestamp,
    witnessV4.leaf.nullifier,
    witnessV4.leaf.leafSpkiCommit,
    dobCommit,
    dobSupported.toString(),
  ];
  if (publicLeafV4.length !== 16) {
    throw new ZkqesError('qkb.leafPublicSignals', {
      reason: 'expected 16 signals in UA V4 public-leaf output',
      got: publicLeafV4.length,
    });
  }
  return {
    publicLeafV4,
    witnessV4,
    leaf: witnessV4.leaf,
    dobYmd,
    dobSourceTag,
    dobCommit,
    dobSupported,
  };
}
