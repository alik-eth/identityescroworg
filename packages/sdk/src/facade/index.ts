/**
 * High-level helpers that compose the lower-level SDK modules into the
 * common consumer flows. Pick the entry point that matches your stage:
 *
 *   - `prepareWitnessV4`   → CAdES + bindings → Phase2WitnessV4
 *   - `encodeRegisterFromSignals` → public signals → ABI-encoded register calldata
 *
 * Anything that needs a wallet/provider (actual on-chain submission) stays
 * in the consumer's hands; the SDK doesn't ship a viem WalletClient.
 */
import type { BindingV2 } from '../binding/index.js';
import type { Binding } from '../binding/v1.js';
import type { AlgorithmTag, ParsedCades } from '../cert/cades.js';
import { ZkqesError } from '../errors/index.js';
import type { PolicyInclusionProof } from '../policy/index.js';
import {
  buildPhase2Witness,
  type BuildPhase2WitnessInput,
} from '../witness/builder.js';
import {
  buildPhase2WitnessV4Draft,
  type Phase2WitnessV4,
} from '../witness/index.js';
import {
  buildRegisterArgsV4AgeFromSignals,
  buildRegisterArgsV4FromSignals,
  encodeV4RegisterCalldata,
  type AgeInputsV4,
  type RegisterArgsV4,
  type RegisterArgsV4Age,
} from '../registry/index.js';
import type { Groth16Proof } from '../core/index.js';

// ===========================================================================
// prepareWitnessV4
// ===========================================================================

export interface PrepareWitnessV4Input {
  /** Parsed CAdES-BES detached signature (output of `parseCades`). */
  parsed: ParsedCades;
  /** QKB/1.0 binding object — the legacy shape the leaf circuit's binding-parser scans. */
  bindingV1: Binding;
  /** JCS-canonical bytes of `bindingV1` (output of `canonicalizeBinding`). */
  bindingV1Bytes: Uint8Array;
  /** QKB/2.0 binding — provides policyLeafHash + policyVersion + scheme/pk/timestamp/nonce strings. */
  bindingV2: BindingV2;
  /** Inclusion proof for `bindingV2.policy.leafHash` under the on-chain policyRoot. */
  policyProof: Pick<PolicyInclusionProof, 'leafHex' | 'rootHex' | 'path' | 'indices'>;
  /** Trusted-list Poseidon-Merkle root (decimal, bigint, or 0x-hex). */
  trustedListRoot: string | bigint;
  /** Optional override for parsed.algorithmTag. */
  algorithmTag?: AlgorithmTag;
  /** Optional intermediate DER (when CAdES shipped leaf-only). */
  intermediateCertDer?: Uint8Array;
  /** Merkle inclusion path of the intermediate under trustedListRoot. */
  merklePath?: (string | bigint)[];
  merkleIndices?: number[];
}

/**
 * One-call witness preparation: parse → V1 phase-2 witness → V4 projection.
 * Returns a `Phase2WitnessV4` ready to feed to a Groth16 prover.
 */
export async function prepareWitnessV4(
  input: PrepareWitnessV4Input,
): Promise<Phase2WitnessV4> {
  const phase2Input: BuildPhase2WitnessInput = {
    parsed: input.parsed,
    binding: input.bindingV1,
    bindingBytes: input.bindingV1Bytes,
    trustedListRoot: input.trustedListRoot,
  };
  if (input.algorithmTag !== undefined) phase2Input.algorithmTag = input.algorithmTag;
  if (input.intermediateCertDer !== undefined)
    phase2Input.intermediateCertDer = input.intermediateCertDer;
  if (input.merklePath !== undefined) phase2Input.merklePath = input.merklePath;
  if (input.merkleIndices !== undefined) phase2Input.merkleIndices = input.merkleIndices;

  const baseWitness = await buildPhase2Witness(phase2Input);

  return buildPhase2WitnessV4Draft({
    baseWitness,
    binding: input.bindingV2,
    policyProof: input.policyProof,
  });
}

// ===========================================================================
// encodeRegisterFromSignals
// ===========================================================================

export interface EncodeRegisterFromSignalsInput {
  /** Holder's uncompressed secp256k1 pk: 0x04 || x(32) || y(32). */
  pk: `0x04${string}`;
  proofLeaf: Groth16Proof;
  publicLeaf: readonly string[];
  proofChain: Groth16Proof;
  publicChain: readonly string[];
}

export interface EncodeRegisterFromSignalsAgeInput
  extends EncodeRegisterFromSignalsInput {
  proofAge: Groth16Proof;
  publicAge: readonly string[];
  /** When true, the contract will revert if `ageQualified !== 1`. */
  requireAgeQualification: boolean;
}

export interface EncodedRegister {
  args: RegisterArgsV4;
  calldata: `0x${string}`;
}

export interface EncodedRegisterAge {
  args: RegisterArgsV4Age;
  calldata: `0x${string}`;
}

/**
 * Project leaf + chain Groth16 proofs and their public signals into the
 * QKBRegistryV4.register tuple, then ABI-encode. The non-age register
 * call takes a 14-signal leaf layout (no dobCommit / dobSupported).
 */
export function encodeRegisterFromSignals(
  input: EncodeRegisterFromSignalsInput,
): EncodedRegister {
  if (input.publicLeaf.length !== 14) {
    throw new ZkqesError('qkb.leafPublicSignals', { reason: 'expected-14', got: input.publicLeaf.length });
  }
  if (input.publicChain.length !== 3) {
    throw new ZkqesError('qkb.leafPublicSignals', { reason: 'expected-chain-3', got: input.publicChain.length });
  }
  const args = buildRegisterArgsV4FromSignals(
    input.pk,
    input.proofLeaf,
    input.publicLeaf,
    input.proofChain,
    input.publicChain,
  );
  return { args, calldata: encodeV4RegisterCalldata(args) };
}

/**
 * Age-capable variant: leaf + chain + age proofs → registerWithAge
 * calldata. The age-aware leaf carries 16 public signals (the trailing
 * pair is dobCommit + dobSupported).
 */
export function encodeRegisterFromSignalsAge(
  input: EncodeRegisterFromSignalsAgeInput,
  _ageInputs?: AgeInputsV4,
): EncodedRegisterAge {
  void _ageInputs; // age tuple is fully derived from public signals; kept for API symmetry.
  if (input.publicLeaf.length !== 16) {
    throw new ZkqesError('qkb.leafPublicSignals', { reason: 'expected-16', got: input.publicLeaf.length });
  }
  if (input.publicChain.length !== 3) {
    throw new ZkqesError('qkb.leafPublicSignals', { reason: 'expected-chain-3', got: input.publicChain.length });
  }
  if (input.publicAge.length !== 3) {
    throw new ZkqesError('qkb.leafPublicSignals', { reason: 'expected-age-3', got: input.publicAge.length });
  }
  const args = buildRegisterArgsV4AgeFromSignals(
    input.pk,
    input.proofLeaf,
    input.publicLeaf,
    input.proofChain,
    input.publicChain,
    input.proofAge,
    input.publicAge,
    input.requireAgeQualification,
  );
  return { args, calldata: encodeV4RegisterCalldata(args) };
}
