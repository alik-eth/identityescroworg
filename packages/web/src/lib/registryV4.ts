/**
 * Draft QKBRegistryV4 bindings — policy-root successor surface.
 *
 * This module is intentionally forward-looking and MUST NOT be wired into the
 * live V3 submit path until the successor leaf circuit / verifier / registry
 * are real. Its purpose is to freeze the intended proof bundle boundary for
 * `QKB/2.0`:
 *
 *   Leaf (14 public signals)
 *     [0..3]  pkX limbs
 *     [4..7]  pkY limbs
 *     [8]     ctxHash
 *     [9]     policyLeafHash
 *     [10]    policyRoot
 *     [11]    timestamp
 *     [12]    nullifier
 *     [13]    leafSpkiCommit
 *
 *   Chain (3 public signals; unchanged from V3)
 *     [0]     rTL
 *     [1]     algorithmTag
 *     [2]     leafSpkiCommit
 *
 * Rationale for exposing both `policyLeafHash` and `policyRoot`:
 *   - `policyRoot` is the acceptance gate controlled by the contract.
 *   - `policyLeafHash` keeps the proof bundle self-describing across root
 *     rotations and makes it explicit which policy leaf the signed binding
 *     referenced.
 *
 * The future leaf circuit may still keep the Merkle path private and only
 * publish these two commitments plus the existing nullifier / key surface.
 */
import { QkbError } from './errors';
import type { Groth16Proof } from './prover';
import { packProof, type ChainInputs, type SolidityProof } from './registry';
import type { LeafPublicSignals } from './witnessV4';

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface LeafInputsV4 {
  readonly pkX: readonly [string, string, string, string];
  readonly pkY: readonly [string, string, string, string];
  readonly ctxHash: `0x${string}`;
  readonly policyLeafHash: `0x${string}`;
  readonly policyRoot: `0x${string}`;
  readonly timestamp: string | bigint | number;
  readonly nullifier: `0x${string}`;
  readonly leafSpkiCommit: `0x${string}`;
}

export interface LeafInputsV4AgeCapable extends LeafInputsV4 {
  readonly dobCommit: `0x${string}`;
  readonly dobSupported: 0 | 1;
}

export interface AgeInputsV4 {
  readonly dobCommit: `0x${string}`;
  readonly ageCutoffDate: string | bigint | number;
  readonly ageQualified: 0 | 1;
}

export interface RegisterArgsV4 {
  readonly pk: `0x04${string}`;
  readonly proofLeaf: SolidityProof;
  readonly leafInputs: LeafInputsV4;
  readonly proofChain: SolidityProof;
  readonly chainInputs: ChainInputs;
}

export interface RegisterArgsV4Age {
  readonly pk: `0x04${string}`;
  readonly proofLeaf: SolidityProof;
  readonly leafInputs: LeafInputsV4AgeCapable;
  readonly proofChain: SolidityProof;
  readonly chainInputs: ChainInputs;
  readonly proofAge: SolidityProof;
  readonly ageInputs: AgeInputsV4;
  readonly requireAgeQualification: boolean;
}

export interface LeafPublicSignalsV4 {
  readonly signals: readonly string[];
  readonly pkX: readonly string[];
  readonly pkY: readonly string[];
  readonly ctxHash: string;
  readonly policyLeafHash: string;
  readonly policyRoot: string;
  readonly timestamp: string;
  readonly nullifier: string;
  readonly leafSpkiCommit: string;
}

export interface LeafPublicSignalsV4AgeCapable extends LeafPublicSignalsV4 {
  readonly dobCommit: string;
  readonly dobSupported: string;
}

export interface LeafPublicSignalFieldsV4 {
  readonly pkX: readonly string[];
  readonly pkY: readonly string[];
  readonly ctxHash: string;
  readonly policyLeafHash: string;
  readonly policyRoot: string;
  readonly timestamp: string;
  readonly nullifier: string;
  readonly leafSpkiCommit: string;
}

export interface LeafPublicSignalFieldsV4AgeCapable extends LeafPublicSignalFieldsV4 {
  readonly dobCommit: string;
  readonly dobSupported: string | number;
}

export interface AgePublicSignalsV4 {
  readonly signals: readonly string[];
  readonly dobCommit: string;
  readonly ageCutoffDate: string;
  readonly ageQualified: string;
}

export interface AgePublicSignalFieldsV4 {
  readonly dobCommit: string;
  readonly ageCutoffDate: string | bigint | number;
  readonly ageQualified: string | number;
}

export interface G16Proof {
  a: readonly [bigint, bigint];
  b: readonly [readonly [bigint, bigint], readonly [bigint, bigint]];
  c: readonly [bigint, bigint];
}

export interface LeafCalldata {
  a: readonly [bigint, bigint];
  b: readonly [readonly [bigint, bigint], readonly [bigint, bigint]];
  c: readonly [bigint, bigint];
  inputs: readonly bigint[];
}

export function encodeLeafProofCalldata(
  proof: G16Proof,
  s: LeafPublicSignals,
): LeafCalldata {
  return {
    a: proof.a,
    b: proof.b,
    c: proof.c,
    inputs: [
      ...s.pkX,
      ...s.pkY,
      s.ctxHash,
      s.policyLeafHash,
      s.policyRoot,
      s.timestamp,
      s.nullifier,
      s.leafSpkiCommit,
      s.dobCommit,
      s.dobSupported,
    ],
  };
}

export function assertRegisterArgsV4Shape(args: RegisterArgsV4): void {
  if (!args.pk.startsWith('0x04') || args.pk.length !== 132) {
    throw new QkbError('binding.pkMismatch', { reason: 'register-args-v4-pk-shape' });
  }
  assertProofShape(args.proofLeaf, 'leaf');
  assertProofShape(args.proofChain, 'chain');
  assertLeafInputsV4Shape(args.leafInputs);
  assertChainInputsShape(args.chainInputs);
  if (args.leafInputs.leafSpkiCommit.toLowerCase() !== args.chainInputs.leafSpkiCommit.toLowerCase()) {
    throw new QkbError('witness.fieldTooLong', { reason: 'leaf-spki-commit-mismatch-v4' });
  }
}

export function assertRegisterArgsV4AgeShape(args: RegisterArgsV4Age): void {
  if (!args.pk.startsWith('0x04') || args.pk.length !== 132) {
    throw new QkbError('binding.pkMismatch', { reason: 'register-args-v4-age-pk-shape' });
  }
  assertProofShape(args.proofLeaf, 'leaf');
  assertProofShape(args.proofChain, 'chain');
  assertProofShape(args.proofAge, 'age');
  assertLeafInputsV4AgeShape(args.leafInputs);
  assertChainInputsShape(args.chainInputs);
  assertAgeInputsV4Shape(args.ageInputs);
  if (args.leafInputs.leafSpkiCommit.toLowerCase() !== args.chainInputs.leafSpkiCommit.toLowerCase()) {
    throw new QkbError('witness.fieldTooLong', { reason: 'leaf-spki-commit-mismatch-v4-age' });
  }
  if (args.requireAgeQualification) {
    if (args.leafInputs.dobSupported !== 1) {
      throw new QkbError('witness.fieldTooLong', { reason: 'dob-unsupported-v4-age' });
    }
    if (args.leafInputs.dobCommit.toLowerCase() !== args.ageInputs.dobCommit.toLowerCase()) {
      throw new QkbError('witness.fieldTooLong', { reason: 'dob-commit-mismatch-v4-age' });
    }
    if (args.ageInputs.ageQualified !== 1) {
      throw new QkbError('witness.fieldTooLong', { reason: 'age-not-qualified-v4-age' });
    }
  }
}

export function assertLeafInputsV4Shape(l: LeafInputsV4): void {
  if (l.pkX.length !== 4 || l.pkY.length !== 4) {
    throw new QkbError('witness.fieldTooLong', { reason: 'leaf-v4-pk-limbs' });
  }
  assertHex32(l.ctxHash, 'ctxHash');
  assertHex32(l.policyLeafHash, 'policyLeafHash');
  assertHex32(l.policyRoot, 'policyRoot');
  assertHex32(l.nullifier, 'nullifier');
  assertHex32(l.leafSpkiCommit, 'leafSpkiCommit');
}

export function assertLeafInputsV4AgeShape(l: LeafInputsV4AgeCapable): void {
  assertLeafInputsV4Shape(l);
  assertHex32(l.dobCommit, 'dobCommit');
  assertBinaryFlag(l.dobSupported, 'dobSupported');
}

export function assertAgeInputsV4Shape(a: AgeInputsV4): void {
  assertHex32(a.dobCommit, 'age.dobCommit');
  assertBinaryFlag(a.ageQualified, 'ageQualified');
}

export function leafPublicSignalsV4(input: LeafPublicSignalFieldsV4): LeafPublicSignalsV4 {
  if (input.pkX.length !== 4 || input.pkY.length !== 4) {
    throw new QkbError('witness.fieldTooLong', { reason: 'leaf-v4-pk-limbs' });
  }
  const signals: string[] = [
    ...input.pkX,
    ...input.pkY,
    input.ctxHash,
    input.policyLeafHash,
    input.policyRoot,
    input.timestamp,
    input.nullifier,
    input.leafSpkiCommit,
  ];
  if (signals.length !== 14) {
    throw new QkbError('witness.fieldTooLong', { reason: 'leaf-v4-signals-shape', got: signals.length });
  }
  return { signals, ...input };
}

export function leafPublicSignalsV4Age(
  input: LeafPublicSignalFieldsV4AgeCapable,
): LeafPublicSignalsV4AgeCapable {
  if (input.pkX.length !== 4 || input.pkY.length !== 4) {
    throw new QkbError('witness.fieldTooLong', { reason: 'leaf-v4-age-pk-limbs' });
  }
  const dobSupported = toBinaryFlagString(input.dobSupported, 'dobSupported');
  const signals: string[] = [
    ...input.pkX,
    ...input.pkY,
    input.ctxHash,
    input.policyLeafHash,
    input.policyRoot,
    input.timestamp,
    input.nullifier,
    input.leafSpkiCommit,
    input.dobCommit,
    dobSupported,
  ];
  if (signals.length !== 16) {
    throw new QkbError('witness.fieldTooLong', { reason: 'leaf-v4-age-signals-shape', got: signals.length });
  }
  return { signals, ...input, dobSupported };
}

export function agePublicSignalsV4(input: AgePublicSignalFieldsV4): AgePublicSignalsV4 {
  const ageQualified = toBinaryFlagString(input.ageQualified, 'ageQualified');
  const ageCutoffDate = toLimbString(input.ageCutoffDate);
  const signals: string[] = [input.dobCommit, ageCutoffDate, ageQualified];
  if (signals.length !== 3) {
    throw new QkbError('witness.fieldTooLong', { reason: 'age-v4-signals-shape', got: signals.length });
  }
  return {
    signals,
    dobCommit: input.dobCommit,
    ageCutoffDate,
    ageQualified,
  };
}

export function leafInputsV4FromPublicSignals(publicLeaf: readonly string[]): LeafInputsV4 {
  if (publicLeaf.length !== 14) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'leaf-v4-signals-shape',
      got: publicLeaf.length,
    });
  }
  return {
    pkX: [
      toLimbString(publicLeaf[0]!),
      toLimbString(publicLeaf[1]!),
      toLimbString(publicLeaf[2]!),
      toLimbString(publicLeaf[3]!),
    ] as const,
    pkY: [
      toLimbString(publicLeaf[4]!),
      toLimbString(publicLeaf[5]!),
      toLimbString(publicLeaf[6]!),
      toLimbString(publicLeaf[7]!),
    ] as const,
    ctxHash: toHex32(publicLeaf[8]!),
    policyLeafHash: toHex32(publicLeaf[9]!),
    policyRoot: toHex32(publicLeaf[10]!),
    timestamp: toLimbString(publicLeaf[11]!),
    nullifier: toHex32(publicLeaf[12]!),
    leafSpkiCommit: toHex32(publicLeaf[13]!),
  };
}

export function leafInputsV4AgeFromPublicSignals(publicLeaf: readonly string[]): LeafInputsV4AgeCapable {
  if (publicLeaf.length !== 16) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'leaf-v4-age-signals-shape',
      got: publicLeaf.length,
    });
  }
  return {
    pkX: [
      toLimbString(publicLeaf[0]!),
      toLimbString(publicLeaf[1]!),
      toLimbString(publicLeaf[2]!),
      toLimbString(publicLeaf[3]!),
    ] as const,
    pkY: [
      toLimbString(publicLeaf[4]!),
      toLimbString(publicLeaf[5]!),
      toLimbString(publicLeaf[6]!),
      toLimbString(publicLeaf[7]!),
    ] as const,
    ctxHash: toHex32(publicLeaf[8]!),
    policyLeafHash: toHex32(publicLeaf[9]!),
    policyRoot: toHex32(publicLeaf[10]!),
    timestamp: toLimbString(publicLeaf[11]!),
    nullifier: toHex32(publicLeaf[12]!),
    leafSpkiCommit: toHex32(publicLeaf[13]!),
    dobCommit: toHex32(publicLeaf[14]!),
    dobSupported: toBinaryFlag(publicLeaf[15]!, 'dobSupported'),
  };
}

export function ageInputsV4FromPublicSignals(publicAge: readonly string[]): AgeInputsV4 {
  if (publicAge.length !== 3) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'age-v4-signals-shape',
      got: publicAge.length,
    });
  }
  return {
    dobCommit: toHex32(publicAge[0]!),
    ageCutoffDate: toLimbString(publicAge[1]!),
    ageQualified: toBinaryFlag(publicAge[2]!, 'ageQualified'),
  };
}

export function buildRegisterArgsV4FromSignals(
  pk: `0x04${string}`,
  proofLeaf: Groth16Proof,
  publicLeaf: readonly string[],
  proofChain: Groth16Proof,
  publicChain: readonly string[],
): RegisterArgsV4 {
  return {
    pk,
    proofLeaf: packProof(proofLeaf),
    leafInputs: leafInputsV4FromPublicSignals(publicLeaf),
    proofChain: packProof(proofChain),
    chainInputs: chainInputsFromPublicSignals(publicChain),
  };
}

export function buildRegisterArgsV4AgeFromSignals(
  pk: `0x04${string}`,
  proofLeaf: Groth16Proof,
  publicLeaf: readonly string[],
  proofChain: Groth16Proof,
  publicChain: readonly string[],
  proofAge: Groth16Proof,
  publicAge: readonly string[],
  requireAgeQualification: boolean,
): RegisterArgsV4Age {
  return {
    pk,
    proofLeaf: packProof(proofLeaf),
    leafInputs: leafInputsV4AgeFromPublicSignals(publicLeaf),
    proofChain: packProof(proofChain),
    chainInputs: chainInputsFromPublicSignals(publicChain),
    proofAge: packProof(proofAge),
    ageInputs: ageInputsV4FromPublicSignals(publicAge),
    requireAgeQualification,
  };
}

function assertProofShape(p: SolidityProof, side: 'leaf' | 'chain' | 'age'): void {
  if (p.a.length !== 2 || p.c.length !== 2) {
    throw new QkbError('witness.fieldTooLong', { reason: 'proof-ac', side });
  }
  if (p.b.length !== 2 || p.b[0]!.length !== 2 || p.b[1]!.length !== 2) {
    throw new QkbError('witness.fieldTooLong', { reason: 'proof-b', side });
  }
}

function assertChainInputsShape(c: ChainInputs): void {
  assertHex32(c.rTL, 'rTL');
  assertHex32(c.leafSpkiCommit, 'chain.leafSpkiCommit');
  if (c.algorithmTag !== 0 && c.algorithmTag !== 1) {
    throw new QkbError('witness.fieldTooLong', { reason: 'algorithm-tag', got: c.algorithmTag });
  }
}

function chainInputsFromPublicSignals(publicChain: readonly string[]): ChainInputs {
  if (publicChain.length !== 3) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'chain-signals-shape',
      got: publicChain.length,
    });
  }
  const tag = publicChain[1] === '1' ? 1 : 0;
  return {
    rTL: toHex32(publicChain[0]!),
    algorithmTag: tag,
    leafSpkiCommit: toHex32(publicChain[2]!),
  };
}

function assertHex32(v: string, field: string): void {
  if (!/^0x[0-9a-fA-F]{64}$/.test(v)) {
    throw new QkbError('witness.fieldTooLong', { reason: 'hex32', field });
  }
}

function assertBinaryFlag(v: string | number, field: string): void {
  const n = typeof v === 'number' ? v : Number(v);
  if (n !== 0 && n !== 1) {
    throw new QkbError('witness.fieldTooLong', { reason: 'binary-flag', field, got: v });
  }
}

function toHex32(v: string | bigint | number): `0x${string}` {
  const big =
    typeof v === 'bigint'
      ? v
      : typeof v === 'number'
        ? BigInt(v)
        : v.startsWith('0x') || v.startsWith('0X')
          ? BigInt(v)
          : BigInt(v);
  const reduced = ((big % P) + P) % P;
  return `0x${reduced.toString(16).padStart(64, '0')}`;
}

function toLimbString(v: string | bigint | number): string {
  if (typeof v === 'bigint' || typeof v === 'number') return v.toString();
  return BigInt(v).toString();
}

function toBinaryFlag(v: string | number, field: string): 0 | 1 {
  const n = typeof v === 'number' ? v : Number(v);
  if (n === 0 || n === 1) return n;
  throw new QkbError('witness.fieldTooLong', { reason: 'binary-flag', field, got: v });
}

function toBinaryFlagString(v: string | number, field: string): string {
  return toBinaryFlag(v, field).toString();
}
