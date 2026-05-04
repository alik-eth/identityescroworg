// Read-side viem helpers (added M4 T14). The write-side calldata encoder
// + revert classifier below stay as-is.
export { isVerified, nullifierOf, trustedListRoot } from './reads.js';

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
import { encodeFunctionData } from 'viem';
import { keccak_256 } from '@noble/hashes/sha3';
import { ZkqesError } from '../errors/index.js';
import {
  packProof,
  type ChainInputs,
  type Groth16Proof,
  type SolidityProof,
} from '../core/index.js';
import type { LeafPublicSignals } from '../witness/index.js';
import { assertGregorianDate } from '../dob/index.js';

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
    throw new ZkqesError('binding.pkMismatch', { reason: 'register-args-v4-pk-shape' });
  }
  assertProofShape(args.proofLeaf, 'leaf');
  assertProofShape(args.proofChain, 'chain');
  assertLeafInputsV4Shape(args.leafInputs);
  assertChainInputsShape(args.chainInputs);
  if (args.leafInputs.leafSpkiCommit.toLowerCase() !== args.chainInputs.leafSpkiCommit.toLowerCase()) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'leaf-spki-commit-mismatch-v4' });
  }
}

export function assertRegisterArgsV4AgeShape(args: RegisterArgsV4Age): void {
  if (!args.pk.startsWith('0x04') || args.pk.length !== 132) {
    throw new ZkqesError('binding.pkMismatch', { reason: 'register-args-v4-age-pk-shape' });
  }
  assertProofShape(args.proofLeaf, 'leaf');
  assertProofShape(args.proofChain, 'chain');
  assertProofShape(args.proofAge, 'age');
  assertLeafInputsV4AgeShape(args.leafInputs);
  assertChainInputsShape(args.chainInputs);
  assertAgeInputsV4Shape(args.ageInputs);
  if (args.leafInputs.leafSpkiCommit.toLowerCase() !== args.chainInputs.leafSpkiCommit.toLowerCase()) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'leaf-spki-commit-mismatch-v4-age' });
  }
  if (args.requireAgeQualification) {
    if (args.leafInputs.dobSupported !== 1) {
      throw new ZkqesError('witness.fieldTooLong', { reason: 'dob-unsupported-v4-age' });
    }
    if (args.leafInputs.dobCommit.toLowerCase() !== args.ageInputs.dobCommit.toLowerCase()) {
      throw new ZkqesError('witness.fieldTooLong', { reason: 'dob-commit-mismatch-v4-age' });
    }
    if (args.ageInputs.ageQualified !== 1) {
      throw new ZkqesError('witness.fieldTooLong', { reason: 'age-not-qualified-v4-age' });
    }
  }
}

export function assertLeafInputsV4Shape(l: LeafInputsV4): void {
  if (l.pkX.length !== 4 || l.pkY.length !== 4) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'leaf-v4-pk-limbs' });
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
  assertAgeCutoffDate(a.ageCutoffDate);
}

/** ageCutoffDate is a public age-circuit signal carrying a YYYYMMDD integer
 *  (e.g. 20080423 for "person is born on or before 2008-04-23"). The
 *  circuit treats it as an opaque field element, but the TS boundary —
 *  which freezes what the contract consumes — must reject negatives,
 *  impossible calendar dates, and non-numeric strings. Otherwise a
 *  malformed bundle can pass the boundary with dobCommit/ageQualified that
 *  the contract then trusts. */
function assertAgeCutoffDate(raw: string | number | bigint): void {
  let n: bigint;
  if (typeof raw === 'bigint') n = raw;
  else if (typeof raw === 'number') {
    if (!Number.isInteger(raw)) {
      throw new ZkqesError('binding.field', { field: 'ageCutoffDate', reason: 'not-integer', raw });
    }
    n = BigInt(raw);
  } else {
    if (!/^\d{8}$/.test(raw)) {
      throw new ZkqesError('binding.field', { field: 'ageCutoffDate', reason: 'format', raw });
    }
    n = BigInt(raw);
  }
  if (n < 19000101n || n > 29991231n) {
    throw new ZkqesError('binding.field', { field: 'ageCutoffDate', reason: 'range', raw: String(raw) });
  }
  const ymd = Number(n);
  const year = Math.floor(ymd / 10000);
  const month = Math.floor((ymd % 10000) / 100);
  const day = ymd % 100;
  assertGregorianDate(year, month, day, String(raw), 'ageCutoffDate');
}

export function leafPublicSignalsV4(input: LeafPublicSignalFieldsV4): LeafPublicSignalsV4 {
  if (input.pkX.length !== 4 || input.pkY.length !== 4) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'leaf-v4-pk-limbs' });
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
    throw new ZkqesError('witness.fieldTooLong', { reason: 'leaf-v4-signals-shape', got: signals.length });
  }
  return { signals, ...input };
}

export function leafPublicSignalsV4Age(
  input: LeafPublicSignalFieldsV4AgeCapable,
): LeafPublicSignalsV4AgeCapable {
  if (input.pkX.length !== 4 || input.pkY.length !== 4) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'leaf-v4-age-pk-limbs' });
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
    throw new ZkqesError('witness.fieldTooLong', { reason: 'leaf-v4-age-signals-shape', got: signals.length });
  }
  return { signals, ...input, dobSupported };
}

export function agePublicSignalsV4(input: AgePublicSignalFieldsV4): AgePublicSignalsV4 {
  const ageQualified = toBinaryFlagString(input.ageQualified, 'ageQualified');
  const ageCutoffDate = toLimbString(input.ageCutoffDate);
  const signals: string[] = [input.dobCommit, ageCutoffDate, ageQualified];
  if (signals.length !== 3) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'age-v4-signals-shape', got: signals.length });
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
    throw new ZkqesError('witness.fieldTooLong', {
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
    throw new ZkqesError('witness.fieldTooLong', {
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
    throw new ZkqesError('witness.fieldTooLong', {
      reason: 'age-v4-signals-shape',
      got: publicAge.length,
    });
  }
  // Validate the cutoff date at the public-signal boundary so downstream
  // callers can't bypass it by going through toLimbString (which would
  // raise a generic SyntaxError instead of a typed ZkqesError on garbage).
  assertAgeCutoffDate(publicAge[1]!);
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
    throw new ZkqesError('witness.fieldTooLong', { reason: 'proof-ac', side });
  }
  if (p.b.length !== 2 || p.b[0]!.length !== 2 || p.b[1]!.length !== 2) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'proof-b', side });
  }
}

function assertChainInputsShape(c: ChainInputs): void {
  assertHex32(c.rTL, 'rTL');
  assertHex32(c.leafSpkiCommit, 'chain.leafSpkiCommit');
  if (c.algorithmTag !== 0 && c.algorithmTag !== 1) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'algorithm-tag', got: c.algorithmTag });
  }
}

function chainInputsFromPublicSignals(publicChain: readonly string[]): ChainInputs {
  if (publicChain.length !== 3) {
    throw new ZkqesError('witness.fieldTooLong', {
      reason: 'chain-signals-shape',
      got: publicChain.length,
    });
  }
  // Reject unknown algorithm tags at this boundary rather than silently
  // coercing to RSA (tag 0). The chain circuit only emits '0' or '1' today,
  // and any other value is either a malformed bundle or a future tag the
  // contract hasn't been taught to dispatch.
  const tagStr = publicChain[1];
  if (tagStr !== '0' && tagStr !== '1') {
    throw new ZkqesError('witness.fieldTooLong', {
      reason: 'algorithm-tag-unknown',
      got: tagStr,
    });
  }
  return {
    rTL: toHex32(publicChain[0]!),
    algorithmTag: tagStr === '1' ? 1 : 0,
    leafSpkiCommit: toHex32(publicChain[2]!),
  };
}

function assertHex32(v: string, field: string): void {
  if (!/^0x[0-9a-fA-F]{64}$/.test(v)) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'hex32', field });
  }
}

function assertBinaryFlag(v: string | number, field: string): void {
  const n = typeof v === 'number' ? v : Number(v);
  if (n !== 0 && n !== 1) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'binary-flag', field, got: v });
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
  throw new ZkqesError('witness.fieldTooLong', { reason: 'binary-flag', field, got: v });
}

function toBinaryFlagString(v: string | number, field: string): string {
  return toBinaryFlag(v, field).toString();
}

// ---------------------------------------------------------------------------
// QKBRegistryV4 on-chain submit surface
//
// register(ChainProof, LeafProof) — selector + tuple encoding per Solidity
// ABIv2 rules. The ABI fragment below mirrors packages/contracts/src/
// QKBRegistryV4.sol — keep in sync whenever the contract's struct layout
// changes (an ABI pump is the cleaner long-term fix).
// ---------------------------------------------------------------------------

const V4_REGISTRY_ABI = [
  {
    type: 'function',
    name: 'register',
    stateMutability: 'nonpayable',
    inputs: [
      {
        name: 'cp',
        type: 'tuple',
        components: [
          {
            name: 'proof',
            type: 'tuple',
            components: [
              { name: 'a', type: 'uint256[2]' },
              { name: 'b', type: 'uint256[2][2]' },
              { name: 'c', type: 'uint256[2]' },
            ],
          },
          { name: 'rTL', type: 'uint256' },
          { name: 'algorithmTag', type: 'uint256' },
          { name: 'leafSpkiCommit', type: 'uint256' },
        ],
      },
      {
        name: 'lp',
        type: 'tuple',
        components: [
          {
            name: 'proof',
            type: 'tuple',
            components: [
              { name: 'a', type: 'uint256[2]' },
              { name: 'b', type: 'uint256[2][2]' },
              { name: 'c', type: 'uint256[2]' },
            ],
          },
          { name: 'pkX', type: 'uint256[4]' },
          { name: 'pkY', type: 'uint256[4]' },
          { name: 'ctxHash', type: 'uint256' },
          { name: 'policyLeafHash', type: 'uint256' },
          { name: 'policyRoot_', type: 'uint256' },
          { name: 'timestamp', type: 'uint256' },
          { name: 'nullifier', type: 'uint256' },
          { name: 'leafSpkiCommit', type: 'uint256' },
          { name: 'dobCommit', type: 'uint256' },
          { name: 'dobSupported', type: 'uint256' },
        ],
      },
    ],
    outputs: [{ name: 'bindingId', type: 'bytes32' }],
  },
] as const;

export interface LeafDobInputs {
  readonly dobCommit: `0x${string}`;
  readonly dobSupported: 0 | 1;
}

/**
 * ABI-encode the V4 `register(ChainProof, LeafProof)` calldata. The optional
 * `dob` parameter fills the `dobCommit` / `dobSupported` signals at the tail
 * of the LeafProof tuple. When omitted they default to 0 / 0 — consistent
 * with a jurisdiction whose DOB extractor is wired to `DobExtractorNull`.
 *
 * The 4-byte selector is
 *   keccak256("register((...<chain>...),(...<leaf>...))")[0..4]
 * everything after is ABI-encoded per Solidity's tuple-in-calldata rules.
 * Static tuples only → no dynamic offsets.
 */
export function encodeV4RegisterCalldata(
  args: RegisterArgsV4,
  dob?: LeafDobInputs,
): `0x${string}` {
  const dobCommit = dob?.dobCommit ?? `0x${'0'.repeat(64)}`;
  const dobSupported = dob?.dobSupported ?? 0;
  return encodeFunctionData({
    abi: V4_REGISTRY_ABI,
    functionName: 'register',
    args: [
      {
        proof: {
          a: [BigInt(args.proofChain.a[0]), BigInt(args.proofChain.a[1])],
          b: [
            [BigInt(args.proofChain.b[0][0]), BigInt(args.proofChain.b[0][1])],
            [BigInt(args.proofChain.b[1][0]), BigInt(args.proofChain.b[1][1])],
          ],
          c: [BigInt(args.proofChain.c[0]), BigInt(args.proofChain.c[1])],
        },
        rTL: BigInt(args.chainInputs.rTL),
        algorithmTag: BigInt(args.chainInputs.algorithmTag),
        leafSpkiCommit: BigInt(args.chainInputs.leafSpkiCommit),
      },
      {
        proof: {
          a: [BigInt(args.proofLeaf.a[0]), BigInt(args.proofLeaf.a[1])],
          b: [
            [BigInt(args.proofLeaf.b[0][0]), BigInt(args.proofLeaf.b[0][1])],
            [BigInt(args.proofLeaf.b[1][0]), BigInt(args.proofLeaf.b[1][1])],
          ],
          c: [BigInt(args.proofLeaf.c[0]), BigInt(args.proofLeaf.c[1])],
        },
        pkX: [
          BigInt(args.leafInputs.pkX[0]),
          BigInt(args.leafInputs.pkX[1]),
          BigInt(args.leafInputs.pkX[2]),
          BigInt(args.leafInputs.pkX[3]),
        ],
        pkY: [
          BigInt(args.leafInputs.pkY[0]),
          BigInt(args.leafInputs.pkY[1]),
          BigInt(args.leafInputs.pkY[2]),
          BigInt(args.leafInputs.pkY[3]),
        ],
        ctxHash: BigInt(args.leafInputs.ctxHash),
        policyLeafHash: BigInt(args.leafInputs.policyLeafHash),
        policyRoot_: BigInt(args.leafInputs.policyRoot),
        timestamp: BigInt(args.leafInputs.timestamp as string | bigint | number),
        nullifier: BigInt(args.leafInputs.nullifier),
        leafSpkiCommit: BigInt(args.leafInputs.leafSpkiCommit),
        dobCommit: BigInt(dobCommit),
        dobSupported: BigInt(dobSupported),
      },
    ],
  });
}

// ---------------------------------------------------------------------------
// Custom error taxonomy (QKBRegistryV4.sol)
// ---------------------------------------------------------------------------

function sel(signature: string): `0x${string}` {
  const h = keccak_256(new TextEncoder().encode(signature));
  let hex = '';
  for (let i = 0; i < 4; i++) hex += (h[i] as number).toString(16).padStart(2, '0');
  return `0x${hex}`;
}

export const REGISTRY_V4_ERROR_SELECTORS: Readonly<Record<string, `0x${string}`>> = {
  // register()
  NotOnTrustedList: sel('NotOnTrustedList()'),
  InvalidLeafSpkiCommit: sel('InvalidLeafSpkiCommit()'),
  InvalidPolicyRoot: sel('InvalidPolicyRoot()'),
  AlgorithmNotSupported: sel('AlgorithmNotSupported()'),
  DuplicateNullifier: sel('DuplicateNullifier()'),
  InvalidProof: sel('InvalidProof()'),
  // proveAdulthood()
  AgeProofMismatch: sel('AgeProofMismatch()'),
  AgeNotQualified: sel('AgeNotQualified()'),
  DobNotAvailable: sel('DobNotAvailable()'),
  NotMonotonic: sel('NotMonotonic()'),
  BindingNotFound: sel('BindingNotFound()'),
  // admin / selfRevoke()
  SelfRevokeSigInvalid: sel('SelfRevokeSigInvalid()'),
  BindingRevoked: sel('BindingRevoked()'),
  OnlyAdmin: sel('OnlyAdmin()'),
} as const;

/**
 * Map a V4 custom-error `data` (4-byte selector + optional args) to a typed
 * ZkqesError. Unknown selectors return null so callers can fall back to the
 * raw wallet message.
 */
export function classifyV4RegistryRevert(data: string | undefined): ZkqesError | null {
  if (!data || typeof data !== 'string') return null;
  const lower = data.toLowerCase();
  if (!lower.startsWith('0x')) return null;
  const s = lower.slice(0, 10);

  if (s === REGISTRY_V4_ERROR_SELECTORS.DuplicateNullifier) {
    return new ZkqesError('registry.nullifierUsed');
  }
  if (s === REGISTRY_V4_ERROR_SELECTORS.NotOnTrustedList) {
    return new ZkqesError('registry.rootMismatch', { reason: 'trusted-list-root-stale' });
  }
  if (s === REGISTRY_V4_ERROR_SELECTORS.InvalidPolicyRoot) {
    return new ZkqesError('registry.rootMismatch', { reason: 'policy-root-mismatch' });
  }
  if (s === REGISTRY_V4_ERROR_SELECTORS.InvalidLeafSpkiCommit) {
    return new ZkqesError('witness.fieldTooLong', { reason: 'leaf-spki-commit-mismatch-on-chain' });
  }
  if (s === REGISTRY_V4_ERROR_SELECTORS.AlgorithmNotSupported) {
    return new ZkqesError('qes.wrongAlgorithm');
  }
  if (s === REGISTRY_V4_ERROR_SELECTORS.InvalidProof) {
    return new ZkqesError('qes.sigInvalid', { reason: 'groth16-invalid-on-chain' });
  }
  if (s === REGISTRY_V4_ERROR_SELECTORS.AgeProofMismatch) {
    return new ZkqesError('registry.ageExceeded', { reason: 'age-proof-mismatch' });
  }
  if (s === REGISTRY_V4_ERROR_SELECTORS.AgeNotQualified) {
    return new ZkqesError('registry.ageExceeded', { reason: 'age-not-qualified' });
  }
  if (s === REGISTRY_V4_ERROR_SELECTORS.DobNotAvailable) {
    return new ZkqesError('registry.ageExceeded', { reason: 'dob-not-available' });
  }
  return null;
}

/**
 * Heuristic wallet-revert classifier — accepts viem + EIP-1474 shapes plus
 * bare error messages containing the error name. Mirrors registry.ts's
 * `classifyWalletRevert` for V3.
 */
export function classifyV4WalletRevert(err: unknown): ZkqesError | null {
  if (err instanceof Error && err.message) {
    const m = err.message;
    if (/DuplicateNullifier/.test(m)) return new ZkqesError('registry.nullifierUsed');
    if (/NotOnTrustedList/.test(m)) {
      return new ZkqesError('registry.rootMismatch', { reason: 'trusted-list-root-stale' });
    }
    if (/InvalidPolicyRoot/.test(m)) {
      return new ZkqesError('registry.rootMismatch', { reason: 'policy-root-mismatch' });
    }
    if (/InvalidLeafSpkiCommit/.test(m)) {
      return new ZkqesError('witness.fieldTooLong', { reason: 'leaf-spki-commit-mismatch-on-chain' });
    }
    if (/AlgorithmNotSupported/.test(m)) return new ZkqesError('qes.wrongAlgorithm');
    if (/InvalidProof/.test(m)) {
      return new ZkqesError('qes.sigInvalid', { reason: 'groth16-invalid-on-chain' });
    }
    if (/AgeProofMismatch|AgeNotQualified|DobNotAvailable/.test(m)) {
      return new ZkqesError('registry.ageExceeded', { reason: 'age-path' });
    }
  }
  const data = extractV4RevertData(err);
  if (data) return classifyV4RegistryRevert(data);
  return null;
}

function extractV4RevertData(err: unknown): string | undefined {
  if (!err || typeof err !== 'object') return undefined;
  const obj = err as Record<string, unknown>;
  if (typeof obj.data === 'string') return obj.data;
  // viem nests revert data under { cause: { data: { originalError: { data: "0x..." } } } }
  // — when `data` is itself an object rather than a string, keep descending.
  for (const c of [obj.cause, obj.error, obj.originalError, obj.data]) {
    if (c && typeof c === 'object') {
      const nested = extractV4RevertData(c);
      if (nested) return nested;
    }
  }
  return undefined;
}
