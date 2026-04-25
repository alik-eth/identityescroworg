/**
 * Shared low-level primitives used by the QKB witness builders, registry
 * encoders, and proof-encoding helpers. Lifted from packages/web/src/lib/
 * (witness.ts + registry.ts + prover.ts) — kept SDK-internal because the
 * public API surface lives in `binding`, `witness`, `registry`, etc.
 *
 * Everything in this module is pure: no DOM, no Node `crypto`, no Worker.
 * Every helper round-trips against the corresponding Circom primitive
 * (Bytes32ToLimbs643, X509SubjectSerial, BindingParseV2Core, …).
 */
import * as asn1js from 'asn1js';
import { Certificate } from 'pkijs';
import { QkbError } from '../errors/index.js';

// ===========================================================================
// Compile-time caps from the QKBPresentationEcdsa{Leaf,Chain,Age} circuits.
// Must stay in sync with circuits/QKBPresentationEcdsa{Leaf,Chain}.circom.
// ===========================================================================

export const MAX_BCANON = 1024;
export const MAX_SA = 1536;
export const MAX_CERT = 1536;
export const MAX_CTX = 256;
export const MAX_DECL = 960;
export const MERKLE_DEPTH = 16;

export const ALGORITHM_TAG_RSA_STR = '0';
export const ALGORITHM_TAG_ECDSA_STR = '1';

// BN254 scalar field modulus.
const BN254_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ===========================================================================
// Cross-circuit witness types — leaf, chain, and shared bundles.
// ===========================================================================

/**
 * Leaf circuit witness — feeds QKBPresentationEcdsaLeaf.wasm.
 * 13-signal public layout (pkX[4], pkY[4], ctxHash, declHash, timestamp,
 * nullifier, leafSpkiCommit) plus the private witness inputs the circuit
 * uses to re-derive them under constraint. Phase-1 / V3 layout — V4
 * builders consume this as the base shape and project it into the V4
 * 16-signal layout.
 */
export interface LeafWitnessInput {
  // === Public signals (decimal-string bigints) ===
  pkX: string[];
  pkY: string[];
  ctxHash: string;
  declHash: string;
  timestamp: string;
  nullifier: string;
  leafSpkiCommit: string;

  // === Private — nullifier extraction (X509SubjectSerial) ===
  subjectSerialValueOffset: number;
  subjectSerialValueLength: number;

  // === Private — binding parse ===
  Bcanon: number[];
  BcanonLen: number;
  BcanonPaddedIn: number[];
  BcanonPaddedLen: number;
  pkValueOffset: number;
  schemeValueOffset: number;
  ctxValueOffset: number;
  ctxHexLen: number;
  declValueOffset: number;
  declValueLen: number;
  tsValueOffset: number;
  tsDigitCount: number;

  // === Private — declaration hash ===
  declPaddedIn: number[];
  declPaddedLen: number;

  // === Private — CMS signedAttrs + leaf ECDSA signature ===
  signedAttrs: number[];
  signedAttrsLen: number;
  signedAttrsPaddedIn: number[];
  signedAttrsPaddedLen: number;
  mdOffsetInSA: number;

  // === Private — leaf certificate ===
  leafDER: number[];
  leafSpkiXOffset: number;
  leafSpkiYOffset: number;
  leafSigR: string[];
  leafSigS: string[];
}

/**
 * Chain circuit witness — feeds QKBPresentationEcdsaChain.wasm.
 * 3-signal public layout (rTL, algorithmTag, leafSpkiCommit) plus the private
 * inputs proving `intDER` signs `leafTBS` and Merkle inclusion of the
 * intermediate canonicalization under rTL.
 */
export interface ChainWitnessInput {
  // === Public signals ===
  rTL: string;
  algorithmTag: string;
  leafSpkiCommit: string;

  // === Private — leaf cert (for leafSpkiCommit equality constraint) ===
  leafDER: number[];
  leafSpkiXOffset: number;
  leafSpkiYOffset: number;

  // === Private — leaf TBS for sha256(leafTBS) ===
  leafTbsPaddedIn: number[];
  leafTbsPaddedLen: number;

  // === Private — intermediate cert + signature over leaf TBS ===
  intDER: number[];
  intDerLen: number;
  intSpkiXOffset: number;
  intSpkiYOffset: number;
  intSigR: string[];
  intSigS: string[];

  // === Private — Merkle inclusion of intermediate under rTL ===
  merklePath: string[];
  merkleIndices: number[];
}

/**
 * Top-level Phase-2 witness bundle: V1 leaf + chain witness + the shared
 * public-signal values. V4 callers consume this as the base shape and
 * project it into the V4 16-signal layout via `buildPhase2WitnessV4Draft`.
 */
export interface Phase2Witness {
  leaf: LeafWitnessInput;
  chain: ChainWitnessInput;
  shared: Phase2SharedInputs;
}

export interface Phase2SharedInputs {
  pkX: string[];
  pkY: string[];
  ctxHash: string;
  declHash: string;
  timestamp: string;
  nullifier: string;
  leafSpkiCommit: string;
  rTL: string;
  algorithmTag: string;
}

// ===========================================================================
// Solidity proof + chain-input encoding (used by registryV4.encode*Calldata).
// ===========================================================================

/**
 * Snarkjs Groth16 proof shape — `pi_a` and `pi_c` are length-2 string
 * arrays, `pi_b` is a 2×2 string-array. Decimal-string limbs.
 */
export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol?: string;
  curve?: string;
}

export interface SolidityProof {
  /** `uint[2]` */
  a: readonly [string, string];
  /** `uint[2][2]` — already swapped for the verifier's BN254 pi_b convention. */
  b: readonly [readonly [string, string], readonly [string, string]];
  /** `uint[2]` */
  c: readonly [string, string];
}

export interface ChainInputs {
  readonly rTL: `0x${string}`;
  readonly algorithmTag: 0 | 1;
  readonly leafSpkiCommit: `0x${string}`;
}

/**
 * Pack a snarkjs Groth16 proof into the on-chain `(uint[2], uint[2][2],
 * uint[2])` shape. Snarkjs's `pi_b[i]` is `[real, imag]`; the BN254
 * verifier expects `[imag, real]` per gnark/snarkjs convention. We swap
 * here so the Solidity verifier doesn't double-flip.
 */
export function packProof(proof: Groth16Proof): SolidityProof {
  const a: [string, string] = [String(proof.pi_a[0]), String(proof.pi_a[1])];
  const c: [string, string] = [String(proof.pi_c[0]), String(proof.pi_c[1])];
  const b00 = String(proof.pi_b[0]![0]);
  const b01 = String(proof.pi_b[0]![1]);
  const b10 = String(proof.pi_b[1]![0]);
  const b11 = String(proof.pi_b[1]![1]);
  const b: readonly [readonly [string, string], readonly [string, string]] = [
    [b01, b00],
    [b11, b10],
  ] as const;
  return { a: [a[0], a[1]] as const, b, c: [c[0], c[1]] as const };
}

// ===========================================================================
// Low-level helpers — SHA padding, limb packing, DER scans
// ===========================================================================

/**
 * FIPS 180-4 SHA-256 padding. Appends 0x80, zero-pads, and writes an
 * 8-byte big-endian bit-length trailer. Output length is a multiple of 64.
 */
export function sha256Pad(data: Uint8Array): Uint8Array {
  const msgBits = BigInt(data.length) * 8n;
  const minLen = data.length + 1 + 8;
  const padLen = (64 - (minLen % 64)) % 64;
  const totalLen = minLen + padLen;
  const out = new Uint8Array(totalLen);
  out.set(data);
  out[data.length] = 0x80;
  for (let i = 0; i < 8; i++) {
    out[totalLen - 1 - i] = Number((msgBits >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}

export function zeroPadTo(data: Uint8Array, max: number): number[] {
  if (data.length > max) {
    throw new QkbError('witness.fieldTooLong', { got: data.length, max });
  }
  const out = new Array<number>(max).fill(0);
  for (let i = 0; i < data.length; i++) out[i] = data[i]!;
  return out;
}

/**
 * Pack a 32-byte big-endian coordinate into 4×64-bit LE limbs, matching
 * the circuit's Secp256k1PkMatch input layout.
 */
export function pkCoordToLimbs(bytes: Uint8Array): string[] {
  if (bytes.length !== 32) {
    throw new QkbError('witness.fieldTooLong', { reason: 'pk-coord', got: bytes.length });
  }
  const limbs: string[] = [];
  for (let l = 0; l < 4; l++) {
    let acc = 0n;
    const off = (3 - l) * 8;
    for (let j = 0; j < 8; j++) acc = (acc << 8n) | BigInt(bytes[off + j]!);
    limbs.push(acc.toString());
  }
  return limbs;
}

/**
 * Pack 32 big-endian bytes into 6×43-bit LE limbs, matching
 * Bytes32ToLimbs643 (used for ECDSA r/s + SPKI coords).
 */
export function bytes32ToLimbs643(bytes: Uint8Array): string[] {
  if (bytes.length !== 32) {
    throw new QkbError('witness.fieldTooLong', { reason: 'ecdsa-limb', got: bytes.length });
  }
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]!);
  const limbs: string[] = [];
  const MASK = (1n << 43n) - 1n;
  for (let i = 0; i < 6; i++) {
    limbs.push((v & MASK).toString());
    v >>= 43n;
  }
  return limbs;
}

/**
 * Pack 32 big-endian digest bytes into a single BN254 field element,
 * matching the circuit's Bits256ToField. Reduces mod p.
 */
export function digestToField(bytes: Uint8Array): string {
  if (bytes.length !== 32) {
    throw new QkbError('witness.fieldTooLong', { reason: 'digest', got: bytes.length });
  }
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]!);
  return (v % BN254_P).toString();
}

/**
 * Locate the byte offset of `"<key>":` inside a JCS-encoded payload.
 * Returns the offset of the opening quote. Throws witness.offsetNotFound
 * if the key is missing or appears more than once.
 */
export function findJcsKeyValueOffset(bytes: Uint8Array, key: string): number {
  const needle = new TextEncoder().encode(`"${key}":`);
  const first = indexOf(bytes, needle);
  if (first === -1) {
    throw new QkbError('witness.offsetNotFound', { key });
  }
  const second = indexOf(bytes, needle, first + 1);
  if (second !== -1) {
    throw new QkbError('witness.offsetNotFound', { key, reason: 'duplicate' });
  }
  return first;
}

// ===========================================================================
// X.509 subject.serialNumber (OID 2.5.4.5) extraction — used by the leaf
// witness's nullifier derivation and X509SubjectSerial.circom.
// ===========================================================================

const OID_SUBJECT_SERIAL = '2.5.4.5';

export interface ExtractedSubjectSerial {
  /** Raw PrintableString content bytes (no TLV header). */
  content: Uint8Array;
  /** Absolute byte offset of content[0] inside leafDer. */
  contentOffset: number;
}

/**
 * Extract the subject.serialNumber attribute from a leaf cert DER. Returns
 * the raw content bytes + the absolute byte offset into `leafDer` where
 * the content starts.
 */
export function extractSubjectSerial(leafDer: Uint8Array): ExtractedSubjectSerial {
  const asn = asn1js.fromBER(toAB(leafDer));
  if (asn.offset === -1) {
    throw new QkbError('witness.offsetNotFound', { field: 'subjectSerial', reason: 'asn1' });
  }
  let cert: Certificate;
  try {
    cert = new Certificate({ schema: asn.result });
  } catch (cause) {
    throw new QkbError('witness.offsetNotFound', {
      field: 'subjectSerial',
      reason: 'schema',
      cause: String(cause),
    });
  }

  const avas = (
    cert.subject as unknown as {
      typesAndValues: Array<{
        type: string;
        value: { valueBlock: { valueHexView: Uint8Array; value?: string } };
      }>;
    }
  ).typesAndValues;
  for (const ava of avas) {
    if (ava.type !== OID_SUBJECT_SERIAL) continue;
    const raw = ava.value.valueBlock.valueHexView;
    const content =
      raw && raw.length > 0
        ? new Uint8Array(raw)
        : new TextEncoder().encode(ava.value.valueBlock.value ?? '');
    if (content.length === 0) {
      throw new QkbError('witness.offsetNotFound', { field: 'subjectSerial', reason: 'empty' });
    }
    const offset = findUnique(leafDer, content);
    if (offset === -1) {
      throw new QkbError('witness.offsetNotFound', {
        field: 'subjectSerial',
        reason: 'ambiguous-offset',
      });
    }
    return { content, contentOffset: offset };
  }
  throw new QkbError('witness.offsetNotFound', {
    field: 'subjectSerial',
    reason: 'oid-not-present',
  });
}

/**
 * Pack the raw subject.serialNumber PrintableString bytes into 4×64-bit LE
 * limbs (X509SubjectSerial.circom convention). Right-pads with zeros to
 * 32 bytes; does NOT left-pad or reverse.
 */
export function subjectSerialToLimbs(serialBytes: Uint8Array): string[] {
  if (serialBytes.length < 1 || serialBytes.length > 32) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'subject-serial-length',
      got: serialBytes.length,
    });
  }
  const padded = new Uint8Array(32);
  padded.set(serialBytes, 0);
  const limbs: string[] = [];
  for (let l = 0; l < 4; l++) {
    let acc = 0n;
    for (let b = 7; b >= 0; b--) {
      acc = (acc << 8n) | BigInt(padded[l * 8 + b]!);
    }
    limbs.push(acc.toString());
  }
  return limbs;
}

// ===========================================================================
// Internal helpers
// ===========================================================================

function indexOf(hay: Uint8Array, needle: Uint8Array, from = 0): number {
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function findUnique(hay: Uint8Array, needle: Uint8Array): number {
  let found = -1;
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    if (found !== -1) return -1;
    found = i;
  }
  return found;
}

function toAB(b: Uint8Array): ArrayBuffer {
  if (b.byteOffset === 0 && b.byteLength === b.buffer.byteLength) {
    return b.buffer as ArrayBuffer;
  }
  return b.slice().buffer;
}
