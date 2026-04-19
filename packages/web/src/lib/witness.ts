/**
 * Circuit witness builder for `QKBPresentationEcdsa{Leaf,Chain}` — split-proof
 * pivot (2026-04-18).
 *
 * Two Groth16 circuits glue together on-chain via a shared `leafSpkiCommit`
 * public signal:
 *
 *   Leaf (13 public signals, orchestration §2.1)
 *     [0..3]  pkX limbs    [4..7]  pkY limbs
 *     [8]     ctxHash      [9]     declHash
 *     [10]    timestamp    [11]    nullifier
 *     [12]    leafSpkiCommit
 *
 *   Chain (3 public signals, orchestration §2.2)
 *     [0]     rTL          [1]     algorithmTag    [2]     leafSpkiCommit
 *
 * `leafSpkiCommit` is a `signal input` (not output) in BOTH circuits,
 * declared last in the public list so snarkjs emits it at index 12 / index 2
 * respectively. The circuit constrains it to
 *
 *     Poseidon2(Poseidon6(leafXLimbs), Poseidon6(leafYLimbs))
 *
 * so the prover cannot supply an arbitrary value. We compute it identically
 * off-circuit and hand the same value to both witnesses; the on-chain
 * `QKBVerifier.verify` asserts leaf[12] == chain[2] to bind the two proofs
 * into one R_QKB attestation (spec §5.4 split-proof fallback).
 *
 * Shared derivations (Bcanon offsets, RDN subject-serialNumber scan, leaf
 * SPKI offsets, leafSpkiCommit, intermediate-cert location) are computed
 * once in `buildSharedInputs` and threaded into both builders so nothing
 * drifts between the two circuit views of the same signature.
 *
 * All numbers larger than a JS safe-int are emitted as decimal strings, the
 * convention snarkjs expects for `calculateWitness`.
 */
import { sha256 } from '@noble/hashes/sha256';
import * as asn1js from 'asn1js';
import { buildPoseidon } from 'circomlibjs';
import { Certificate } from 'pkijs';
import type { Binding } from './binding';
import type { AlgorithmTag, ParsedCades } from './cades';
import { QkbError } from './errors';

// Compile-time caps from the circuits. Must stay in sync with
// QKBPresentationEcdsa{Leaf,Chain}.circom:
//   MAX_BCANON = 1024, MAX_SA = 1536, MAX_CERT = 1536,
//   MAX_CTX = 256, MAX_DECL = 960, MERKLE_DEPTH = 16.
export const MAX_BCANON = 1024;
export const MAX_SA = 1536;
export const MAX_CERT = 1536;
export const MAX_CTX = 256;
export const MAX_DECL = 960;
export const MERKLE_DEPTH = 16;

export const ALGORITHM_TAG_RSA_STR = '0';
export const ALGORITHM_TAG_ECDSA_STR = '1';

// ===========================================================================
// Witness input shapes — FROZEN by orchestration §2.1 / §2.2
// ===========================================================================

/**
 * Leaf circuit witness — feeds QKBPresentationEcdsaLeaf.wasm.
 * 13-signal public layout (pkX[4], pkY[4], ctxHash, declHash, timestamp,
 * nullifier, leafSpkiCommit) plus the private witness inputs the circuit
 * uses to re-derive them under constraint.
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
 * 3-signal public layout (rTL, algorithmTag, leafSpkiCommit) plus the
 * private witness inputs for sha256(leafTBS), intermediate ECDSA verify,
 * and Merkle inclusion of the intermediate canonicalization under rTL.
 */
export interface ChainWitnessInput {
  // === Public signals ===
  rTL: string;
  algorithmTag: string; // '0' = RSA, '1' = ECDSA
  leafSpkiCommit: string; // must equal leaf witness's leafSpkiCommit

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
 * Shared derivations surfaced to the caller for convenience — both `leaf`
 * and `chain` already carry these in their own signal inputs; re-exporting
 * them at the top level makes it easy for the submit code path to build
 * the V3 `LeafInputs` / `ChainInputs` Solidity structs without having to
 * peek inside the leaf or chain witness.
 */
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

/**
 * Top-level Phase-2 witness bundle consumed by the prover: a pair of
 * per-circuit witness objects and the shared public-signal values.
 * Spec §5.4 split-proof pivot (2026-04-18).
 */
export interface Phase2Witness {
  leaf: LeafWitnessInput;
  chain: ChainWitnessInput;
  shared: Phase2SharedInputs;
}

export interface BuildWitnessInput {
  parsed: ParsedCades;
  binding: Binding;
  bindingBytes: Uint8Array;
}

// ===========================================================================
// Low-level helpers — SHA padding, limb packing, DER scans
// ===========================================================================

// FIPS 180-4 SHA-256 padding. Appends 0x80, zero-pads, and writes an 8-byte
// big-endian bit-length trailer. Output length is a multiple of 64.
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

// Pack a 32-byte big-endian coordinate into 4 × 64-bit LE limbs, matching
// the circuit's Secp256k1PkMatch input layout.
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

// Pack 32 big-endian bytes into 6 × 43-bit LE limbs, matching
// Bytes32ToLimbs643 in both circuits (used for ECDSA r/s + SPKI coords).
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

// Pack 32 big-endian digest bytes into a single BN254 field element, matching
// the circuit's Bits256ToField. Reduces mod p automatically because BN254's
// prime is < 2^254, so any 256-bit input is interpreted mod p by the circuit.
export function digestToField(bytes: Uint8Array): string {
  if (bytes.length !== 32) {
    throw new QkbError('witness.fieldTooLong', { reason: 'digest', got: bytes.length });
  }
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]!);
  const p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  return (v % p).toString();
}

/**
 * Locate the byte offset of the key-literal `"<key>":` inside Bcanon. The
 * return value is the offset of the quote character opening the JCS
 * key literal. Throws witness.offsetNotFound if the key is missing or
 * appears more than once.
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

function indexOf(hay: Uint8Array, needle: Uint8Array, from = 0): number {
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function indexOfSubarray(hay: Uint8Array, needle: Uint8Array): number {
  return indexOf(hay, needle, 0);
}

function sliceJsonString(bytes: Uint8Array, start: number): Uint8Array {
  let i = start;
  const out: number[] = [];
  while (i < bytes.length) {
    const b = bytes[i]!;
    if (b === 0x5c /* \ */) {
      // JCS escapes: forward one byte raw (circuits side scans the raw
      // JCS-encoded declaration, not the decoded Unicode string).
      out.push(b);
      const next = bytes[i + 1];
      if (next === undefined) {
        throw new QkbError('witness.offsetNotFound', { field: 'declaration', reason: 'trailing-backslash' });
      }
      out.push(next);
      i += 2;
      continue;
    }
    if (b === 0x22 /* " */) {
      return new Uint8Array(out);
    }
    out.push(b);
    i++;
  }
  throw new QkbError('witness.offsetNotFound', { field: 'declaration', reason: 'unterminated' });
}

function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0) {
    throw new QkbError('witness.fieldTooLong', { reason: 'odd-hex', len: h.length });
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function findTbs(der: Uint8Array): { tbsOffset: number; tbsLen: number } {
  // An X.509 cert is SEQUENCE (outer). Its first child is the TBSCertificate
  // (also SEQUENCE). Decode via pkijs, re-encode the TBS, then unique-scan
  // the raw DER to locate its offset.
  const buf = toAB(der);
  const asn = asn1js.fromBER(buf);
  if (asn.offset === -1) {
    throw new QkbError('witness.offsetNotFound', { field: 'leafTbs', reason: 'cert-asn1' });
  }
  let cert: Certificate;
  try {
    cert = new Certificate({ schema: asn.result });
  } catch (cause) {
    throw new QkbError('witness.offsetNotFound', { field: 'leafTbs', reason: 'cert-schema', cause: String(cause) });
  }
  const tbs = new Uint8Array(cert.encodeTBS().toBER(false));
  const off = indexOfSubarray(der, tbs);
  if (off === -1) {
    throw new QkbError('witness.offsetNotFound', { field: 'leafTbs', reason: 'not-found' });
  }
  return { tbsOffset: off, tbsLen: tbs.length };
}

function findSpkiXYOffsets(der: Uint8Array): { spkiXOffset: number; spkiYOffset: number } {
  // For ECDSA P-256 certs the SPKI BIT STRING contains:
  //   0x00 (unused bits) || 0x04 (uncompressed) || X(32) || Y(32)
  // pkijs strips the unused-bits byte; we get 0x04 || X || Y.
  const buf = toAB(der);
  const asn = asn1js.fromBER(buf);
  if (asn.offset === -1) {
    throw new QkbError('witness.offsetNotFound', { field: 'spki', reason: 'asn1' });
  }
  const cert = new Certificate({ schema: asn.result });
  const pubKey = new Uint8Array(
    cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
  );
  if (pubKey.length !== 65 || pubKey[0] !== 0x04) {
    throw new QkbError('witness.offsetNotFound', {
      field: 'spki',
      reason: 'not-uncompressed-p256',
      len: pubKey.length,
    });
  }
  const off = indexOfSubarray(der, pubKey);
  if (off === -1) {
    throw new QkbError('witness.offsetNotFound', { field: 'spki', reason: 'not-in-der' });
  }
  return { spkiXOffset: off + 1, spkiYOffset: off + 33 };
}

function ecdsaSigDerToRS32(der: Uint8Array): { r: Uint8Array; s: Uint8Array } {
  const asn = asn1js.fromBER(toAB(der));
  if (asn.offset === -1) {
    throw new QkbError('witness.offsetNotFound', { field: 'sig', reason: 'asn1' });
  }
  const seq = asn.result as asn1js.Sequence;
  const [rNode, sNode] = seq.valueBlock.value as [asn1js.Integer, asn1js.Integer];
  return {
    r: normalizeInt32(new Uint8Array(rNode.valueBlock.valueHexView)),
    s: normalizeInt32(new Uint8Array(sNode.valueBlock.valueHexView)),
  };
}

function normalizeInt32(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  const trimmed = b.subarray(i);
  if (trimmed.length > 32) {
    throw new QkbError('witness.fieldTooLong', { reason: 'ecdsa-r-or-s', got: trimmed.length });
  }
  const out = new Uint8Array(32);
  out.set(trimmed, 32 - trimmed.length);
  return out;
}

function findMessageDigestOffsetInSA(saDer: Uint8Array, mdBytes: Uint8Array): number {
  // mdBytes is exactly 32 bytes (sha-256). The messageDigest attribute value
  // appears as OCTET STRING (0x04 0x20 <32 bytes>) inside the signedAttrs
  // SET. Return the offset of the 32-byte payload within signedAttrsDer.
  if (mdBytes.length !== 32) {
    throw new QkbError('witness.fieldTooLong', { reason: 'md-length', got: mdBytes.length });
  }
  const marker = new Uint8Array(2 + 32);
  marker[0] = 0x04;
  marker[1] = 0x20;
  marker.set(mdBytes, 2);
  const off = indexOfSubarray(saDer, marker);
  if (off === -1) {
    throw new QkbError('witness.offsetNotFound', { field: 'messageDigest', reason: 'not-in-sa' });
  }
  return off + 2;
}

function toAB(b: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  return ab;
}

// ===========================================================================
// Poseidon reference — used to compute leafSpkiCommit + nullifier off-circuit
// so the witness matches what the circuit derives in-constraint.
// ===========================================================================

type PoseidonFn = ((inputs: unknown[]) => unknown) & {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
};

let poseidonP: Promise<PoseidonFn> | null = null;
function getPoseidon(): Promise<PoseidonFn> {
  if (poseidonP === null) poseidonP = buildPoseidon() as unknown as Promise<PoseidonFn>;
  return poseidonP;
}

async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const p = await getPoseidon();
  return p.F.toObject(p(inputs.map((v) => p.F.e(v))) as unknown);
}

/**
 * Compute leafSpkiCommit = Poseidon2(Poseidon6(xLimbs), Poseidon6(yLimbs))
 * over the 6×43-bit ECDSA-P256 SPKI coordinate limbs. Matches the template
 * in both QKBPresentationEcdsaLeaf.circom and QKBPresentationEcdsaChain.circom
 * byte-for-byte — the same formula is constrained inside each circuit and
 * on-chain equality of the two public signals glues the proofs together.
 */
export async function computeLeafSpkiCommit(
  leafXBytes: Uint8Array,
  leafYBytes: Uint8Array,
): Promise<bigint> {
  const xLimbs = bytes32ToLimbs643(leafXBytes).map((s) => BigInt(s));
  const yLimbs = bytes32ToLimbs643(leafYBytes).map((s) => BigInt(s));
  const pX = await poseidonHash(xLimbs);
  const pY = await poseidonHash(yLimbs);
  return poseidonHash([pX, pY]);
}

/**
 * Compute nullifier = Poseidon(Poseidon(subjectSerialLimbs[4], serialLen), ctxHash).
 * §14.4 person-level nullifier (2026-04-18 amendment). All inputs/outputs
 * are BN254 field elements.
 */
export async function computeNullifier(
  subjectSerialLimbs: bigint[],
  subjectSerialLen: bigint,
  ctxHash: bigint,
): Promise<bigint> {
  if (subjectSerialLimbs.length !== 4) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'subject-serial-limbs',
      got: subjectSerialLimbs.length,
    });
  }
  if (subjectSerialLen < 1n || subjectSerialLen > 32n) {
    throw new QkbError('witness.fieldTooLong', {
      reason: 'subject-serial-length',
      got: Number(subjectSerialLen),
    });
  }
  const secret = await poseidonHash([
    subjectSerialLimbs[0]!,
    subjectSerialLimbs[1]!,
    subjectSerialLimbs[2]!,
    subjectSerialLimbs[3]!,
    subjectSerialLen,
  ]);
  return poseidonHash([secret, ctxHash]);
}

// ===========================================================================
// Subject serialNumber extraction (OID 2.5.4.5, PrintableString)
// ===========================================================================

const OID_SUBJECT_SERIAL = '2.5.4.5';

export interface ExtractedSubjectSerial {
  /** Raw PrintableString content bytes (no TLV header). */
  content: Uint8Array;
  /** Absolute byte offset of content[0] inside leafDer. */
  contentOffset: number;
}

/**
 * Extract the subject.serialNumber attribute (OID 2.5.4.5, PrintableString)
 * from a leaf cert DER. Returns the raw content bytes + the absolute byte
 * offset into `leafDer` where the content starts — which is what
 * X509SubjectSerial.circom consumes as `subjectSerialValueOffset`.
 *
 * This is DISTINCT from the cert's own serialNumber INTEGER field (that
 * identifies the cert, not the person). OID 2.5.4.5 lives inside the subject
 * RDN sequence; we locate it by re-walking the DER manually because pkijs
 * does not surface absolute offsets.
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

  // pkijs' RelativeDistinguishedNames uses `typesAndValues: AttributeTypeAndValue[]`
  // which flattens the RDN sequence into AVA entries. For our purposes a flat
  // walk suffices — we're looking for a specific OID, not preserving RDN shape.
  const avas = (cert.subject as unknown as {
    typesAndValues: Array<{
      type: string;
      value: { valueBlock: { valueHexView: Uint8Array; value?: string } };
    }>;
  }).typesAndValues;
  for (const ava of avas) {
    if (ava.type !== OID_SUBJECT_SERIAL) continue;
    const raw = ava.value.valueBlock.valueHexView;
    const content =
      raw && raw.length > 0
        ? new Uint8Array(raw)
        : new TextEncoder().encode(ava.value.valueBlock.value ?? '');
    if (content.length === 0) {
      throw new QkbError('witness.offsetNotFound', {
        field: 'subjectSerial',
        reason: 'empty',
      });
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

/**
 * Pack the raw PrintableString content bytes of the subject.serialNumber
 * attribute into 4 × 64-bit LE limbs — matches X509SubjectSerial.circom:
 * content byte 0 becomes the LSB of limb[0], byte 8 the LSB of limb[1],
 * etc. Right-pads with zeros to 32 bytes. Does NOT left-pad or reverse.
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
    // LSB-first within each 8-byte group. bytes[l*8 + 0] is limb[l]'s LSB.
    for (let b = 7; b >= 0; b--) {
      acc = (acc << 8n) | BigInt(padded[l * 8 + b]!);
    }
    limbs.push(acc.toString());
  }
  return limbs;
}

// ===========================================================================
// Shared derivations — computed once, threaded into both circuit builders
// ===========================================================================

interface SharedDerivations {
  // Binding / pk / ctx / ts / decl
  pkX: string[];
  pkY: string[];
  ctxHash: string;
  ctxHexLen: number;
  declHash: string;
  declBytes: Uint8Array;
  declPadded: Uint8Array;
  timestamp: string;
  tsDigitCount: number;
  pkKeyOff: number;
  schemeKeyOff: number;
  ctxKeyOff: number;
  declKeyOff: number;
  tsKeyOff: number;
  bcanonPadded: Uint8Array;

  // CMS signedAttrs + messageDigest offset
  saPadded: Uint8Array;
  mdOffsetInSA: number;

  // Leaf cert offsets + signature limbs
  leafTbsOffset: number;
  leafTbsLen: number;
  leafTbsBytes: Uint8Array;
  leafTbsPadded: Uint8Array;
  leafSpkiXOffset: number;
  leafSpkiYOffset: number;
  leafSigR: string[];
  leafSigS: string[];
  leafXBytes: Uint8Array;
  leafYBytes: Uint8Array;

  // Nullifier derivation
  subjectSerialContent: Uint8Array;
  subjectSerialContentOffset: number;
  subjectSerialLimbs: string[];
  nullifier: string;
  leafSpkiCommit: string;
}

async function buildSharedInputs(input: BuildWitnessInput): Promise<SharedDerivations> {
  const { parsed, binding, bindingBytes } = input;

  if (bindingBytes.length > MAX_BCANON) {
    throw new QkbError('witness.fieldTooLong', { field: 'Bcanon', got: bindingBytes.length, max: MAX_BCANON });
  }
  if (parsed.signedAttrsDer.length > MAX_SA) {
    throw new QkbError('witness.fieldTooLong', { field: 'signedAttrs', got: parsed.signedAttrsDer.length, max: MAX_SA });
  }
  if (parsed.leafCertDer.length > MAX_CERT) {
    throw new QkbError('witness.fieldTooLong', { field: 'leafDER', got: parsed.leafCertDer.length, max: MAX_CERT });
  }

  // --- Binding field offsets (JCS-canonical, keys alphabetical, stable) ---
  const pkKeyOff = findJcsKeyValueOffset(bindingBytes, 'pk');
  const schemeKeyOff = findJcsKeyValueOffset(bindingBytes, 'scheme');
  const ctxKeyOff = findJcsKeyValueOffset(bindingBytes, 'context');
  const declKeyOff = findJcsKeyValueOffset(bindingBytes, 'declaration');
  const tsKeyOff = findJcsKeyValueOffset(bindingBytes, 'timestamp');

  // --- ctxHash: Phase-1 / Phase-2 admin binding currently uses context "0x"
  //     (empty hex after prefix). The circuit treats "ctx empty ⇒ ctxHash=0".
  //     Non-empty contexts require the Poseidon path, which lands with escrow
  //     commitments in Phase 2 proper (not in this pivot). ---
  const ctxStart = ctxKeyOff + '"context":"0x'.length;
  let ctxEnd = ctxStart;
  while (ctxEnd < bindingBytes.length && bindingBytes[ctxEnd] !== 0x22 /* " */) ctxEnd++;
  const ctxHexLen = ctxEnd - ctxStart;
  if (ctxHexLen !== 0) {
    throw new QkbError('witness.fieldTooLong', {
      field: 'ctx',
      reason: 'non-empty-ctx-unsupported-phase2-mvp',
      got: ctxHexLen,
    });
  }
  const ctxHash = '0';

  // --- pk X/Y limbs from the uncompressed ASCII pk hex ---
  const pkHex = binding.pk.startsWith('0x') ? binding.pk.slice(2) : binding.pk;
  if (pkHex.length !== 130 || !pkHex.toLowerCase().startsWith('04')) {
    throw new QkbError('witness.fieldTooLong', {
      field: 'pk',
      reason: 'expected-uncompressed',
      got: pkHex.length,
    });
  }
  const xBytesPk = hexToBytes(pkHex.slice(2, 66));
  const yBytesPk = hexToBytes(pkHex.slice(66, 130));
  const pkX = pkCoordToLimbs(xBytesPk);
  const pkY = pkCoordToLimbs(yBytesPk);

  // --- Declaration: slice from Bcanon, hash, pack into a field ---
  const declStart = declKeyOff + '"declaration":"'.length;
  const declBytes = sliceJsonString(bindingBytes, declStart);
  const declDigest = sha256(declBytes);
  const declHash = digestToField(declDigest);
  const declPadded = sha256Pad(declBytes);

  // --- Timestamp integer + digit count ---
  const tsStart = tsKeyOff + '"timestamp":'.length;
  let tsEnd = tsStart;
  while (tsEnd < bindingBytes.length) {
    const b = bindingBytes[tsEnd]!;
    if (b < 0x30 || b > 0x39) break;
    tsEnd++;
  }
  const tsDigitCount = tsEnd - tsStart;
  if (tsDigitCount === 0) {
    throw new QkbError('witness.offsetNotFound', { field: 'timestamp', reason: 'no-digits' });
  }
  const timestamp = BigInt(
    new TextDecoder().decode(bindingBytes.subarray(tsStart, tsEnd)),
  ).toString();

  // --- SHA padding for each Sha256Var instance in the circuits ---
  const bcanonPadded = sha256Pad(bindingBytes);
  const saPadded = sha256Pad(parsed.signedAttrsDer);

  // --- Leaf cert TBS offset + SPKI x/y offsets ---
  const leafDer = parsed.leafCertDer;
  const { tbsOffset, tbsLen } = findTbs(leafDer);
  const leafTbsBytes = leafDer.subarray(tbsOffset, tbsOffset + tbsLen);
  const leafTbsPadded = sha256Pad(leafTbsBytes);
  const { spkiXOffset, spkiYOffset } = findSpkiXYOffsets(leafDer);
  const leafXBytes = leafDer.subarray(spkiXOffset, spkiXOffset + 32);
  const leafYBytes = leafDer.subarray(spkiYOffset, spkiYOffset + 32);

  // --- Leaf signature R/S from the CAdES signer signatureValue (over
  //     signedAttrsDer). ECDSA signature = SEQ { INTEGER r, INTEGER s }. ---
  const { r: leafSigR32, s: leafSigS32 } = ecdsaSigDerToRS32(parsed.signatureValue);
  const leafSigR = bytes32ToLimbs643(leafSigR32);
  const leafSigS = bytes32ToLimbs643(leafSigS32);

  // --- messageDigest attribute offset inside signedAttrsDer ---
  const mdOffsetInSA = findMessageDigestOffsetInSA(parsed.signedAttrsDer, parsed.messageDigest);

  // --- Subject serialNumber → limbs + absolute content offset ---
  const subj = extractSubjectSerial(leafDer);
  const subjectSerialLimbs = subjectSerialToLimbs(subj.content);

  // --- Nullifier (person-level) + leafSpkiCommit (Poseidon2(P6(X), P6(Y))) ---
  const ctxHashBig = BigInt(ctxHash);
  const nullifierBig = await computeNullifier(
    subjectSerialLimbs.map((s) => BigInt(s)),
    BigInt(subj.content.length),
    ctxHashBig,
  );
  const leafSpkiCommitBig = await computeLeafSpkiCommit(
    new Uint8Array(leafXBytes),
    new Uint8Array(leafYBytes),
  );

  return {
    pkX,
    pkY,
    ctxHash,
    ctxHexLen,
    declHash,
    declBytes,
    declPadded,
    timestamp,
    tsDigitCount,
    pkKeyOff,
    schemeKeyOff,
    ctxKeyOff,
    declKeyOff,
    tsKeyOff,
    bcanonPadded,
    saPadded,
    mdOffsetInSA,
    leafTbsOffset: tbsOffset,
    leafTbsLen: tbsLen,
    leafTbsBytes: new Uint8Array(leafTbsBytes),
    leafTbsPadded,
    leafSpkiXOffset: spkiXOffset,
    leafSpkiYOffset: spkiYOffset,
    leafSigR,
    leafSigS,
    leafXBytes: new Uint8Array(leafXBytes),
    leafYBytes: new Uint8Array(leafYBytes),
    subjectSerialContent: subj.content,
    subjectSerialContentOffset: subj.contentOffset,
    subjectSerialLimbs,
    nullifier: nullifierBig.toString(),
    leafSpkiCommit: leafSpkiCommitBig.toString(),
  };
}

// ===========================================================================
// Phase-2 split-proof witness builder (async — Poseidon is async)
// ===========================================================================

/**
 * Extra knobs needed by the chain witness that don't live inside the CAdES:
 *   - `trustedListRoot` (rTL public signal — normally matches the root
 *     in `trusted-cas/root.json`).
 *   - Merkle inclusion inputs for the intermediate CA under rTL. Caller
 *     produces these via `buildInclusionPath` against `layers.json`; we
 *     accept them as already-formed arrays so this module stays free of
 *     the fetch / layers-file parsing concerns.
 *   - `intermediateCertDer` override for leaf-only CAdES where the CMS
 *     didn't ship the intermediate (Diia) — caller resolves it from LOTL
 *     and supplies it here. Defaults to `parsed.intermediateCertDer`.
 */
export interface BuildPhase2WitnessInput extends BuildWitnessInput {
  /** Poseidon-Merkle root of the trusted-list, as decimal string, bigint, or 0x-hex. */
  trustedListRoot: string | bigint;
  /** Optional override for CLI/testing; defaults to `parsed.algorithmTag`. */
  algorithmTag?: AlgorithmTag;
  /** Intermediate DER override when `parsed.intermediateCertDer` is null. */
  intermediateCertDer?: Uint8Array;
  /**
   * Merkle inclusion path for the intermediate's canonicalization under rTL.
   * Must match `MERKLE_DEPTH`. When omitted the chain witness is filled with
   * all-zero path + indices — only useful for structural/shape tests; the
   * chain Groth16 proof will fail to generate against zeros unless rTL is
   * also zero.
   */
  merklePath?: (string | bigint)[];
  merkleIndices?: number[];
}

function parseFieldString(v: string | bigint): bigint {
  if (typeof v === 'bigint') return v;
  const s = v.trim();
  if (s.startsWith('0x') || s.startsWith('0X')) return BigInt(s);
  if (!/^\d+$/.test(s)) {
    throw new QkbError('witness.fieldTooLong', { reason: 'bad-field-string', got: s });
  }
  return BigInt(s);
}

function normalizeMerkle(
  path: (string | bigint)[] | undefined,
  indices: number[] | undefined,
): { path: string[]; indices: number[] } {
  const outPath: string[] = new Array(MERKLE_DEPTH);
  const outIdx: number[] = new Array(MERKLE_DEPTH);
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    outPath[i] = path && i < path.length ? parseFieldString(path[i]!).toString() : '0';
    outIdx[i] = indices && i < indices.length ? (indices[i] === 1 ? 1 : 0) : 0;
  }
  return { path: outPath, indices: outIdx };
}

/**
 * Build the leaf-circuit witness alone (convenience wrapper around
 * buildPhase2Witness). Useful for routes / tests that only need the leaf
 * shape — e.g. the unit suite that doesn't synthesize an intermediate cert
 * or a trusted-list. `trustedListRoot` defaults to 0 and the intermediate
 * cert is only consulted by the chain builder which this helper discards.
 */
export async function buildLeafWitness(input: BuildWitnessInput): Promise<LeafWitnessInput> {
  const s = await buildSharedInputs(input);
  return buildLeafFromShared(s, input);
}

/**
 * Build the full Phase-2 split-proof witness bundle. Shared derivations
 * (Bcanon offsets, RDN subject-serialNumber scan, leaf SPKI offsets,
 * leafSpkiCommit, nullifier) are computed once and threaded into both
 * circuit-level witnesses.
 */
export async function buildPhase2Witness(
  input: BuildPhase2WitnessInput,
): Promise<Phase2Witness> {
  const s = await buildSharedInputs(input);

  const algorithmTag =
    (input.algorithmTag ?? input.parsed.algorithmTag) === 1
      ? ALGORITHM_TAG_ECDSA_STR
      : ALGORITHM_TAG_RSA_STR;

  const rTL = parseFieldString(input.trustedListRoot).toString();

  const leaf = buildLeafFromShared(s, input);
  const chain = await buildChainFromShared(s, input, rTL, algorithmTag);

  const shared: Phase2SharedInputs = {
    pkX: s.pkX,
    pkY: s.pkY,
    ctxHash: s.ctxHash,
    declHash: s.declHash,
    timestamp: s.timestamp,
    nullifier: s.nullifier,
    leafSpkiCommit: s.leafSpkiCommit,
    rTL,
    algorithmTag,
  };

  return { leaf, chain, shared };
}

function buildLeafFromShared(
  s: SharedDerivations,
  input: BuildWitnessInput,
): LeafWitnessInput {
  const { parsed, bindingBytes } = input;
  const leafDer = parsed.leafCertDer;

  return {
    // Public (13 signals — order matches orchestration §2.1)
    pkX: s.pkX,
    pkY: s.pkY,
    ctxHash: s.ctxHash,
    declHash: s.declHash,
    timestamp: s.timestamp,
    nullifier: s.nullifier,
    leafSpkiCommit: s.leafSpkiCommit,

    // Nullifier extraction
    subjectSerialValueOffset: s.subjectSerialContentOffset,
    subjectSerialValueLength: s.subjectSerialContent.length,

    // Binding
    Bcanon: zeroPadTo(bindingBytes, MAX_BCANON),
    BcanonLen: bindingBytes.length,
    BcanonPaddedIn: zeroPadTo(s.bcanonPadded, MAX_BCANON),
    BcanonPaddedLen: s.bcanonPadded.length,
    // findJcsKeyValueOffset returns the position of the OPENING QUOTE of the
    // key literal (e.g. the `"` in `"pk":"`). The circuit's BindingKeyAt
    // expects `offset` to point to the first byte of the VALUE, so that
    // bytes[offset - KEY_LEN .. offset - 1] equals the key literal. Add
    // each key literal's length (including the `:` and — for string values
    // — the opening `"`) to convert.
    //   "pk":"          →  6 bytes
    //   "scheme":"      → 10
    //   "context":"     → 11
    //   "declaration":" → 15
    //   "timestamp":    → 12 (no opening `"` on the numeric value)
    pkValueOffset: s.pkKeyOff + 6,
    schemeValueOffset: s.schemeKeyOff + 10,
    ctxValueOffset: s.ctxKeyOff + 11,
    ctxHexLen: s.ctxHexLen,
    declValueOffset: s.declKeyOff + 15,
    declValueLen: s.declBytes.length,
    tsValueOffset: s.tsKeyOff + 12,
    tsDigitCount: s.tsDigitCount,

    // Declaration
    declPaddedIn: zeroPadTo(s.declPadded, MAX_DECL + 64),
    declPaddedLen: s.declPadded.length,

    // CMS signedAttrs
    signedAttrs: zeroPadTo(parsed.signedAttrsDer, MAX_SA),
    signedAttrsLen: parsed.signedAttrsDer.length,
    signedAttrsPaddedIn: zeroPadTo(s.saPadded, MAX_SA),
    signedAttrsPaddedLen: s.saPadded.length,
    mdOffsetInSA: s.mdOffsetInSA,

    // Leaf cert + signature
    leafDER: zeroPadTo(leafDer, MAX_CERT),
    leafSpkiXOffset: s.leafSpkiXOffset,
    leafSpkiYOffset: s.leafSpkiYOffset,
    leafSigR: s.leafSigR,
    leafSigS: s.leafSigS,
  };
}

async function buildChainFromShared(
  s: SharedDerivations,
  input: BuildPhase2WitnessInput,
  rTL: string,
  algorithmTag: string,
): Promise<ChainWitnessInput> {
  const { parsed } = input;
  const leafDer = parsed.leafCertDer;

  // Intermediate DER: caller override wins (for LOTL-resolved cases where
  // the CMS shipped leaf-only). Falls back to the CMS-bundled intermediate.
  const intDer = input.intermediateCertDer ?? parsed.intermediateCertDer;
  if (!intDer) {
    throw new QkbError('witness.offsetNotFound', {
      field: 'intDER',
      reason: 'no-intermediate',
    });
  }
  if (intDer.length > MAX_CERT) {
    throw new QkbError('witness.fieldTooLong', { field: 'intDER', got: intDer.length, max: MAX_CERT });
  }

  const { spkiXOffset: intSpkiXOffset, spkiYOffset: intSpkiYOffset } = findSpkiXYOffsets(intDer);

  // Intermediate's signature over the leaf TBS lives inside the leaf cert
  // itself as Certificate.signatureValue (the outer `signed` block is
  // { TBSCertificate, signatureAlgorithm, signatureValue }). For ECDSA-P256
  // the signature is SEQ { INTEGER r, INTEGER s } — the same shape as the
  // CMS signer's signature, decoded the same way.
  const outerSigDer = extractCertSignatureDer(leafDer);
  const { r: intR32, s: intS32 } = ecdsaSigDerToRS32(outerSigDer);
  const intSigR = bytes32ToLimbs643(intR32);
  const intSigS = bytes32ToLimbs643(intS32);

  const { path: merklePath, indices: merkleIndices } = normalizeMerkle(
    input.merklePath,
    input.merkleIndices,
  );

  void rTL; // used below for the public signal emission
  void algorithmTag;

  return {
    // Public
    rTL,
    algorithmTag,
    leafSpkiCommit: s.leafSpkiCommit,

    // Leaf cert (for leafSpkiCommit equality constraint)
    leafDER: zeroPadTo(leafDer, MAX_CERT),
    leafSpkiXOffset: s.leafSpkiXOffset,
    leafSpkiYOffset: s.leafSpkiYOffset,

    // Leaf TBS padded
    leafTbsPaddedIn: zeroPadTo(s.leafTbsPadded, MAX_CERT),
    leafTbsPaddedLen: s.leafTbsPadded.length,

    // Intermediate cert + signature over leaf TBS
    intDER: zeroPadTo(intDer, MAX_CERT),
    intDerLen: intDer.length,
    intSpkiXOffset,
    intSpkiYOffset,
    intSigR,
    intSigS,

    // Merkle
    merklePath,
    merkleIndices,
  };
}

/**
 * Extract the outer Certificate.signatureValue (the intermediate's ECDSA
 * signature over the leaf TBS). pkijs re-parses into
 *   Certificate := SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
 * and surfaces the signature as a BIT STRING whose content is the ECDSA
 * SEQ(r, s) DER encoding.
 */
function extractCertSignatureDer(leafDer: Uint8Array): Uint8Array {
  const asn = asn1js.fromBER(toAB(leafDer));
  if (asn.offset === -1) {
    throw new QkbError('witness.offsetNotFound', {
      field: 'leafCertSig',
      reason: 'asn1',
    });
  }
  let cert: Certificate;
  try {
    cert = new Certificate({ schema: asn.result });
  } catch (cause) {
    throw new QkbError('witness.offsetNotFound', {
      field: 'leafCertSig',
      reason: 'schema',
      cause: String(cause),
    });
  }
  const raw = new Uint8Array(cert.signatureValue.valueBlock.valueHexView);
  if (raw.length < 8 || raw[0] !== 0x30) {
    throw new QkbError('witness.offsetNotFound', {
      field: 'leafCertSig',
      reason: 'not-ecdsa-seq',
      len: raw.length,
    });
  }
  return raw;
}

// ===========================================================================
// Public-signal packing helpers — for the on-chain V3 register() call
// ===========================================================================

export interface LeafPublicSignals {
  /** 13-element decimal-string array matching the frozen orchestration §2.1 layout. */
  signals: string[];
  pkX: string[];
  pkY: string[];
  ctxHash: string;
  declHash: string;
  timestamp: string;
  nullifier: string;
  leafSpkiCommit: string;
}

export interface ChainPublicSignals {
  /** 3-element decimal-string array matching the frozen orchestration §2.2 layout. */
  signals: string[];
  rTL: string;
  algorithmTag: string;
  leafSpkiCommit: string;
}

/**
 * Assemble the 13-element leaf public-signal array from a leaf witness.
 * Order is FROZEN by orchestration §2.1: pkX[0..3], pkY[0..3], ctxHash,
 * declHash, timestamp, nullifier, leafSpkiCommit.
 */
export function leafPublicSignals(w: LeafWitnessInput): LeafPublicSignals {
  const signals: string[] = [
    ...w.pkX,
    ...w.pkY,
    w.ctxHash,
    w.declHash,
    w.timestamp,
    w.nullifier,
    w.leafSpkiCommit,
  ];
  if (signals.length !== 13) {
    throw new QkbError('witness.fieldTooLong', { reason: 'leaf-signals-shape', got: signals.length });
  }
  return {
    signals,
    pkX: w.pkX,
    pkY: w.pkY,
    ctxHash: w.ctxHash,
    declHash: w.declHash,
    timestamp: w.timestamp,
    nullifier: w.nullifier,
    leafSpkiCommit: w.leafSpkiCommit,
  };
}

/**
 * Assemble the 3-element chain public-signal array from a chain witness.
 * Order is FROZEN by orchestration §2.2: rTL, algorithmTag, leafSpkiCommit.
 */
export function chainPublicSignals(w: ChainWitnessInput): ChainPublicSignals {
  const signals: string[] = [w.rTL, w.algorithmTag, w.leafSpkiCommit];
  if (signals.length !== 3) {
    throw new QkbError('witness.fieldTooLong', { reason: 'chain-signals-shape', got: signals.length });
  }
  return {
    signals,
    rTL: w.rTL,
    algorithmTag: w.algorithmTag,
    leafSpkiCommit: w.leafSpkiCommit,
  };
}
