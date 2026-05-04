/**
 * Phase-2 split-proof witness builder. Produces the ({leaf, chain, shared})
 * tuple consumed by the Groth16 leaf + chain circuits — this is the universal
 * "parse a CAdES + binding into circuit-ready form" pipeline. The V4 layer
 * (`buildPhase2WitnessV4Draft` in @zkqes/sdk/witness) takes the output here as
 * a base witness and projects it into the QKB/2.0 16-signal layout.
 *
 * Lifted verbatim from packages/web/src/lib/witness.ts (V1/V3 split-proof
 * pivot, 2026-04-18). Pure module — no DOM, no Node crypto.
 */
import { sha256 } from '@noble/hashes/sha256';
import * as asn1js from 'asn1js';
import { buildPoseidon } from 'circomlibjs';
import { Certificate } from 'pkijs';
import type { Binding } from '../binding/v1.js';
import type { AlgorithmTag, ParsedCades } from '../cert/cades.js';
import { ZkqesError } from '../errors/index.js';
import {
  ALGORITHM_TAG_ECDSA_STR,
  ALGORITHM_TAG_RSA_STR,
  MAX_BCANON,
  MAX_CERT,
  MAX_DECL,
  MAX_SA,
  MERKLE_DEPTH,
  bytes32ToLimbs643,
  digestToField,
  extractSubjectSerial,
  findJcsKeyValueOffset,
  pkCoordToLimbs,
  sha256Pad,
  subjectSerialToLimbs,
  zeroPadTo,
  type ChainWitnessInput,
  type LeafWitnessInput,
  type Phase2SharedInputs,
  type Phase2Witness,
} from '../core/index.js';

// ===========================================================================
// Public Poseidon helpers — exported so callers can recompute leafSpkiCommit
// or nullifier off-circuit (matching the in-circuit derivation byte-for-byte).
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
 * in both leaf + chain circuits byte-for-byte.
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
 * §14.4 scoped credential nullifier — stable only within the identifier
 * namespace encoded in subject.serialNumber.
 */
export async function computeNullifier(
  subjectSerialLimbs: bigint[],
  subjectSerialLen: bigint,
  ctxHash: bigint,
): Promise<bigint> {
  if (subjectSerialLimbs.length !== 4) {
    throw new ZkqesError('witness.fieldTooLong', {
      reason: 'subject-serial-limbs',
      got: subjectSerialLimbs.length,
    });
  }
  if (subjectSerialLen < 1n || subjectSerialLen > 32n) {
    throw new ZkqesError('witness.fieldTooLong', {
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
// Builder inputs
// ===========================================================================

export interface BuildWitnessInput {
  parsed: ParsedCades;
  binding: Binding;
  bindingBytes: Uint8Array;
}

export interface BuildPhase2WitnessInput extends BuildWitnessInput {
  /** Poseidon-Merkle root of the trusted-list, as decimal, bigint, or 0x-hex. */
  trustedListRoot: string | bigint;
  /** Optional override for CLI/testing; defaults to `parsed.algorithmTag`. */
  algorithmTag?: AlgorithmTag;
  /** Intermediate DER override when `parsed.intermediateCertDer` is null. */
  intermediateCertDer?: Uint8Array;
  /**
   * Merkle inclusion path for the intermediate's canonicalization under rTL.
   * Must match `MERKLE_DEPTH`. When omitted the chain witness is filled with
   * all-zero path/indices — only useful for structural shape tests.
   */
  merklePath?: (string | bigint)[];
  merkleIndices?: number[];
}

/**
 * Build the leaf-circuit witness alone. Useful when only the leaf shape is
 * needed; trustedListRoot defaults to 0 and the intermediate cert is not
 * consulted.
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

// ===========================================================================
// Shared derivations
// ===========================================================================

interface SharedDerivations {
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
  saPadded: Uint8Array;
  mdOffsetInSA: number;
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
  subjectSerialContent: Uint8Array;
  subjectSerialContentOffset: number;
  subjectSerialLimbs: string[];
  nullifier: string;
  leafSpkiCommit: string;
}

async function buildSharedInputs(input: BuildWitnessInput): Promise<SharedDerivations> {
  const { parsed, binding, bindingBytes } = input;

  if (bindingBytes.length > MAX_BCANON) {
    throw new ZkqesError('witness.fieldTooLong', { field: 'Bcanon', got: bindingBytes.length, max: MAX_BCANON });
  }
  if (parsed.signedAttrsDer.length > MAX_SA) {
    throw new ZkqesError('witness.fieldTooLong', { field: 'signedAttrs', got: parsed.signedAttrsDer.length, max: MAX_SA });
  }
  if (parsed.leafCertDer.length > MAX_CERT) {
    throw new ZkqesError('witness.fieldTooLong', { field: 'leafDER', got: parsed.leafCertDer.length, max: MAX_CERT });
  }

  // Binding field offsets (JCS-canonical, keys alphabetical).
  const pkKeyOff = findJcsKeyValueOffset(bindingBytes, 'pk');
  const schemeKeyOff = findJcsKeyValueOffset(bindingBytes, 'scheme');
  const ctxKeyOff = findJcsKeyValueOffset(bindingBytes, 'context');
  const declKeyOff = findJcsKeyValueOffset(bindingBytes, 'declaration');
  const tsKeyOff = findJcsKeyValueOffset(bindingBytes, 'timestamp');

  // ctxHash: Phase-1 / Phase-2 admin binding currently uses context "0x"
  // (empty hex after prefix). Circuit treats "ctx empty ⇒ ctxHash=0".
  const ctxStart = ctxKeyOff + '"context":"0x'.length;
  let ctxEnd = ctxStart;
  while (ctxEnd < bindingBytes.length && bindingBytes[ctxEnd] !== 0x22) ctxEnd++;
  const ctxHexLen = ctxEnd - ctxStart;
  if (ctxHexLen !== 0) {
    throw new ZkqesError('witness.fieldTooLong', {
      field: 'ctx',
      reason: 'non-empty-ctx-unsupported-phase2-mvp',
      got: ctxHexLen,
    });
  }
  const ctxHash = '0';

  const pkHex = binding.pk.startsWith('0x') ? binding.pk.slice(2) : binding.pk;
  if (pkHex.length !== 130 || !pkHex.toLowerCase().startsWith('04')) {
    throw new ZkqesError('witness.fieldTooLong', {
      field: 'pk',
      reason: 'expected-uncompressed',
      got: pkHex.length,
    });
  }
  const xBytesPk = hexToBytes(pkHex.slice(2, 66));
  const yBytesPk = hexToBytes(pkHex.slice(66, 130));
  const pkX = pkCoordToLimbs(xBytesPk);
  const pkY = pkCoordToLimbs(yBytesPk);

  const declStart = declKeyOff + '"declaration":"'.length;
  const declBytes = sliceJsonString(bindingBytes, declStart);
  const declDigest = sha256(declBytes);
  const declHash = digestToField(declDigest);
  const declPadded = sha256Pad(declBytes);

  const tsStart = tsKeyOff + '"timestamp":'.length;
  let tsEnd = tsStart;
  while (tsEnd < bindingBytes.length) {
    const b = bindingBytes[tsEnd]!;
    if (b < 0x30 || b > 0x39) break;
    tsEnd++;
  }
  const tsDigitCount = tsEnd - tsStart;
  if (tsDigitCount === 0) {
    throw new ZkqesError('witness.offsetNotFound', { field: 'timestamp', reason: 'no-digits' });
  }
  const timestamp = BigInt(
    new TextDecoder().decode(bindingBytes.subarray(tsStart, tsEnd)),
  ).toString();

  const bcanonPadded = sha256Pad(bindingBytes);
  const saPadded = sha256Pad(parsed.signedAttrsDer);

  const leafDer = parsed.leafCertDer;
  const { tbsOffset, tbsLen } = findTbs(leafDer);
  const leafTbsBytes = leafDer.subarray(tbsOffset, tbsOffset + tbsLen);
  const leafTbsPadded = sha256Pad(leafTbsBytes);
  const { spkiXOffset, spkiYOffset } = findSpkiXYOffsets(leafDer);
  const leafXBytes = leafDer.subarray(spkiXOffset, spkiXOffset + 32);
  const leafYBytes = leafDer.subarray(spkiYOffset, spkiYOffset + 32);

  const { r: leafSigR32, s: leafSigS32 } = ecdsaSigDerToRS32(parsed.signatureValue);
  const leafSigR = bytes32ToLimbs643(leafSigR32);
  const leafSigS = bytes32ToLimbs643(leafSigS32);

  const mdOffsetInSA = findMessageDigestOffsetInSA(parsed.signedAttrsDer, parsed.messageDigest);

  const subj = extractSubjectSerial(leafDer);
  const subjectSerialLimbs = subjectSerialToLimbs(subj.content);

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

function buildLeafFromShared(
  s: SharedDerivations,
  input: BuildWitnessInput,
): LeafWitnessInput {
  const { parsed, bindingBytes } = input;
  const leafDer = parsed.leafCertDer;

  return {
    pkX: s.pkX,
    pkY: s.pkY,
    ctxHash: s.ctxHash,
    declHash: s.declHash,
    timestamp: s.timestamp,
    nullifier: s.nullifier,
    leafSpkiCommit: s.leafSpkiCommit,
    subjectSerialValueOffset: s.subjectSerialContentOffset,
    subjectSerialValueLength: s.subjectSerialContent.length,
    Bcanon: zeroPadTo(bindingBytes, MAX_BCANON),
    BcanonLen: bindingBytes.length,
    BcanonPaddedIn: zeroPadTo(s.bcanonPadded, MAX_BCANON),
    BcanonPaddedLen: s.bcanonPadded.length,
    pkValueOffset: s.pkKeyOff + 6,
    schemeValueOffset: s.schemeKeyOff + 10,
    ctxValueOffset: s.ctxKeyOff + 11,
    ctxHexLen: s.ctxHexLen,
    declValueOffset: s.declKeyOff + 15,
    declValueLen: s.declBytes.length,
    tsValueOffset: s.tsKeyOff + 12,
    tsDigitCount: s.tsDigitCount,
    declPaddedIn: zeroPadTo(s.declPadded, MAX_DECL + 64),
    declPaddedLen: s.declPadded.length,
    signedAttrs: zeroPadTo(parsed.signedAttrsDer, MAX_SA),
    signedAttrsLen: parsed.signedAttrsDer.length,
    signedAttrsPaddedIn: zeroPadTo(s.saPadded, MAX_SA),
    signedAttrsPaddedLen: s.saPadded.length,
    mdOffsetInSA: s.mdOffsetInSA,
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

  const intDer = input.intermediateCertDer ?? parsed.intermediateCertDer;
  if (!intDer) {
    throw new ZkqesError('witness.offsetNotFound', { field: 'intDER', reason: 'no-intermediate' });
  }
  if (intDer.length > MAX_CERT) {
    throw new ZkqesError('witness.fieldTooLong', { field: 'intDER', got: intDer.length, max: MAX_CERT });
  }

  const { spkiXOffset: intSpkiXOffset, spkiYOffset: intSpkiYOffset } = findSpkiXYOffsets(intDer);

  const outerSigDer = extractCertSignatureDer(leafDer);
  const { r: intR32, s: intS32 } = ecdsaSigDerToRS32(outerSigDer);
  const intSigR = bytes32ToLimbs643(intR32);
  const intSigS = bytes32ToLimbs643(intS32);

  const { path: merklePath, indices: merkleIndices } = normalizeMerkle(
    input.merklePath,
    input.merkleIndices,
  );

  return {
    rTL,
    algorithmTag,
    leafSpkiCommit: s.leafSpkiCommit,
    leafDER: zeroPadTo(leafDer, MAX_CERT),
    leafSpkiXOffset: s.leafSpkiXOffset,
    leafSpkiYOffset: s.leafSpkiYOffset,
    leafTbsPaddedIn: zeroPadTo(s.leafTbsPadded, MAX_CERT),
    leafTbsPaddedLen: s.leafTbsPadded.length,
    intDER: zeroPadTo(intDer, MAX_CERT),
    intDerLen: intDer.length,
    intSpkiXOffset,
    intSpkiYOffset,
    intSigR,
    intSigS,
    merklePath,
    merkleIndices,
  };
}

// ===========================================================================
// DER + JCS internal helpers
// ===========================================================================

function parseFieldString(v: string | bigint): bigint {
  if (typeof v === 'bigint') return v;
  const s = v.trim();
  if (s.startsWith('0x') || s.startsWith('0X')) return BigInt(s);
  if (!/^\d+$/.test(s)) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'bad-field-string', got: s });
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

function indexOfSubarray(hay: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function sliceJsonString(bytes: Uint8Array, start: number): Uint8Array {
  let i = start;
  const out: number[] = [];
  while (i < bytes.length) {
    const b = bytes[i]!;
    if (b === 0x5c /* \ */) {
      out.push(b);
      const next = bytes[i + 1];
      if (next === undefined) {
        throw new ZkqesError('witness.offsetNotFound', { field: 'declaration', reason: 'trailing-backslash' });
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
  throw new ZkqesError('witness.offsetNotFound', { field: 'declaration', reason: 'unterminated' });
}

function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'odd-hex', len: h.length });
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function findTbs(der: Uint8Array): { tbsOffset: number; tbsLen: number } {
  const buf = toAB(der);
  const asn = asn1js.fromBER(buf);
  if (asn.offset === -1) {
    throw new ZkqesError('witness.offsetNotFound', { field: 'leafTbs', reason: 'cert-asn1' });
  }
  let cert: Certificate;
  try {
    cert = new Certificate({ schema: asn.result });
  } catch (cause) {
    throw new ZkqesError('witness.offsetNotFound', { field: 'leafTbs', reason: 'cert-schema', cause: String(cause) });
  }
  const tbs = new Uint8Array(cert.encodeTBS().toBER(false));
  const off = indexOfSubarray(der, tbs);
  if (off === -1) {
    throw new ZkqesError('witness.offsetNotFound', { field: 'leafTbs', reason: 'not-found' });
  }
  return { tbsOffset: off, tbsLen: tbs.length };
}

function findSpkiXYOffsets(der: Uint8Array): { spkiXOffset: number; spkiYOffset: number } {
  const buf = toAB(der);
  const asn = asn1js.fromBER(buf);
  if (asn.offset === -1) {
    throw new ZkqesError('witness.offsetNotFound', { field: 'spki', reason: 'asn1' });
  }
  const cert = new Certificate({ schema: asn.result });
  const pubKey = new Uint8Array(
    cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
  );
  if (pubKey.length !== 65 || pubKey[0] !== 0x04) {
    throw new ZkqesError('witness.offsetNotFound', {
      field: 'spki',
      reason: 'not-uncompressed-p256',
      len: pubKey.length,
    });
  }
  const off = indexOfSubarray(der, pubKey);
  if (off === -1) {
    throw new ZkqesError('witness.offsetNotFound', { field: 'spki', reason: 'not-in-der' });
  }
  return { spkiXOffset: off + 1, spkiYOffset: off + 33 };
}

function ecdsaSigDerToRS32(der: Uint8Array): { r: Uint8Array; s: Uint8Array } {
  const asn = asn1js.fromBER(toAB(der));
  if (asn.offset === -1) {
    throw new ZkqesError('witness.offsetNotFound', { field: 'sig', reason: 'asn1' });
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
    throw new ZkqesError('witness.fieldTooLong', { reason: 'ecdsa-r-or-s', got: trimmed.length });
  }
  const out = new Uint8Array(32);
  out.set(trimmed, 32 - trimmed.length);
  return out;
}

function findMessageDigestOffsetInSA(saDer: Uint8Array, mdBytes: Uint8Array): number {
  if (mdBytes.length !== 32) {
    throw new ZkqesError('witness.fieldTooLong', { reason: 'md-length', got: mdBytes.length });
  }
  const marker = new Uint8Array(2 + 32);
  marker[0] = 0x04;
  marker[1] = 0x20;
  marker.set(mdBytes, 2);
  const off = indexOfSubarray(saDer, marker);
  if (off === -1) {
    throw new ZkqesError('witness.offsetNotFound', { field: 'messageDigest', reason: 'not-in-sa' });
  }
  return off + 2;
}

function extractCertSignatureDer(leafDer: Uint8Array): Uint8Array {
  const asn = asn1js.fromBER(toAB(leafDer));
  if (asn.offset === -1) {
    throw new ZkqesError('witness.offsetNotFound', { field: 'leafCertSig', reason: 'asn1' });
  }
  let cert: Certificate;
  try {
    cert = new Certificate({ schema: asn.result });
  } catch (cause) {
    throw new ZkqesError('witness.offsetNotFound', { field: 'leafCertSig', reason: 'schema', cause: String(cause) });
  }
  const raw = new Uint8Array(cert.signatureValue.valueBlock.valueHexView);
  if (raw.length < 8 || raw[0] !== 0x30) {
    throw new ZkqesError('witness.offsetNotFound', {
      field: 'leafCertSig',
      reason: 'not-ecdsa-seq',
      len: raw.length,
    });
  }
  return raw;
}

function toAB(b: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  return ab;
}
