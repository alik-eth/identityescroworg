// Witness builders for the Phase-2 split-proof ECDSA circuits
// (QKBPresentationEcdsaLeaf + QKBPresentationEcdsaChain). Loads a fixture
// emitted by scripts/build-admin-ecdsa-fixture.ts and produces two witness
// records, one per circuit, with every shared derivation (Bcanon offsets,
// subject-serial RDN parse, leaf-SPKI offsets, leafSpkiCommit, intermediate
// cert location) computed once in buildSharedInputs and threaded into both
// builders.
//
// Why split: the unified QKBPresentationEcdsa.circom couldn't be Groth16-
// setup by snarkjs at 10.85 M constraints (§14 spec pivot). The leaf proof
// carries R_QKB constraints 1, 2, 5, 6 + the person-nullifier; the chain
// proof carries constraints 3, 4. On-chain the two are glued by asserting
// their leafSpkiCommit outputs are equal (QKBVerifier §2.5).

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';

// circomlibjs has no types.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { buildPoseidon } = require('circomlibjs');

// -------------------------------------------------------------------------
// Compile-time caps — MUST match the on-circuit var declarations.
// -------------------------------------------------------------------------
export const MAX_BCANON = 1024;
export const MAX_SA = 1536;
export const MAX_CERT = 1536;
export const MAX_CTX = 256;
export const MAX_DECL = 960;
export const MERKLE_DEPTH = 16;

// -------------------------------------------------------------------------
// Fixture schema (admin-ecdsa/fixture.json, v1).
// -------------------------------------------------------------------------
export interface AdminEcdsaFixture {
  leaf: {
    derLength: number;
    tbs: { offset: number; length: number };
    spki: { xOffset: number; yOffset: number };
  };
  binding: {
    bytesLength: number;
    offsets: { context: number; declaration: number; pk: number; scheme: number; timestamp: number };
    declarationBytesLength: number;
  };
  cms: {
    signedAttrsHex: string;
    signedAttrsLength: number;
    messageDigestOffsetInSignedAttrs: number;
    leafSigR: string;
    leafSigS: string;
  };
  synthIntermediate: {
    derLength: number;
    derPath: string;
    spkiXOffset: number;
    spkiYOffset: number;
    sigROverRealLeafTbsHex: string;
    sigSOverRealLeafTbsHex: string;
  };
  merkle: {
    depth: number;
    root: string;
    path: string[];
    indices: number[];
  };
}

// -------------------------------------------------------------------------
// Witness-input shapes — one per circuit. FROZEN by orchestration §2.1/§2.2.
// -------------------------------------------------------------------------

// Leaf circuit: 13 public signals (pkX[4], pkY[4], ctxHash, declHash,
// timestamp, nullifier, leafSpkiCommit) + private nullifier/binding/SA/leaf
// inputs.
export interface LeafWitnessInput {
  // Public
  pkX: string[];
  pkY: string[];
  ctxHash: string;
  declHash: string;
  timestamp: string;
  nullifier: string;

  // Private — nullifier extraction
  subjectSerialValueOffset: number;
  subjectSerialValueLength: number;

  // Private — binding
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

  // Private — declaration
  declPaddedIn: number[];
  declPaddedLen: number;

  // Private — CMS signedAttrs
  signedAttrs: number[];
  signedAttrsLen: number;
  signedAttrsPaddedIn: number[];
  signedAttrsPaddedLen: number;
  mdOffsetInSA: number;

  // Private — leaf cert + signature
  leafDER: number[];
  leafSpkiXOffset: number;
  leafSpkiYOffset: number;
  leafSigR: string[];
  leafSigS: string[];
}

// Chain circuit: 5 public signals (rTL, algorithmTag, leafSpkiCommit) +
// private leafDER/leafTBS/intermediate/Merkle inputs.
export interface ChainWitnessInput {
  // Public
  rTL: string;
  algorithmTag: string;

  // Private — leaf cert (for leafSpkiCommit equality output)
  leafDER: number[];
  leafSpkiXOffset: number;
  leafSpkiYOffset: number;

  // Private — leaf TBS for sha256(leafTBS)
  leafTbsPaddedIn: number[];
  leafTbsPaddedLen: number;

  // Private — intermediate cert + signature over leaf TBS
  intDER: number[];
  intDerLen: number;
  intSpkiXOffset: number;
  intSpkiYOffset: number;
  intSigR: string[];
  intSigS: string[];

  // Private — Merkle inclusion under rTL
  merklePath: string[];
  merkleIndices: number[];
}

// -------------------------------------------------------------------------
// Shared helpers — byte/limb packing + SHA padding.
// -------------------------------------------------------------------------

// FIPS 180-4 SHA-256 padding: 0x80 byte, zero pad, 8-byte BE bit-length
// trailer. Result length is a multiple of 64.
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

// Zero-extend a Uint8Array to exactly `max` bytes.
export function zeroPadTo(data: Uint8Array, max: number): number[] {
  if (data.length > max) throw new Error(`${data.length} > max ${max}`);
  const out = new Array<number>(max).fill(0);
  for (let i = 0; i < data.length; i++) out[i] = data[i]!;
  return out;
}

// Pack 32 big-endian bytes into 6 × 43-bit LE limbs. Matches
// `Bytes32ToLimbs643` in QKBPresentationEcdsa{Leaf,Chain}.circom verbatim.
export function bytes32ToLimbs643(bytes: Uint8Array): bigint[] {
  if (bytes.length !== 32) throw new Error('expected 32 bytes');
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]!);
  const limbs: bigint[] = [];
  const MASK = (1n << 43n) - 1n;
  for (let i = 0; i < 6; i++) {
    limbs.push(v & MASK);
    v >>= 43n;
  }
  return limbs;
}

// Pack a pk X or Y coordinate (32 BE bytes) into 4 × 64-bit LE limbs
// matching the Secp256k1PkMatch layout.
export function pkCoordToLimbs(bytes: Uint8Array): bigint[] {
  if (bytes.length !== 32) throw new Error('expected 32 bytes');
  const limbs: bigint[] = [];
  for (let l = 0; l < 4; l++) {
    let acc = 0n;
    const off = (3 - l) * 8;
    for (let j = 0; j < 8; j++) acc = (acc << 8n) | BigInt(bytes[off + j]!);
    limbs.push(acc);
  }
  return limbs;
}

// Pack a 32-byte SHA-256 digest (big-endian) into a single BN254 field
// element, matching Bits256ToField in the leaf circuit.
export function digestToField(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) throw new Error('expected 32 bytes');
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
}

// Pack up to 32 bytes into 4 × uint64 LE limbs, zero-padded. Matches the
// limb packing inside X509SubjectSerial.circom: byte[l*8+b] is at bit
// positions [b*8..b*8+7] of limb[l].
export function subjectSerialBytesToLimbs(bytes: Uint8Array): bigint[] {
  if (bytes.length > 32) throw new Error('subject serial > 32 bytes');
  const limbs: bigint[] = [0n, 0n, 0n, 0n];
  for (let l = 0; l < 4; l++) {
    let acc = 0n;
    for (let b = 7; b >= 0; b--) {
      const idx = l * 8 + b;
      const byte = idx < bytes.length ? BigInt(bytes[idx]!) : 0n;
      acc = acc * 256n + byte;
    }
    limbs[l] = acc;
  }
  return limbs;
}

// Extract the subject RDN's serialNumber (OID 2.5.4.5) VALUE byte range
// from a DER-encoded X.509 certificate. Scans for the attribute-OID TLV
// (06 03 55 04 05), steps past it to the AttributeValue CHOICE element
// (PrintableString / UTF8String / IA5String / …), and returns the content
// offset + length. The string-type tag byte itself is not returned because
// X509SubjectSerial only consumes the content bytes.
export function findSubjectSerialValue(der: Uint8Array): {
  contentOffset: number;
  contentLength: number;
} {
  // SEQUENCE { OID 2.5.4.5, <AttributeValue DirectoryString> }
  // OID TLV: 06 03 55 04 05
  const oidTlv = [0x06, 0x03, 0x55, 0x04, 0x05];
  outer: for (let i = 0; i + oidTlv.length + 2 < der.length; i++) {
    for (let j = 0; j < oidTlv.length; j++) {
      if (der[i + j] !== oidTlv[j]) continue outer;
    }
    // AttributeValue tag: 0x13 (PrintableString), 0x0c (UTF8String),
    // 0x16 (IA5String), 0x14 (TeletexString). Subject serialNumber is
    // ≤ 32 content bytes in practice, so we only handle short-form length.
    const tagPos = i + oidTlv.length;
    const tag = der[tagPos]!;
    if (tag !== 0x13 && tag !== 0x0c && tag !== 0x16 && tag !== 0x14) continue outer;
    const lenByte = der[tagPos + 1]!;
    if (lenByte & 0x80) {
      throw new Error('subject serialNumber length is long-form (>127 bytes?)');
    }
    return { contentOffset: tagPos + 2, contentLength: lenByte };
  }
  throw new Error('subject serialNumber (OID 2.5.4.5) not found in DER');
}

// -------------------------------------------------------------------------
// Poseidon reference — used to compute leafSpkiCommit + nullifier off-circuit
// so tests can assert the circuit's outputs and so emit-stub-fixtures emits
// matching public-signal arrays. Matches Poseidon arity choices in the
// circuits exactly: Poseidon-6 over limbs, Poseidon-2 to combine X/Y, and
// Poseidon-5 (subjectSerialLimbs ‖ len) then Poseidon-2 (secret ‖ ctxHash).
// -------------------------------------------------------------------------

interface PoseidonF {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
  (inputs: unknown[]): unknown;
}
let poseidonCache: PoseidonF | null = null;
async function getPoseidon(): Promise<PoseidonF> {
  if (poseidonCache !== null) return poseidonCache;
  poseidonCache = (await buildPoseidon()) as unknown as PoseidonF;
  return poseidonCache;
}
async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const p = await getPoseidon();
  return p.F.toObject(p(inputs.map((v) => p.F.e(v))));
}

export async function computeLeafSpkiCommit(
  leafXBytes: Uint8Array,
  leafYBytes: Uint8Array,
): Promise<bigint> {
  const xLimbs = bytes32ToLimbs643(leafXBytes);
  const yLimbs = bytes32ToLimbs643(leafYBytes);
  const pX = await poseidonHash(xLimbs);
  const pY = await poseidonHash(yLimbs);
  return poseidonHash([pX, pY]);
}

export async function computeNullifier(
  subjectSerialLimbs: bigint[],
  subjectSerialLen: bigint,
  ctxHash: bigint,
): Promise<{ secret: bigint; nullifier: bigint }> {
  const secret = await poseidonHash([...subjectSerialLimbs, subjectSerialLen]);
  const nullifier = await poseidonHash([secret, ctxHash]);
  return { secret, nullifier };
}

// -------------------------------------------------------------------------
// Shared derivations from fixture — computed once; threaded into both
// builders so leafSpkiCommit, nullifier, and every offset match across
// the two circuits exactly.
// -------------------------------------------------------------------------

export interface SharedInputs {
  // Raw buffers
  binding: Buffer;
  leafDer: Buffer;
  intDer: Buffer;
  signedAttrs: Buffer;
  leafTbs: Buffer;
  declBytes: Buffer;
  // Padded-for-SHA256 copies
  bcanonPadded: Uint8Array;
  saPadded: Uint8Array;
  tbsPadded: Uint8Array;
  declPadded: Uint8Array;
  // Public-signal bigints
  pkX: bigint[];
  pkY: bigint[];
  ctxHash: bigint;
  declHash: bigint;
  timestamp: bigint;
  nullifier: bigint;
  leafSpkiCommit: bigint;
  // Offsets / lengths used by multiple builders
  ctxHexLen: number;
  tsDigitCount: number;
  subjectSerial: {
    contentOffset: number;
    contentLength: number;
    limbs: bigint[];
  };
  // Fixture passthrough
  fix: AdminEcdsaFixture;
}

export async function buildSharedInputs(fixtureDir: string): Promise<SharedInputs> {
  const fix = JSON.parse(
    readFileSync(resolve(fixtureDir, 'fixture.json'), 'utf8'),
  ) as AdminEcdsaFixture;
  const binding = readFileSync(resolve(fixtureDir, 'binding.qkb.json'));
  const leafDer = readFileSync(resolve(fixtureDir, 'leaf.der'));
  const intDer = readFileSync(resolve(fixtureDir, fix.synthIntermediate.derPath));
  const signedAttrs = Buffer.from(fix.cms.signedAttrsHex, 'hex');

  // SHA padding for each Sha256Var input.
  const bcanonPadded = sha256Pad(binding);
  const saPadded = sha256Pad(signedAttrs);
  const leafTbs = leafDer.subarray(
    fix.leaf.tbs.offset,
    fix.leaf.tbs.offset + fix.leaf.tbs.length,
  );
  const tbsPadded = sha256Pad(leafTbs);
  const declBytes = binding.subarray(
    fix.binding.offsets.declaration,
    fix.binding.offsets.declaration + fix.binding.declarationBytesLength,
  );
  const declPadded = sha256Pad(declBytes);

  // pk coordinates: real Diia binding stores pk = "0x04" || X || Y (65 bytes,
  // hex-encoded after "pk":"0x"). Offset `pk` points at '0' of '0x04...'.
  const pkAsciiStart = fix.binding.offsets.pk + 4; // skip '0x04'
  const pkHex = binding.subarray(pkAsciiStart, pkAsciiStart + 128).toString('utf8');
  const xBytes = Buffer.from(pkHex.slice(0, 64), 'hex');
  const yBytes = Buffer.from(pkHex.slice(64, 128), 'hex');
  const pkX = pkCoordToLimbs(xBytes);
  const pkY = pkCoordToLimbs(yBytes);

  // ctx in admin binding is "0x" (empty) → ctxHash = 0 in-circuit.
  const ctxHash = 0n;

  // declHash: packed SHA-256 of declBytes.
  const declDigest = new Uint8Array(createHash('sha256').update(declBytes).digest());
  const declHash = digestToField(declDigest);

  // Timestamp (decimal ASCII in binding at offsets.timestamp).
  const tsStart = fix.binding.offsets.timestamp;
  let tsEnd = tsStart;
  while (tsEnd < binding.length && binding[tsEnd]! >= 0x30 && binding[tsEnd]! <= 0x39) tsEnd++;
  const timestamp = BigInt(binding.subarray(tsStart, tsEnd).toString('utf8'));
  const tsDigitCount = tsEnd - tsStart;

  // ctx hex content length (between the opening "0x" and the closing quote).
  const ctxStart = fix.binding.offsets.context + 2;
  let ctxEnd = ctxStart;
  while (ctxEnd < binding.length && binding[ctxEnd] !== 0x22) ctxEnd++;
  const ctxHexLen = ctxEnd - ctxStart;

  // Leaf SPKI X, Y bytes for leafSpkiCommit.
  const leafXBytes = new Uint8Array(
    leafDer.subarray(fix.leaf.spki.xOffset, fix.leaf.spki.xOffset + 32),
  );
  const leafYBytes = new Uint8Array(
    leafDer.subarray(fix.leaf.spki.yOffset, fix.leaf.spki.yOffset + 32),
  );
  const leafSpkiCommit = await computeLeafSpkiCommit(leafXBytes, leafYBytes);

  // Subject serialNumber — scan leafDER for OID 2.5.4.5, derive limbs.
  const subjectSerial = findSubjectSerialValue(new Uint8Array(leafDer));
  const serialBytes = new Uint8Array(
    leafDer.subarray(
      subjectSerial.contentOffset,
      subjectSerial.contentOffset + subjectSerial.contentLength,
    ),
  );
  const serialLimbs = subjectSerialBytesToLimbs(serialBytes);
  const { nullifier } = await computeNullifier(
    serialLimbs,
    BigInt(subjectSerial.contentLength),
    ctxHash,
  );

  return {
    binding,
    leafDer,
    intDer,
    signedAttrs,
    leafTbs,
    declBytes,
    bcanonPadded,
    saPadded,
    tbsPadded,
    declPadded,
    pkX,
    pkY,
    ctxHash,
    declHash,
    timestamp,
    nullifier,
    leafSpkiCommit,
    ctxHexLen,
    tsDigitCount,
    subjectSerial: {
      contentOffset: subjectSerial.contentOffset,
      contentLength: subjectSerial.contentLength,
      limbs: serialLimbs,
    },
    fix,
  };
}

// -------------------------------------------------------------------------
// Leaf witness builder.
// -------------------------------------------------------------------------

export async function buildLeafWitness(fixtureDir: string): Promise<LeafWitnessInput> {
  const s = await buildSharedInputs(fixtureDir);
  const leafR = bytes32ToLimbs643(Buffer.from(s.fix.cms.leafSigR, 'hex'));
  const leafS = bytes32ToLimbs643(Buffer.from(s.fix.cms.leafSigS, 'hex'));

  return {
    // Public
    pkX: s.pkX.map((v) => v.toString()),
    pkY: s.pkY.map((v) => v.toString()),
    ctxHash: s.ctxHash.toString(),
    declHash: s.declHash.toString(),
    timestamp: s.timestamp.toString(),
    nullifier: s.nullifier.toString(),

    // Nullifier extraction
    subjectSerialValueOffset: s.subjectSerial.contentOffset,
    subjectSerialValueLength: s.subjectSerial.contentLength,

    // Binding
    Bcanon: zeroPadTo(s.binding, MAX_BCANON),
    BcanonLen: s.binding.length,
    BcanonPaddedIn: zeroPadTo(s.bcanonPadded, MAX_BCANON),
    BcanonPaddedLen: s.bcanonPadded.length,
    pkValueOffset: s.fix.binding.offsets.pk,
    schemeValueOffset: s.fix.binding.offsets.scheme,
    ctxValueOffset: s.fix.binding.offsets.context,
    ctxHexLen: s.ctxHexLen,
    declValueOffset: s.fix.binding.offsets.declaration,
    declValueLen: s.fix.binding.declarationBytesLength,
    tsValueOffset: s.fix.binding.offsets.timestamp,
    tsDigitCount: s.tsDigitCount,

    // Declaration
    declPaddedIn: zeroPadTo(s.declPadded, MAX_DECL + 64),
    declPaddedLen: s.declPadded.length,

    // CMS signedAttrs
    signedAttrs: zeroPadTo(s.signedAttrs, MAX_SA),
    signedAttrsLen: s.signedAttrs.length,
    signedAttrsPaddedIn: zeroPadTo(s.saPadded, MAX_SA),
    signedAttrsPaddedLen: s.saPadded.length,
    mdOffsetInSA: s.fix.cms.messageDigestOffsetInSignedAttrs,

    // Leaf cert + signature
    leafDER: zeroPadTo(s.leafDer, MAX_CERT),
    leafSpkiXOffset: s.fix.leaf.spki.xOffset,
    leafSpkiYOffset: s.fix.leaf.spki.yOffset,
    leafSigR: leafR.map((v) => v.toString()),
    leafSigS: leafS.map((v) => v.toString()),
  };
}

// -------------------------------------------------------------------------
// Chain witness builder.
// -------------------------------------------------------------------------

export async function buildChainWitness(fixtureDir: string): Promise<ChainWitnessInput> {
  const s = await buildSharedInputs(fixtureDir);
  const intR = bytes32ToLimbs643(
    Buffer.from(s.fix.synthIntermediate.sigROverRealLeafTbsHex, 'hex'),
  );
  const intS = bytes32ToLimbs643(
    Buffer.from(s.fix.synthIntermediate.sigSOverRealLeafTbsHex, 'hex'),
  );

  return {
    // Public
    rTL: s.fix.merkle.root,
    algorithmTag: '1',

    // Leaf cert (for leafSpkiCommit output)
    leafDER: zeroPadTo(s.leafDer, MAX_CERT),
    leafSpkiXOffset: s.fix.leaf.spki.xOffset,
    leafSpkiYOffset: s.fix.leaf.spki.yOffset,

    // Leaf TBS padded
    leafTbsPaddedIn: zeroPadTo(s.tbsPadded, MAX_CERT),
    leafTbsPaddedLen: s.tbsPadded.length,

    // Intermediate cert + signature
    intDER: zeroPadTo(s.intDer, MAX_CERT),
    intDerLen: s.intDer.length,
    intSpkiXOffset: s.fix.synthIntermediate.spkiXOffset,
    intSpkiYOffset: s.fix.synthIntermediate.spkiYOffset,
    intSigR: intR.map((v) => v.toString()),
    intSigS: intS.map((v) => v.toString()),

    // Merkle
    merklePath: s.fix.merkle.path,
    merkleIndices: s.fix.merkle.indices,
  };
}
