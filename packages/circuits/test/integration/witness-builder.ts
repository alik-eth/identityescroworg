// Witness builder for the QKBPresentationEcdsa main circuit.
//
// Reads a fixture emitted by scripts/build-admin-ecdsa-fixture.ts and
// produces a record matching the circuit's signal-input layout. Handles
// all off-circuit bookkeeping: SHA-256 pre-padding, byte→limb packing for
// ECDSA inputs, bit-order conversion for declHash, and left-padding/zero-
// extension to the compile-time MAX sizes.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';

// Compile-time caps the main circuit uses.
export const MAX_BCANON = 1024;
export const MAX_SA = 1536;
export const MAX_CERT = 1536;
export const MAX_CTX = 256;
export const MAX_DECL = 960;
export const MERKLE_DEPTH = 16;

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

export interface EcdsaWitnessInput {
  pkX: string[];
  pkY: string[];
  ctxHash: string;
  rTL: string;
  declHash: string;
  timestamp: string;
  algorithmTag: string;
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
  declPaddedIn: number[];
  declPaddedLen: number;
  signedAttrs: number[];
  signedAttrsLen: number;
  signedAttrsPaddedIn: number[];
  signedAttrsPaddedLen: number;
  mdOffsetInSA: number;
  leafDER: number[];
  leafDerLen: number;
  leafTbsOffset: number;
  leafTbsLen: number;
  leafTbsPaddedIn: number[];
  leafTbsPaddedLen: number;
  leafSpkiXOffset: number;
  leafSpkiYOffset: number;
  leafNotBeforeOffset: number;
  leafNotAfterOffset: number;
  leafSigR: (string | number)[];
  leafSigS: (string | number)[];
  intDER: number[];
  intDerLen: number;
  intSpkiXOffset: number;
  intSpkiYOffset: number;
  intSigR: (string | number)[];
  intSigS: (string | number)[];
  merklePath: string[];
  merkleIndices: number[];
}

// FIPS 180-4 SHA-256 padding: one 0x80 byte, zero padding, 8-byte big-endian
// bit-length trailer. Result length is a multiple of 64.
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

// Zero-extend a Uint8Array to exactly `max` bytes. Caller is responsible for
// asserting data.length <= max.
export function zeroPadTo(data: Uint8Array, max: number): number[] {
  if (data.length > max) throw new Error(`${data.length} > max ${max}`);
  const out = new Array<number>(max).fill(0);
  for (let i = 0; i < data.length; i++) out[i] = data[i]!;
  return out;
}

// Pack 32 big-endian bytes into 6 × 43-bit limbs, LE across limbs. Matches
// the `Bytes32ToLimbs643` template in the main circuit.
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

// Pack pk X or Y coordinate (32 big-endian bytes) into 4 × 64-bit LE limbs
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
// element interpreted as a 256-bit integer, matching the circuit's
// Bits256ToField output.
export function digestToField(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) throw new Error('expected 32 bytes');
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
}

export function buildEcdsaWitness(fixtureDir: string): EcdsaWitnessInput {
  const fix = JSON.parse(
    readFileSync(resolve(fixtureDir, 'fixture.json'), 'utf8'),
  ) as AdminEcdsaFixture;
  const binding = readFileSync(resolve(fixtureDir, 'binding.qkb.json'));
  const leafDer = readFileSync(resolve(fixtureDir, 'leaf.der'));
  const intDer = readFileSync(resolve(fixtureDir, fix.synthIntermediate.derPath));
  const signedAttrs = Buffer.from(fix.cms.signedAttrsHex, 'hex');

  // SHA padding for each input fed to Sha256Var.
  const bcanonPadded = sha256Pad(binding);
  const saPadded = sha256Pad(signedAttrs);
  const leafTbs = leafDer.subarray(fix.leaf.tbs.offset, fix.leaf.tbs.offset + fix.leaf.tbs.length);
  const tbsPadded = sha256Pad(leafTbs);
  const declBytes = binding.subarray(
    fix.binding.offsets.declaration,
    fix.binding.offsets.declaration + fix.binding.declarationBytesLength,
  );
  const declPadded = sha256Pad(declBytes);

  // pk coordinates: real Diia leaf binding stores pk = 0x04 || X || Y (65 bytes,
  // hex-encoded after "pk":"0x"). Offset `pk` points at the '0' of '0x04...'.
  const pkAsciiStart = fix.binding.offsets.pk + 4; // skip '0x04'
  const pkHex = binding.subarray(pkAsciiStart, pkAsciiStart + 128).toString('utf8');
  const xBytes = Buffer.from(pkHex.slice(0, 64), 'hex');
  const yBytes = Buffer.from(pkHex.slice(64, 128), 'hex');
  const pkX = pkCoordToLimbs(xBytes);
  const pkY = pkCoordToLimbs(yBytes);

  // ctx field in admin binding is "0x" (empty). ctxHash = 0.
  const ctxHash = 0n;

  // declHash = packed SHA-256 digest over declBytes.
  const declDigest = new Uint8Array(createHash('sha256').update(declBytes).digest());
  const declHash = digestToField(declDigest);

  // Timestamp integer.
  const tsStart = fix.binding.offsets.timestamp;
  let tsEnd = tsStart;
  while (tsEnd < binding.length && binding[tsEnd]! >= 0x30 && binding[tsEnd]! <= 0x39) tsEnd++;
  const tsValue = BigInt(binding.subarray(tsStart, tsEnd).toString('utf8'));
  const tsDigitCount = tsEnd - tsStart;

  // ctx hex length within "0x" prefix.
  const ctxStart = fix.binding.offsets.context + 2;
  let ctxEnd = ctxStart;
  while (ctxEnd < binding.length && binding[ctxEnd] !== 0x22) ctxEnd++;
  const ctxHexLen = ctxEnd - ctxStart;

  // SPKI x/y offsets within intermediate DER (compute from its bytes).
  const intSpkiX = fix.synthIntermediate.spkiXOffset;
  const intSpkiY = fix.synthIntermediate.spkiYOffset;

  // Leaf sigR/sigS (hex) → 6×43-bit LE limbs.
  const leafR = bytes32ToLimbs643(Buffer.from(fix.cms.leafSigR, 'hex'));
  const leafS = bytes32ToLimbs643(Buffer.from(fix.cms.leafSigS, 'hex'));
  const intR = bytes32ToLimbs643(Buffer.from(fix.synthIntermediate.sigROverRealLeafTbsHex, 'hex'));
  const intS = bytes32ToLimbs643(Buffer.from(fix.synthIntermediate.sigSOverRealLeafTbsHex, 'hex'));

  // Note: the circuit has `leafNotBeforeOffset`/`leafNotAfterOffset` inputs
  // that are currently constraint-inert (validity check deferred). Supply
  // any in-buffer offset to satisfy the no-op constraint.
  const leafNotBeforeOffset = 0;
  const leafNotAfterOffset = 0;

  return {
    pkX: pkX.map((v) => v.toString()),
    pkY: pkY.map((v) => v.toString()),
    ctxHash: ctxHash.toString(),
    rTL: fix.merkle.root,
    declHash: declHash.toString(),
    timestamp: tsValue.toString(),
    algorithmTag: '1',
    Bcanon: zeroPadTo(binding, MAX_BCANON),
    BcanonLen: binding.length,
    BcanonPaddedIn: zeroPadTo(bcanonPadded, MAX_BCANON),
    BcanonPaddedLen: bcanonPadded.length,
    pkValueOffset: fix.binding.offsets.pk,
    schemeValueOffset: fix.binding.offsets.scheme,
    ctxValueOffset: fix.binding.offsets.context,
    ctxHexLen,
    declValueOffset: fix.binding.offsets.declaration,
    declValueLen: fix.binding.declarationBytesLength,
    tsValueOffset: fix.binding.offsets.timestamp,
    tsDigitCount,
    declPaddedIn: zeroPadTo(declPadded, MAX_DECL + 64),
    declPaddedLen: declPadded.length,
    signedAttrs: zeroPadTo(signedAttrs, MAX_SA),
    signedAttrsLen: signedAttrs.length,
    signedAttrsPaddedIn: zeroPadTo(saPadded, MAX_SA),
    signedAttrsPaddedLen: saPadded.length,
    mdOffsetInSA: fix.cms.messageDigestOffsetInSignedAttrs,
    leafDER: zeroPadTo(leafDer, MAX_CERT),
    leafDerLen: leafDer.length,
    leafTbsOffset: fix.leaf.tbs.offset,
    leafTbsLen: fix.leaf.tbs.length,
    leafTbsPaddedIn: zeroPadTo(tbsPadded, MAX_CERT),
    leafTbsPaddedLen: tbsPadded.length,
    leafSpkiXOffset: fix.leaf.spki.xOffset,
    leafSpkiYOffset: fix.leaf.spki.yOffset,
    leafNotBeforeOffset,
    leafNotAfterOffset,
    leafSigR: leafR.map((v) => v.toString()),
    leafSigS: leafS.map((v) => v.toString()),
    intDER: zeroPadTo(intDer, MAX_CERT),
    intDerLen: intDer.length,
    intSpkiXOffset: intSpkiX,
    intSpkiYOffset: intSpkiY,
    intSigR: intR.map((v) => v.toString()),
    intSigS: intS.map((v) => v.toString()),
    merklePath: fix.merkle.path,
    merkleIndices: fix.merkle.indices,
  };
}
