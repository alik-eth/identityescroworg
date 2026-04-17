/**
 * Circuit witness builder for `QKBPresentationEcdsaLeaf`.
 *
 * The leaf circuit (see circuits/packages/circuits/circuits/
 * QKBPresentationEcdsaLeaf.circom) wires constraints 1, 2, 5, 6 of R_QKB —
 * the "binding proof" that the user actually performed the QES over the
 * committed binding. Chain-side constraints 3, 4 (intermediate signs leaf,
 * intermediate in trusted list) are proved by a separate chain circuit and
 * glued on-chain via the `leafSpkiCommit` public signal, per spec §5.4
 * split-proof fallback. This module therefore produces ONLY the leaf
 * inputs — no `rTL`, no `algorithmTag`, no `intDER`, no `merklePath`.
 *
 * Public signal order produced by the compiled leaf circuit (must match the
 * on-chain verifier and the contracts worker's Inputs struct):
 *
 *   [0]     leafSpkiCommit   Poseidon commitment to the leaf SPKI (output)
 *   [1..4]  pkX[4]           secp256k1 X coordinate, 4 × uint64 LE limbs
 *   [5..8]  pkY[4]           secp256k1 Y coordinate, 4 × uint64 LE limbs
 *   [9]     ctxHash          Poseidon of ctx bytes, or 0 when ctx is empty
 *   [10]    declHash         sha256(declaration) packed into a BN254 field
 *                            element (same as Bits256ToField on the digest)
 *   [11]    timestamp        unix seconds
 *
 * Everything else in the return value is a private witness input; the
 * circuit uses it to re-derive the public signals under constraint.
 *
 * Offsets inside Bcanon are located by byte-scan at runtime — Bcanon is
 * JCS-canonicalized JSON with a frozen key order (binding.ts §4.1), so the
 * `"<key>":` literals appear exactly once and `indexOf` is unambiguous.
 * Offsets inside the leaf DER are located by searching for the DER bytes
 * of the TBS and SPKI x/y coordinates — the cert we receive from CAdES
 * parsing is re-encoded, so the search-based approach is stable across
 * BER/DER re-encodings of the same cert.
 *
 * All numbers larger than a JS safe-int are emitted as decimal strings,
 * which is the convention snarkjs expects for `calculateWitness`.
 */
import { sha256 } from '@noble/hashes/sha256';
import * as asn1js from 'asn1js';
import { Certificate } from 'pkijs';
import type { Binding } from './binding';
import type { ParsedCades } from './cades';
import { QkbError } from './errors';

// Compile-time caps from the leaf circuit. Must stay in sync with
// QKBPresentationEcdsaLeaf.circom:
//   MAX_BCANON = 1024, MAX_SA = 1536, MAX_CERT = 1536,
//   MAX_CTX = 256, MAX_DECL = 960.
export const MAX_BCANON = 1024;
export const MAX_SA = 1536;
export const MAX_CERT = 1536;
export const MAX_CTX = 256;
export const MAX_DECL = 960;

export interface LeafWitnessInput {
  // Public inputs
  pkX: string[];
  pkY: string[];
  ctxHash: string;
  declHash: string;
  timestamp: string;

  // Binding parse
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

  // Declaration hash
  declPaddedIn: number[];
  declPaddedLen: number;

  // CAdES signedAttrs
  signedAttrs: number[];
  signedAttrsLen: number;
  signedAttrsPaddedIn: number[];
  signedAttrsPaddedLen: number;
  mdOffsetInSA: number;

  // Leaf certificate
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
  leafSigR: string[];
  leafSigS: string[];
}

export interface BuildWitnessInput {
  parsed: ParsedCades;
  binding: Binding;
  bindingBytes: Uint8Array;
}

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
// Bytes32ToLimbs643 in the circuit (used for ECDSA r/s on the signature
// over signedAttrs).
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

/**
 * Build the leaf-circuit witness input from already-parsed CAdES + binding.
 *
 * The circuit's signal-input layout — and therefore the field names on the
 * returned object — mirrors what `buildEcdsaWitness` emits on the circuits
 * side (test/integration/witness-builder.ts), minus the chain-only fields.
 */
export function buildLeafWitness(input: BuildWitnessInput): LeafWitnessInput {
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

  // --- ctxHash: the admin / Phase-1 binding currently uses context "0x"
  //     (empty hex after prefix). The circuit treats "ctx empty ⇒ ctxHash=0"
  //     so we emit 0 here when the hex body is empty. Non-empty contexts
  //     require the Poseidon path, which is out of scope until Phase 2
  //     enables it for escrow commitments. ---
  const ctxStart = ctxKeyOff + '"context":"0x'.length;
  let ctxEnd = ctxStart;
  while (ctxEnd < bindingBytes.length && bindingBytes[ctxEnd] !== 0x22 /* " */) ctxEnd++;
  const ctxHexLen = ctxEnd - ctxStart;
  if (ctxHexLen !== 0) {
    throw new QkbError('witness.fieldTooLong', {
      field: 'ctx',
      reason: 'non-empty-ctx-unsupported-phase1',
      got: ctxHexLen,
    });
  }
  const ctxHash = '0';

  // --- pk X/Y limbs extracted from the uncompressed ASCII pk hex ---
  //   binding.pk == "0x04" || X(32 bytes hex = 64 chars) || Y(64 chars)
  const pkHex = binding.pk.startsWith('0x') ? binding.pk.slice(2) : binding.pk;
  if (pkHex.length !== 130 || !pkHex.toLowerCase().startsWith('04')) {
    throw new QkbError('witness.fieldTooLong', {
      field: 'pk',
      reason: 'expected-uncompressed',
      got: pkHex.length,
    });
  }
  const xBytes = hexToBytes(pkHex.slice(2, 66));
  const yBytes = hexToBytes(pkHex.slice(66, 130));
  const pkX = pkCoordToLimbs(xBytes);
  const pkY = pkCoordToLimbs(yBytes);

  // --- Declaration: slice from Bcanon bytes, hash, pack into a field ---
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
  const timestamp = BigInt(new TextDecoder().decode(bindingBytes.subarray(tsStart, tsEnd))).toString();

  // --- SHA padding for each Sha256Var instance in the circuit ---
  const bcanonPadded = sha256Pad(bindingBytes);
  const saPadded = sha256Pad(parsed.signedAttrsDer);

  // --- Leaf cert TBS + SPKI x/y offsets: search in the DER bytes. The
  //     re-encoded cert from pkijs is a standard SEQ { TBS, sigAlg, sig },
  //     so TBS starts with 0x30 0x82 <LL> <LL> at offset 4 typically, but
  //     we do not hardcode — we decode via asn1js to find the TBS length,
  //     then treat offset 4 as the start (skipping outer tag+length). ---
  const leafDer = parsed.leafCertDer;
  const { tbsOffset, tbsLen } = findTbs(leafDer);
  const tbsBytes = leafDer.subarray(tbsOffset, tbsOffset + tbsLen);
  const tbsPadded = sha256Pad(tbsBytes);

  const { spkiXOffset, spkiYOffset } = findSpkiXYOffsets(leafDer);

  // --- Leaf signature R/S from the CAdES signer signatureValue (over
  //     signedAttrsDer). ECDSA signatures are encoded as SEQ { INTEGER r,
  //     INTEGER s } — decode and trim leading zeros, then left-pad to 32. ---
  const { r: leafSigR32, s: leafSigS32 } = ecdsaSigDerToRS32(parsed.signatureValue);
  const leafSigR = bytes32ToLimbs643(leafSigR32);
  const leafSigS = bytes32ToLimbs643(leafSigS32);

  // --- messageDigest attribute offset inside signedAttrsDer ---
  const mdOffsetInSA = findMessageDigestOffsetInSA(parsed.signedAttrsDer, parsed.messageDigest);

  return {
    pkX,
    pkY,
    ctxHash,
    declHash,
    timestamp,
    Bcanon: zeroPadTo(bindingBytes, MAX_BCANON),
    BcanonLen: bindingBytes.length,
    BcanonPaddedIn: zeroPadTo(bcanonPadded, MAX_BCANON),
    BcanonPaddedLen: bcanonPadded.length,
    pkValueOffset: pkKeyOff,
    schemeValueOffset: schemeKeyOff,
    ctxValueOffset: ctxKeyOff,
    ctxHexLen,
    declValueOffset: declKeyOff,
    declValueLen: declBytes.length,
    tsValueOffset: tsKeyOff,
    tsDigitCount,
    declPaddedIn: zeroPadTo(declPadded, MAX_DECL + 64),
    declPaddedLen: declPadded.length,
    signedAttrs: zeroPadTo(parsed.signedAttrsDer, MAX_SA),
    signedAttrsLen: parsed.signedAttrsDer.length,
    signedAttrsPaddedIn: zeroPadTo(saPadded, MAX_SA),
    signedAttrsPaddedLen: saPadded.length,
    mdOffsetInSA,
    leafDER: zeroPadTo(leafDer, MAX_CERT),
    leafDerLen: leafDer.length,
    leafTbsOffset: tbsOffset,
    leafTbsLen: tbsLen,
    leafTbsPaddedIn: zeroPadTo(tbsPadded, MAX_CERT),
    leafTbsPaddedLen: tbsPadded.length,
    leafSpkiXOffset: spkiXOffset,
    leafSpkiYOffset: spkiYOffset,
    // The circuit declares leafNotBefore/notAfterOffset as inputs but the
    // constraint is currently inert (validity enforced off-circuit by
    // qesVerify). Supply 0 to satisfy the signal binding.
    leafNotBeforeOffset: 0,
    leafNotAfterOffset: 0,
    leafSigR,
    leafSigS,
  };
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
  // (also SEQUENCE). Decode the outer header + first child header and return
  // the child's full encoding length (header+content).
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
  // For ECDSA P-256 leaves the SPKI BIT STRING contains:
  //   0x00 (unused bits) || 0x04 (uncompressed) || X(32) || Y(32)
  // We parse the cert, re-encode the SPKI, grab the last 65 bytes of the
  // BIT STRING contents, and search them in the raw DER.
  const buf = toAB(der);
  const asn = asn1js.fromBER(buf);
  if (asn.offset === -1) {
    throw new QkbError('witness.offsetNotFound', { field: 'leafSpki', reason: 'asn1' });
  }
  const cert = new Certificate({ schema: asn.result });
  const pubKey = new Uint8Array(
    cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
  );
  // pkijs strips the BIT STRING unused-bits byte; pubKey = 0x04 || X || Y.
  if (pubKey.length !== 65 || pubKey[0] !== 0x04) {
    throw new QkbError('witness.offsetNotFound', {
      field: 'leafSpki',
      reason: 'not-uncompressed-p256',
      len: pubKey.length,
    });
  }
  const off = indexOfSubarray(der, pubKey);
  if (off === -1) {
    throw new QkbError('witness.offsetNotFound', { field: 'leafSpki', reason: 'not-in-der' });
  }
  return { spkiXOffset: off + 1, spkiYOffset: off + 33 };
}

function ecdsaSigDerToRS32(der: Uint8Array): { r: Uint8Array; s: Uint8Array } {
  const asn = asn1js.fromBER(toAB(der));
  if (asn.offset === -1) {
    throw new QkbError('witness.offsetNotFound', { field: 'leafSig', reason: 'asn1' });
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
  // SET. Find the 0x04 0x20 marker + the 32-byte payload; return the offset
  // of the 32-byte payload within signedAttrsDer (matches the circuit's
  // `mdOffsetInSA` input semantics).
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
