// V5 witness builder — production entry point (browser-safe port).
//
// Cross-read from arch-circuits f0d5a73's `src/build-witness-v5.ts`. Two
// browser patches relative to the source:
//   1. `node:crypto.createHash('sha256')` → `sha256` from `@noble/hashes/sha2`.
//      Byte-identical: both follow FIPS 180-4 strictly.
//   2. `require('ethers/lib/utils').keccak256` → `keccak_256` from
//      `@noble/hashes/sha3`. Byte-identical: both follow FIPS 202 Keccak-256.
//
// The cross-package "byte-identical witness" contract still applies — if
// circuits-eng amends `build-witness-v5.ts`, this copy MUST be re-synced.
// The integration test in arch-circuits asserts byte-identity against
// `buildV5SmokeWitness`; we don't have a corresponding test on web side
// yet (gated on a real Diia .p7s fixture being pumped here).

import { Buffer } from './_buffer-global';
import { sha256 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';

import { extractBindingOffsets } from './binding-offsets';
import { findSubjectSerial, findTbsInCert } from './leaf-cert-walk';
import { pkCoordToLimbs, subjectSerialBytesToLimbs } from './limbs';
import {
  poseidon2,
  poseidon5,
  poseidonChunkHashVar,
} from './poseidon-chunk-hash';
import {
  decomposeTo643Limbs,
  parseP256Spki,
  spkiCommit,
} from './spki-commit-ref';
import {
  MAX_BCANON,
  MAX_CERT,
  MAX_CTX_PADDED,
  MAX_LEAF_TBS,
  MAX_POLICY_ID,
  MAX_SA,
  type BuildWitnessV5Input,
  type V2CoreBindingOffsets,
  type WitnessV5,
} from './types';

// ----- FIPS-180-4 SHA padding helper -----
// Returns the canonical FIPS-180-4 §5.1.1 padded form of `msg`. Length is
// a multiple of 64 bytes. `Sha256CanonPad(MAX_BYTES)` in the circuit
// asserts the witness-supplied padded form matches this exact byte layout.
function shaPad(msg: Uint8Array): Uint8Array {
  const bitLen = BigInt(msg.length) * 8n;
  const padded = new Uint8Array(Math.ceil((msg.length + 1 + 8) / 64) * 64);
  padded.set(msg, 0);
  padded[msg.length] = 0x80;
  // Length trailer: 8 bytes BE.
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  view.setBigUint64(padded.length - 8, bitLen, false);
  return padded;
}

function rightPadZero(buf: Uint8Array | Buffer, target: number): number[] {
  if (buf.length > target) {
    throw new Error(
      `rightPadZero: input length ${buf.length} exceeds target ${target}`,
    );
  }
  const out = new Array<number>(target).fill(0);
  for (let i = 0; i < buf.length; i++) out[i] = (buf as Buffer)[i] ?? 0;
  return out;
}

function digestHiLo(digest: Uint8Array): { hi: bigint; lo: bigint } {
  if (digest.length !== 32) {
    throw new Error(`digestHiLo: expected 32-byte digest, got ${digest.length}`);
  }
  const hex = Buffer.from(digest).toString('hex');
  return {
    hi: BigInt('0x' + hex.slice(0, 32)),
    lo: BigInt('0x' + hex.slice(32, 64)),
  };
}

function sha256Buf(input: Uint8Array | Buffer): Buffer {
  return Buffer.from(sha256(input));
}

// ----- Public API ------------------------------------------------------

/**
 * Build a V5-main witness from pre-extracted CMS + fixture artifacts.
 *
 * Order of operations mirrors the §6.x wiring tasks:
 *   §6.2  parser binds (timestamp + policyLeafHash) — needs binding offsets.
 *   §6.3  3× SHA chains (binding, signedAttrs, leafTbs).
 *   §6.4  signedAttrsParser fixed-shape walker — needs `signedAttrsMdOffset`.
 *   §6.5  2× SpkiCommit over leaf + intermediate SPKIs.
 *   §6.6  X509SubjectSerial walk → NullifierDerive (Poseidon-domain ctx).
 *   §6.7  Sha256Var(ctxBytes) + Bytes32ToHiLo for the public ctxHashHi/Lo.
 *   §6.8  Secp256k1PkMatch + Keccak256 → msgSender bind.
 *   §6.9  leafTbs ↔ leafCert byte-consistency over the serial window.
 */
export async function buildWitnessV5(
  input: BuildWitnessV5Input,
): Promise<WitnessV5> {
  // -------- §6.2 — V2Core offsets --------
  const offsets: V2CoreBindingOffsets =
    input.bindingOffsets ?? extractBindingOffsets(input.bindingBytes);

  if (input.bindingBytes.length > MAX_BCANON) {
    throw new Error(
      `bindingBytes ${input.bindingBytes.length} > MAX_BCANON ${MAX_BCANON}`,
    );
  }
  if (input.signedAttrsDer.length > MAX_SA) {
    throw new Error(
      `signedAttrsDer ${input.signedAttrsDer.length} > MAX_SA ${MAX_SA}`,
    );
  }
  if (input.leafCertDer.length > MAX_CERT) {
    throw new Error(`leafCertDer ${input.leafCertDer.length} > MAX_CERT ${MAX_CERT}`);
  }

  // -------- Binding parser inputs --------
  const nonceBytesIn = (() => {
    const start = offsets.nonceValueOffset + 2; // skip "0x"
    const out = Buffer.alloc(32);
    Buffer.from(input.bindingBytes.subarray(start, start + 64).toString('utf8'), 'hex').copy(out);
    return out;
  })();
  const policyIdBytesIn = Buffer.from(
    input.bindingBytes.subarray(
      offsets.policyIdValueOffset,
      offsets.policyIdValueOffset + offsets.policyIdLen,
    ),
  );
  const policyVersionIn = (() => {
    const slice = input.bindingBytes
      .subarray(
        offsets.policyVersionValueOffset,
        offsets.policyVersionValueOffset + offsets.policyVersionDigitCount,
      )
      .toString('utf8');
    const n = Number.parseInt(slice, 10);
    if (!Number.isFinite(n)) {
      throw new Error(`binding.policyVersion not a number: ${slice}`);
    }
    return n;
  })();

  // -------- §6.3 — 3× SHA chains + canonical-pad witness --------
  const bindingDigest = sha256Buf(input.bindingBytes);
  const bindingHash = digestHiLo(bindingDigest);
  const bindingPadded = shaPad(input.bindingBytes);

  const saDigest = sha256Buf(input.signedAttrsDer);
  const saHash = digestHiLo(saDigest);
  const saPadded = shaPad(input.signedAttrsDer);

  // Real Diia leaf TBS comes from inside the leaf cert DER — the §6.9
  // gate cross-checks bytes between leafCertBytes and leafTbsBytes.
  const tbsLoc = findTbsInCert(input.leafCertDer);
  if (tbsLoc.length > MAX_LEAF_TBS) {
    throw new Error(
      `leaf TBS ${tbsLoc.length} > MAX_LEAF_TBS ${MAX_LEAF_TBS}; widen the bound`,
    );
  }
  const leafTbsBuf = input.leafCertDer.subarray(
    tbsLoc.offset,
    tbsLoc.offset + tbsLoc.length,
  );
  const leafTbsDigest = sha256Buf(leafTbsBuf);
  const leafTbsHash = digestHiLo(leafTbsDigest);
  const leafTbsPadded = shaPad(leafTbsBuf);

  // -------- §6.5 — SPKI commits + 6×43 limbs --------
  const { x: leafX, y: leafY } = parseP256Spki(input.leafSpki);
  const { x: intX, y: intY } = parseP256Spki(input.intSpki);
  const leafXLimbs = decomposeTo643Limbs(leafX);
  const leafYLimbs = decomposeTo643Limbs(leafY);
  const intXLimbs = decomposeTo643Limbs(intX);
  const intYLimbs = decomposeTo643Limbs(intY);
  const leafSpkiCommit = await spkiCommit(input.leafSpki);
  const intSpkiCommit = await spkiCommit(input.intSpki);

  // -------- §6.6 — Subject serial → NullifierDerive --------
  const subjectSerial = findSubjectSerial(input.leafCertDer);
  const subjectSerialBytes = Buffer.from(
    input.leafCertDer.subarray(
      subjectSerial.offset,
      subjectSerial.offset + subjectSerial.length,
    ),
  );
  const subjectSerialLimbs = subjectSerialBytesToLimbs(subjectSerialBytes);
  const subjectSerialValueOffsetInTbs = subjectSerial.offset - tbsLoc.offset;

  // ctx field-domain hash (PoseidonChunkHashVar). Decode the binding's
  // hex-encoded ctx to bytes; for empty ctx (ctxHexLen=0) the digest is
  // Poseidon(16, [0×16]).
  const ctxBytes = (() => {
    if (offsets.ctxHexLen === 0) return Buffer.alloc(0);
    const start = offsets.ctxValueOffset + 2; // skip "0x"
    const hex = input.bindingBytes
      .subarray(start, start + offsets.ctxHexLen)
      .toString('utf8');
    return Buffer.from(hex, 'hex');
  })();
  const ctxHashField = await poseidonChunkHashVar(new Uint8Array(ctxBytes));
  const secret = await poseidon5([
    ...subjectSerialLimbs,
    BigInt(subjectSerial.length),
  ]);
  const nullifier = await poseidon2(secret, ctxHashField);

  // -------- §6.7 — Byte-domain SHA over ctx --------
  const ctxDigest = sha256Buf(ctxBytes);
  const ctxHash = digestHiLo(ctxDigest);
  const ctxPaddedBuf = shaPad(ctxBytes);

  // -------- §6.8 — pkX/pkY limbs + msgSender via keccak --------
  const pkBytes = (() => {
    const start = offsets.pkValueOffset + 2; // skip "0x" leadIn
    const hex = input.bindingBytes
      .subarray(start, start + 130)
      .toString('utf8');
    const buf = Buffer.from(hex, 'hex');
    if (buf.length !== 65 || buf[0] !== 0x04) {
      throw new Error(
        `binding.pk must be 65-byte SEC1 uncompressed (0x04 || X || Y); got ${buf.length} bytes`,
      );
    }
    return buf;
  })();
  const pkX = pkCoordToLimbs(pkBytes.subarray(1, 33));
  const pkY = pkCoordToLimbs(pkBytes.subarray(33, 65));
  // Browser patch: keccak_256 from @noble/hashes is byte-identical to
  // ethers/v5's keccak256 over the same input bytes.
  const addrDigest = keccak_256(pkBytes.subarray(1, 65));
  const addrHex = Buffer.from(addrDigest).toString('hex');
  // Take the low 20 bytes (40 hex chars) — Ethereum address convention.
  const msgSender = BigInt('0x' + addrHex.slice(24));

  // -------- timestamp + policyLeafHash (parsed out of binding) --------
  const tsValue = (() => {
    const slice = input.bindingBytes
      .subarray(
        offsets.tsValueOffset,
        offsets.tsValueOffset + offsets.tsDigitCount,
      )
      .toString('utf8');
    const n = Number.parseInt(slice, 10);
    if (!Number.isFinite(n)) {
      throw new Error(`binding.timestamp not a number: ${slice}`);
    }
    return n;
  })();
  const policyLeafHash = (() => {
    const start = offsets.policyLeafHashValueOffset + 2; // skip "0x"
    const hex = input.bindingBytes.subarray(start, start + 64).toString('utf8');
    return BigInt('0x' + hex);
  })();

  // -------- Witness assembly --------
  return {
    // 14 public inputs (canonical V5 spec §0.1 order).
    msgSender: msgSender.toString(),
    timestamp: tsValue,
    nullifier: nullifier.toString(),
    ctxHashHi: ctxHash.hi.toString(),
    ctxHashLo: ctxHash.lo.toString(),
    bindingHashHi: bindingHash.hi.toString(),
    bindingHashLo: bindingHash.lo.toString(),
    signedAttrsHashHi: saHash.hi.toString(),
    signedAttrsHashLo: saHash.lo.toString(),
    leafTbsHashHi: leafTbsHash.hi.toString(),
    leafTbsHashLo: leafTbsHash.lo.toString(),
    policyLeafHash: policyLeafHash.toString(),
    leafSpkiCommit: leafSpkiCommit.toString(),
    intSpkiCommit: intSpkiCommit.toString(),

    // Binding parser inputs (§6.2).
    bindingBytes: rightPadZero(input.bindingBytes, MAX_BCANON),
    bindingLength: input.bindingBytes.length,
    bindingPaddedIn: rightPadZero(bindingPadded, MAX_BCANON),
    bindingPaddedLen: bindingPadded.length,
    pkValueOffset: offsets.pkValueOffset,
    schemeValueOffset: offsets.schemeValueOffset,
    assertionsValueOffset: offsets.assertionsValueOffset,
    statementSchemaValueOffset: offsets.statementSchemaValueOffset,
    nonceValueOffset: offsets.nonceValueOffset,
    ctxValueOffset: offsets.ctxValueOffset,
    ctxHexLen: offsets.ctxHexLen,
    policyIdValueOffset: offsets.policyIdValueOffset,
    policyIdLen: offsets.policyIdLen,
    policyLeafHashValueOffset: offsets.policyLeafHashValueOffset,
    policyBindingSchemaValueOffset: offsets.policyBindingSchemaValueOffset,
    policyVersionValueOffset: offsets.policyVersionValueOffset,
    policyVersionDigitCount: offsets.policyVersionDigitCount,
    tsValueOffset: offsets.tsValueOffset,
    tsDigitCount: offsets.tsDigitCount,
    versionValueOffset: offsets.versionValueOffset,
    nonceBytesIn: Array.from(nonceBytesIn),
    policyIdBytesIn: rightPadZero(policyIdBytesIn, MAX_POLICY_ID),
    policyVersionIn: policyVersionIn,

    // §6.3 / §6.4 inputs.
    signedAttrsBytes: rightPadZero(input.signedAttrsDer, MAX_SA),
    signedAttrsLength: input.signedAttrsDer.length,
    signedAttrsPaddedIn: rightPadZero(saPadded, MAX_SA),
    signedAttrsPaddedLen: saPadded.length,
    mdAttrOffset: input.signedAttrsMdOffset,
    leafTbsBytes: rightPadZero(leafTbsBuf, MAX_LEAF_TBS),
    leafTbsLength: leafTbsBuf.length,
    leafTbsPaddedIn: rightPadZero(leafTbsPadded, MAX_LEAF_TBS),
    leafTbsPaddedLen: leafTbsPadded.length,

    // §6.5 — limb inputs (consumed by 2× SpkiCommit instances).
    leafXLimbs: leafXLimbs.map((x) => x.toString()),
    leafYLimbs: leafYLimbs.map((y) => y.toString()),
    intXLimbs: intXLimbs.map((x) => x.toString()),
    intYLimbs: intYLimbs.map((y) => y.toString()),

    // §6.6 — leaf cert walker output.
    leafCertBytes: rightPadZero(input.leafCertDer, MAX_CERT),
    subjectSerialValueOffset: subjectSerial.offset,
    subjectSerialValueLength: subjectSerial.length,
    subjectSerialValueOffsetInTbs,

    // §6.7 — ctx canonical-padded SHA inputs.
    ctxPaddedIn: rightPadZero(ctxPaddedBuf, MAX_CTX_PADDED),
    ctxPaddedLen: ctxPaddedBuf.length,

    // §6.8 — pkX/pkY limbs (Secp256k1PkMatch repacks parser.pkBytes into these).
    pkX: pkX.map((x) => x.toString()),
    pkY: pkY.map((y) => y.toString()),
  };
}

// Re-exports for ergonomic consumer code.
export { parseP7s } from './parse-p7s';
export { extractBindingOffsets } from './binding-offsets';
export { findTbsInCert, findSubjectSerial } from './leaf-cert-walk';
export { pkCoordToLimbs, subjectSerialBytesToLimbs } from './limbs';
export type {
  BuildWitnessV5Input,
  CmsExtraction,
  V2CoreBindingOffsets,
  WitnessV5,
} from './types';
export {
  MAX_BCANON,
  MAX_CERT,
  MAX_CTX,
  MAX_CTX_PADDED,
  MAX_LEAF_TBS,
  MAX_POLICY_ID,
  MAX_SA,
} from './types';
