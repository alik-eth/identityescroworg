// V5.1 witness builder — production entry point.
//
// Consumes pre-extracted CMS / fixture artifacts (signedAttrs DER, leaf
// cert DER, leaf/intermediate SPKIs, JCS-canonicalized binding bytes,
// wallet-bound secret) and emits a JSON witness that
// `snarkjs.wtns.calculate` can hand directly to the V5.1 main circuit's
// witness-calculator wasm.
//
// Output ordering matches QKBPresentationV5.circom's input declaration
// order — the 19 public inputs (msgSender → rotationNewWallet,
// orchestration §1.1) followed by every private witness input the
// circuit consumes (including the new V5.1 `walletSecret`).
//
// Cross-package contract:
//   - web-eng's witness builder (browser-side) and this CLI MUST produce
//     byte-identical witnesses for the same input artifacts. The
//     integration test in test/integration/build-witness-v5.test.ts
//     asserts byte-identity against the existing `buildV5SmokeWitness`
//     test helper — keep them in sync.
//   - The 19-field public-signal layout is FROZEN per orchestration
//     §1.1 (commit 7f5c517); adding/reordering fields here ≡ a
//     cross-worker breaking change.

import { Buffer } from 'node:buffer';
// Browser-isomorphic hash primitives. @noble/hashes works identically in
// Node + browser bundlers without polyfill (vs. node:crypto which needs
// `crypto-browserify` shimming, and vs. ethers/lib/utils which would
// drag the entire ethers v5 bundle into the SDK). Web-eng's vendored
// copy at arch-web/sdk/src/witness/v5/ runs a SHA-256 fingerprint
// drift-check against this file; keep imports isomorphic — see
// CLAUDE.md V5.10.
// `@noble/hashes` v2 ships an explicit exports map requiring the `.js`
// suffix on every subpath. TS resolves this via the package's typings;
// the `.js` is mandatory at runtime under Node ESM and modern bundlers.
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

import { extractBindingOffsets } from './binding-offsets';
import { findSubjectSerial, findTbsInCert } from './leaf-cert-walk';
import { pkCoordToLimbs, subjectSerialBytesToLimbs } from './limbs';
import {
  poseidon2,
  poseidon5,
  poseidonChunkHashVar,
} from './poseidon-chunk-hash';
import { FINGERPRINT_DOMAIN, reduceTo254 } from './wallet-secret';
// scripts/spki-commit-ref.ts hosts the canonical SpkiCommit TS reference
// (parity-fixture-gated against the circom template + Solidity at §9.1).
import {
  decomposeTo643Limbs,
  parseP256Spki,
  spkiCommit,
} from '../scripts/spki-commit-ref';
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

function digestHiLo(digest: Buffer): { hi: bigint; lo: bigint } {
  if (digest.length !== 32) {
    throw new Error(`digestHiLo: expected 32-byte digest, got ${digest.length}`);
  }
  return {
    hi: BigInt('0x' + digest.subarray(0, 16).toString('hex')),
    lo: BigInt('0x' + digest.subarray(16, 32).toString('hex')),
  };
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
  // BindingParseV2CoreFast asserts a slim subset of binding fields by
  // value (nonce hex, policyId bytes, policyVersion). We extract those
  // bytes from `bindingBytes` using the offsets we just walked.
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
  const bindingDigest = Buffer.from(sha256(input.bindingBytes));
  const bindingHash = digestHiLo(bindingDigest);
  const bindingPadded = shaPad(input.bindingBytes);

  const saDigest = Buffer.from(sha256(input.signedAttrsDer));
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
  const leafTbsDigest = Buffer.from(sha256(leafTbsBuf));
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

  // -------- §6.6 — V5.1 wallet-bound nullifier construction --------
  //
  // Replaces V5's `NullifierDerive(subjectSerial-derived-secret, ctxHash)` with:
  //   subjectPack         = Poseidon₅(subjectSerialLimbs[0..3], subjectSerialLen)
  //   identityFingerprint = Poseidon₂(subjectPack, FINGERPRINT_DOMAIN)
  //   identityCommitment  = Poseidon₂(subjectPack, walletSecret)
  //   nullifier           = Poseidon₂(walletSecret, ctxHashField)
  //
  // walletSecret is provided by the caller as 32 bytes (HKDF-SHA256 for EOA,
  // Argon2id for SCW — see `src/wallet-secret.ts`); we reduce it to a 254-bit
  // field element to match the in-circuit Num2Bits(254) range check.
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

  // V5.1 walletSecret reduction.
  if (input.walletSecret.length !== 32) {
    throw new Error(
      `walletSecret must be 32 bytes (got ${input.walletSecret.length})`,
    );
  }
  const walletSecretField = reduceTo254(input.walletSecret);

  // V5.1 oldWalletSecret — required when rotationMode === 1 (proves prior-wallet
  // ownership). Under register mode (default), defaults to walletSecret since
  // the in-circuit gate is OFF; any in-range value works.
  const oldWalletSecretBuf = input.oldWalletSecret ?? input.walletSecret;
  if (oldWalletSecretBuf.length !== 32) {
    throw new Error(
      `oldWalletSecret must be 32 bytes (got ${oldWalletSecretBuf.length})`,
    );
  }
  const oldWalletSecretField = reduceTo254(oldWalletSecretBuf);

  // subjectSerialPacked — shared across 3 downstream Poseidon₂ outputs.
  const subjectPack = await poseidon5([
    ...subjectSerialLimbs,
    BigInt(subjectSerial.length),
  ]);

  const identityFingerprint = await poseidon2(subjectPack, FINGERPRINT_DOMAIN);
  const identityCommitment = await poseidon2(subjectPack, walletSecretField);
  const nullifier = await poseidon2(walletSecretField, ctxHashField);

  // -------- §6.7 — Byte-domain SHA over ctx --------
  const ctxDigest = Buffer.from(sha256(ctxBytes));
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
  // Ethereum address = keccak256(pk[1:65])[12:32] interpreted big-endian.
  const pkKeccak = Buffer.from(keccak_256(pkBytes.subarray(1, 65)));
  const msgSender = BigInt('0x' + pkKeccak.subarray(12, 32).toString('hex'));

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
    // policyLeafHash value is a hex string `"0x" + 64 chars`. We field-
    // encode it as `uint256(sha256(JCS(policyLeafObject))) mod p` — the
    // raw 32-byte hash interpreted as a single field element.
    const start = offsets.policyLeafHashValueOffset + 2; // skip "0x"
    const hex = input.bindingBytes.subarray(start, start + 64).toString('utf8');
    return BigInt('0x' + hex);
  })();

  // -------- V5.1 rotation-mode payload --------
  // Defaults to register mode (rotationMode === 0). Under register mode the
  // in-circuit `ForceEqualIfEnabled` gates pin slot 17 == identityCommitment
  // and slot 18 == msgSender; we set those values here so the no-op constraint
  // is trivially satisfied. Under rotateWallet mode (rotationMode === 1), the
  // caller supplies the actual prior commitment + new wallet address.
  const rotationMode = input.rotationMode ?? 0;
  const rotationOldCommitment = ((): bigint => {
    if (rotationMode === 1) {
      if (input.rotationOldCommitment === undefined) {
        throw new Error(
          'rotationMode=1 (rotateWallet) requires rotationOldCommitment',
        );
      }
      return typeof input.rotationOldCommitment === 'bigint'
        ? input.rotationOldCommitment
        : BigInt(input.rotationOldCommitment);
    }
    return identityCommitment;
  })();
  const rotationNewWallet = ((): bigint => {
    if (rotationMode === 1) {
      if (input.rotationNewWalletAddress === undefined) {
        throw new Error(
          'rotationMode=1 (rotateWallet) requires rotationNewWalletAddress',
        );
      }
      return typeof input.rotationNewWalletAddress === 'bigint'
        ? input.rotationNewWalletAddress
        : BigInt(input.rotationNewWalletAddress);
    }
    return msgSender;
  })();
  // Under rotation mode, oldWalletSecret is REQUIRED (input.oldWalletSecret
  // must be supplied and produce a commitment that opens to rotationOldCommitment;
  // the in-circuit ForceEqualIfEnabled gate will reject witnesses where
  // Poseidon₂(subjectPack, oldWalletSecret) !== rotationOldCommitment).
  if (rotationMode === 1 && input.oldWalletSecret === undefined) {
    throw new Error(
      'rotationMode=1 (rotateWallet) requires oldWalletSecret to prove old-wallet ownership',
    );
  }

  // -------- Witness assembly --------
  return {
    // 19 public inputs (canonical V5.1 order — orchestration §1.1, FROZEN).
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
    // V5.1 additions (slots 14-18).
    identityFingerprint: identityFingerprint.toString(),
    identityCommitment: identityCommitment.toString(),
    rotationMode: rotationMode,
    rotationOldCommitment: rotationOldCommitment.toString(),
    rotationNewWallet: rotationNewWallet.toString(),

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

    // V5.1 — wallet-bound nullifier secret (private, range-checked in-circuit).
    walletSecret: walletSecretField.toString(),
    // V5.1 — old-wallet-secret (private, only meaningfully constrained under
    // rotationMode === 1; under register mode the in-circuit gate is OFF).
    oldWalletSecret: oldWalletSecretField.toString(),
  };
}

// Re-exports for ergonomic consumer code.
export { parseP7s } from './parse-p7s';
export { extractBindingOffsets } from './binding-offsets';
export { findTbsInCert, findSubjectSerial } from './leaf-cert-walk';
export { pkCoordToLimbs, subjectSerialBytesToLimbs } from './limbs';
export {
  FINGERPRINT_DOMAIN,
  BN254_SCALAR_FIELD,
  reduceTo254,
  packFieldToBytes32,
} from './wallet-secret';
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
