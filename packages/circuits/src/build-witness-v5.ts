// V5.2 witness builder — production entry point.
//
// Consumes pre-extracted CMS / fixture artifacts (signedAttrs DER, leaf
// cert DER, leaf/intermediate SPKIs, JCS-canonicalized binding bytes,
// wallet-bound secret) and emits a JSON witness that
// `snarkjs.wtns.calculate` can hand directly to the V5.2 main circuit's
// witness-calculator wasm.
//
// Output ordering matches QKBPresentationV5.circom's input declaration
// order — the 22 public inputs (timestamp → bindingPkYLo, V5.2 spec
// §"Public-signal layout") followed by every private witness input the
// circuit consumes (including the V5.1 `walletSecret`).
//
// V5.1 → V5.2 changes in this file:
//   - DROPPED: `msgSender` from public-signals output (no longer a
//     circuit public signal — keccak-derived contract-side from the
//     new bindingPk limbs).
//   - DROPPED: `pkX` / `pkY` private witness inputs (V5.1's 4×64-bit
//     Secp256k1PkMatch limbs — gone with the in-circuit keccak chain).
//   - ADDED: 4 public-signal limb fields `bindingPkXHi`/`Lo` +
//     `bindingPkYHi`/`Lo`, packed big-endian from `parser.pkBytes[1..65]`
//     in 16-byte chunks. These are the cross-package handshake with
//     contracts-eng's keccak gate — bytes-identical to V5.1's
//     Secp256k1PkMatch input bytes, just packed at 128-bit instead of
//     64-bit granularity.
//
// Cross-package contract:
//   - web-eng's witness builder (browser-side) and this CLI MUST produce
//     byte-identical witnesses for the same input artifacts. The
//     integration test in test/integration/build-witness-v5.test.ts
//     asserts byte-identity against the existing `buildV5SmokeWitness`
//     test helper — keep them in sync.
//   - The 22-field public-signal layout is FROZEN per V5.2 spec
//     `2026-05-01-keccak-on-chain-amendment.md`; adding/reordering
//     fields here ≡ a cross-worker breaking change.

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
import { subjectSerialBytesToLimbs } from './limbs';
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
 *   §6.8  V5.2 wallet-pk limb packing — Bits2Num over parser.pkBytes[1..65]
 *         into 4 × 128-bit big-endian public-signal limbs (bindingPkX/Y
 *         Hi/Lo). Contract reconstructs + keccaks + checks msg.sender.
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

  // V5.3 F1 — OID-anchor offset (private witness input).  The value-
  // offset above points at the bytes AFTER the `06 03 55 04 05 <13|0c> NN`
  // ASN.1 frame inside the subject.serialNumber AttributeTypeAndValue.
  // The frame is 7 bytes (5 OID bytes + 1 string-tag + 1 length), so
  // the OID-offset is exactly value-offset − 7.  No parser change
  // needed; the X.509 walker already locates the value bytes
  // (subjectSerial.offset).  See V5.3 spec §F1.2 + §F1.5.
  //
  // The §6.9b in-circuit gate verifies the bytes at this offset spell
  // `06 03 55 04 05 <0x13|0x0c> NN`, anchoring the value-offset to a
  // real subject.serialNumber attribute frame and closing the V5.2
  // Sybil vector.
  const subjectSerialOidOffsetInTbs = subjectSerialValueOffsetInTbs - 7;

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

  // -------- §6.8 — V5.2 wallet-pk limb packing (4 × 128-bit, big-endian) --------
  //
  // V5.1 derived msgSender in-circuit via Secp256k1PkMatch + keccak (~200K
  // constraints). V5.2 emits the binding's claimed pubkey as 4 × 128-bit
  // public-signal limbs and the contract reconstructs the 64-byte
  // uncompressed pk + runs keccak natively.
  //
  // Cross-package handshake (load-bearing):
  //   bindingPkXHi = bytes-to-bigint-BE(pkBytes[1..17])    // upper 16 bytes of X
  //   bindingPkXLo = bytes-to-bigint-BE(pkBytes[17..33])   // lower 16 bytes of X
  //   bindingPkYHi = bytes-to-bigint-BE(pkBytes[33..49])   // upper 16 bytes of Y
  //   bindingPkYLo = bytes-to-bigint-BE(pkBytes[49..65])   // lower 16 bytes of Y
  //
  // Contract reassembles via `(pkXHi << 128) | pkXLo` for X, same for Y,
  // concatenates `(0x04 || X || Y)` (the SEC1 prefix is contract-known
  // because the circuit asserts pkBytes[0] === 4) and keccaks. Identical
  // input bytes to V5.1's in-circuit keccak; identical address output.
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
  const bytesBeToBigInt = (slice: Buffer): bigint =>
    BigInt('0x' + (slice.length === 0 ? '0' : slice.toString('hex')));
  const bindingPkXHi = bytesBeToBigInt(pkBytes.subarray(1, 17));
  const bindingPkXLo = bytesBeToBigInt(pkBytes.subarray(17, 33));
  const bindingPkYHi = bytesBeToBigInt(pkBytes.subarray(33, 49));
  const bindingPkYLo = bytesBeToBigInt(pkBytes.subarray(49, 65));
  // V5.2: msgSender is no longer a circuit public signal. We still derive
  // the Ethereum address here for fixture-default convenience: under
  // register mode the contract enforces `rotationNewWallet == msg.sender`,
  // and tests want the witness's rotationNewWallet to match what
  // msg.sender will be when the proof is submitted (= keccak-derived
  // address from the binding's pk). The value is purely advisory at the
  // witness-builder layer; it does NOT bind any circuit constraint.
  const pkKeccak = Buffer.from(keccak_256(pkBytes.subarray(1, 65)));
  const fixtureDerivedAddress = BigInt(
    '0x' + pkKeccak.subarray(12, 32).toString('hex'),
  );

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

  // -------- V5.1 rotation-mode payload (V5.2 amendment: rotationNewWallet
  //                                       no longer constrained by circuit
  //                                       under register mode; contract
  //                                       enforces == msg.sender) --------
  // Defaults to register mode (rotationMode === 0). Under register mode the
  // in-circuit `ForceEqualIfEnabled` gate (V5.1's `oldCommitNoOp`) still
  // pins slot 16 == identityCommitment; the V5.1 `newWalletNoOp` gate
  // (`rotationNewWallet === msgSender`) was DROPPED in V5.2 because
  // msgSender is no longer a circuit public signal. Slot 17
  // (rotationNewWallet) is therefore a witness pass-through that the
  // contract enforces post-verifier. We default it to the binding-pk-
  // derived address so that test fixtures pre-match what msg.sender will
  // be when the proof is submitted on-chain. Under rotateWallet mode
  // (rotationMode === 1), the caller supplies the actual new wallet
  // address.
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
    return fixtureDerivedAddress;
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
    // 22 public inputs (canonical V5.2 order — V5.2 spec §"Public-signal
    // layout V5.1 (19) → V5.2 (22)", FROZEN).
    timestamp: tsValue,                              // [0]
    nullifier: nullifier.toString(),                 // [1]
    ctxHashHi: ctxHash.hi.toString(),                // [2]
    ctxHashLo: ctxHash.lo.toString(),                // [3]
    bindingHashHi: bindingHash.hi.toString(),        // [4]
    bindingHashLo: bindingHash.lo.toString(),        // [5]
    signedAttrsHashHi: saHash.hi.toString(),         // [6]
    signedAttrsHashLo: saHash.lo.toString(),         // [7]
    leafTbsHashHi: leafTbsHash.hi.toString(),        // [8]
    leafTbsHashLo: leafTbsHash.lo.toString(),        // [9]
    policyLeafHash: policyLeafHash.toString(),       // [10]
    leafSpkiCommit: leafSpkiCommit.toString(),       // [11]
    intSpkiCommit: intSpkiCommit.toString(),         // [12]
    // V5.1 amendment additions (slots 13-17 in V5.2 numbering).
    identityFingerprint: identityFingerprint.toString(),  // [13]
    identityCommitment: identityCommitment.toString(),    // [14]
    rotationMode: rotationMode,                            // [15]
    rotationOldCommitment: rotationOldCommitment.toString(), // [16]
    rotationNewWallet: rotationNewWallet.toString(),       // [17]
    // V5.2 amendment additions (slots 18-21) — wallet-pk limbs for
    // contract-side keccak gate. Big-endian, byte-identical to V5.1
    // Secp256k1PkMatch's input bytes (`parser.pkBytes[1..65]`), just
    // packed at 128-bit instead of 64-bit granularity.
    bindingPkXHi: bindingPkXHi.toString(),                 // [18]
    bindingPkXLo: bindingPkXLo.toString(),                 // [19]
    bindingPkYHi: bindingPkYHi.toString(),                 // [20]
    bindingPkYLo: bindingPkYLo.toString(),                 // [21]

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
    // V5.3 F1 — OID-anchor private input.
    subjectSerialOidOffsetInTbs,

    // §6.7 — ctx canonical-padded SHA inputs.
    ctxPaddedIn: rightPadZero(ctxPaddedBuf, MAX_CTX_PADDED),
    ctxPaddedLen: ctxPaddedBuf.length,

    // V5.2: pkX/pkY 4×64-bit limb private inputs from V5.1 are dropped.
    // The 4 × 128-bit public-signal limbs (bindingPkX/Y Hi/Lo above)
    // are constrained by Bits2Num packing of `parser.pkBytes[1..65]`
    // directly inside the circuit — no separate witness-side limb
    // decomposition required.

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
