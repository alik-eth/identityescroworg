import { expect } from 'chai';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, type CompiledCircuit } from '../helpers/compile';
import { rightPadZero, shaPad } from '../helpers/shaPad';
// keccak-from-pkBytes off-circuit reference. ethers v5 is already a
// transitive dep (used in @ethersproject/solidity downstream); using its
// keccak256 keeps the test surface consistent with web-eng's witness
// builder, which will also use ethers for address derivation.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { keccak256: ethersKeccak256 } = require('ethers/lib/utils');
import {
  buildV2CoreWitnessFromFixture,
  loadFixture,
  V2CORE_MAX_BCANON,
  V2CORE_MAX_POLICY_ID,
} from '../binding/v2core-witness';
import {
  decomposeTo643Limbs,
  parseP256Spki,
  spkiCommit,
} from '../../scripts/spki-commit-ref';
import { FINGERPRINT_DOMAIN, reduceTo254 } from '../../src/wallet-secret';

// V5.1 deterministic test wallet secret. Same byte pattern across all tests
// for fixture stability. After reduceTo254 the high 2 bits are masked, so
// the in-circuit Num2Bits(254) range check trivially passes.
const TEST_WALLET_SECRET = Buffer.alloc(32, 0x42);

// circomlibjs has no types; require-interop matches other tests in this package.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { buildPoseidon } = require('circomlibjs');

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

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');
const MAX_SA = 1536;
const MAX_LEAF_TBS = 1408;
const MAX_CERT = 2048;
const MAX_CTX_PADDED = 320;

/**
 * Find the subject.serialNumber RDN VALUE inside a leaf cert DER.
 *
 * OID 2.5.4.5 occurs in BOTH the issuer DN and the subject DN, in that
 * order within TBSCertificate. Real Diia issuer carries an EDRPOU-style
 * organizational serial (e.g. "UA-43395033-2311"); the subject carries the
 * natural-person semanticsIdentifier (ETSI EN 319 412-1 — e.g.
 * "TINUA-3627506575" for Ukrainian taxpayers).
 *
 * To pick the SUBJECT occurrence robustly we filter on the ETSI prefix —
 * any of `TINUA-`, `PNOUA-`, `PNODE-`, `PNOPL-`, `TINPL-`, `TINDE-`,
 * `IDC??-`, `PAS??-`, etc. (§5.1.3 of EN 319 412-1). Practically we accept
 * the canonical `TIN`/`PNO`/`IDC`/`PAS` country-prefixed string-with-dash
 * shape; if no such prefix is found we fall back to the SECOND occurrence
 * (issuer comes first, subject comes second in TBSCertificate field order).
 *
 * § Witness builder note: the production §7 build-witness-v5.ts will
 * replace this with a proper pkijs-based extractor; this is sufficient for
 * the §6.6 integration test against the admin-ecdsa real-Diia fixture.
 */
function findSubjectSerial(der: Buffer): { offset: number; length: number } {
  const OID = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x05]);
  const ETSI_PREFIXES = ['TIN', 'PNO', 'IDC', 'PAS', 'CPI'];
  type Hit = { offset: number; length: number; value: string };
  const hits: Hit[] = [];
  for (let i = 0; i < der.length - OID.length - 2; i++) {
    let match = true;
    for (let k = 0; k < OID.length; k++) {
      if (der[i + k] !== OID[k]) { match = false; break; }
    }
    if (!match) continue;
    const tag = der[i + OID.length] as number;
    const len = der[i + OID.length + 1] as number;
    if (tag !== 0x13 && tag !== 0x0c) continue;
    const offset = i + OID.length + 2;
    const value = der.subarray(offset, offset + len).toString('utf8');
    hits.push({ offset, length: len, value });
  }
  if (hits.length === 0) {
    throw new Error('subject.serialNumber OID not found in leaf DER');
  }
  // Prefer ETSI EN 319 412-1 prefix matches (subject's natural-person ID).
  for (const h of hits) {
    if (ETSI_PREFIXES.some((p) => h.value.startsWith(p))) {
      return { offset: h.offset, length: h.length };
    }
  }
  // Fallback: subject occurs after issuer in TBSCertificate, so take #2.
  if (hits.length >= 2) return { offset: hits[1]!.offset, length: hits[1]!.length };
  return { offset: hits[0]!.offset, length: hits[0]!.length };
}

/**
 * Pack up to 32 content bytes into 4 × uint64 LE limbs, byte-equivalent to
 * the X509SubjectSerial circom template's packing (§14 spec, line 105–113
 * of X509SubjectSerial.circom).
 */
function subjectSerialBytesToLimbs(bytes: Buffer): bigint[] {
  if (bytes.length > 32) throw new Error('subject serial > 32 bytes');
  const limbs: bigint[] = [0n, 0n, 0n, 0n];
  for (let l = 0; l < 4; l++) {
    let acc = 0n;
    for (let b = 7; b >= 0; b--) {
      const idx = l * 8 + b;
      const byte = idx < bytes.length ? BigInt(bytes[idx] as number) : 0n;
      acc = acc * 256n + byte;
    }
    limbs[l] = acc;
  }
  return limbs;
}

/**
 * Read a single ASN.1 length encoding starting at `der[off]`. Returns
 * `{ headerLen, contentLen }` where headerLen is the number of bytes
 * consumed (1 for short form, or 1+n for long-form `0x8n + n`).
 */
function readDerLength(der: Buffer, off: number): { headerLen: number; contentLen: number } {
  const b0 = der[off] as number;
  if (b0 < 0x80) return { headerLen: 1, contentLen: b0 };
  const n = b0 & 0x7f;
  let len = 0;
  for (let k = 1; k <= n; k++) len = (len << 8) | (der[off + k] as number);
  return { headerLen: 1 + n, contentLen: len };
}

/**
 * Locate the TBSCertificate sub-DER inside a leaf cert DER. The Certificate
 * structure is `SEQUENCE { tbsCertificate TBSCertificate, signatureAlgorithm,
 * signatureValue }`; tbsCertificate is the FIRST inner SEQUENCE, beginning
 * with its own `0x30 <length>` tag.
 *
 * Returns the offset of the TBS tag byte (`0x30`) within `der`, plus the
 * total TBS byte length (header + content). The TBS bytes therefore live
 * at `der.subarray(offset, offset + length)`.
 */
function findTbsInCert(der: Buffer): { offset: number; length: number } {
  if (der[0] !== 0x30) throw new Error('leaf cert is not a SEQUENCE');
  const outerLen = readDerLength(der, 1);
  const tbsTagOffset = 1 + outerLen.headerLen;
  if (der[tbsTagOffset] !== 0x30) {
    throw new Error('expected SEQUENCE tag for TBSCertificate');
  }
  const tbsLen = readDerLength(der, tbsTagOffset + 1);
  return {
    offset: tbsTagOffset,
    length: 1 + tbsLen.headerLen + tbsLen.contentLen,
  };
}

/**
 * Off-circuit reference for PoseidonChunkHashVar(MAX_CTX) when len === 0.
 * From the template: nChunks=0, nRounds=⌈(0+1)/15⌉=1, fe = [0×15] (slot 0
 * is `feLenProd[0] = (0==0)*0 = 0`; remaining slots are zero too because
 * no chunks exist). state_0 = 0; state_1 = Poseidon(16, [0×16]). The
 * synthetic admin-ecdsa fixture pins ctxHexLen=0 so this is the canonical
 * "empty ctx" hash that lands in nullifier derivation.
 */
async function poseidonChunkHashVarEmpty(): Promise<bigint> {
  // Poseidon(16) — circomlibjs's buildPoseidon supports arity up to 16
  // (the full set the circuit uses).
  return poseidonHash(new Array<bigint>(16).fill(0n));
}

// Synthetic CAdES messageDigest Attribute prefix (17 bytes). Same constant
// SignedAttrsParser.circom EXPECTED_PREFIX uses.
const MD_PREFIX = Buffer.from([
  0x30, 0x2f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
  0x31, 0x22, 0x04, 0x20,
]);
const SYNTH_MD_OFFSET = 60; // matches Diia's actual offset; keeps mdAttrOffset < 256

// `zeros` helper retired post-§6.8 — every formerly-zero-padded witness slot
// (leafCertBytes, pkX/pkY, etc.) is now bound to real-fixture values.

/**
 * Build a synthetic signedAttrs blob whose messageDigest at SYNTH_MD_OFFSET
 * is sha256(bindingBytes). The bytes before the messageDigest Attribute are
 * zero-padding; the parser only checks the 17-byte prefix at the witnessed
 * offset and reads 32 bytes of digest immediately after.
 *
 * Real Diia signedAttrs has additional Attributes (contentType,
 * signing-time, …) before/after; the parser doesn't care, only the
 * messageDigest extraction matters for §6.4.
 */
function buildSyntheticSignedAttrs(bindingDigest: Buffer): {
  bytes: Buffer;
  length: number;
  mdAttrOffset: number;
} {
  const length = SYNTH_MD_OFFSET + 17 + 32; // 109
  const bytes = Buffer.alloc(length);
  MD_PREFIX.copy(bytes, SYNTH_MD_OFFSET);
  bindingDigest.copy(bytes, SYNTH_MD_OFFSET + 17);
  return { bytes, length, mdAttrOffset: SYNTH_MD_OFFSET };
}

/**
 * Pack a 32-byte big-endian secp256k1 coordinate into 4 × uint64 limbs, in
 * the order Secp256k1PkMatch.circom expects (LE across limbs, BE within):
 *
 *   limb[3] = bytes[0..7]   (most-significant 64 bits)
 *   limb[2] = bytes[8..15]
 *   limb[1] = bytes[16..23]
 *   limb[0] = bytes[24..31] (least-significant 64 bits)
 *
 * Each limb is the BE concatenation of 8 bytes packed into a single uint64.
 */
function pkCoordToLimbs(bytes32: Buffer): bigint[] {
  if (bytes32.length !== 32) throw new Error('expected 32-byte coordinate');
  const limbs: bigint[] = [0n, 0n, 0n, 0n];
  for (let l = 0; l < 4; l++) {
    const off = (3 - l) * 8;
    let acc = 0n;
    for (let j = 0; j < 8; j++) acc = (acc << 8n) | BigInt(bytes32[off + j] as number);
    limbs[l] = acc;
  }
  return limbs;
}

/**
 * Build a minimal V5-main witness exercising §6.2-§6.9:
 *   §6.2 parser binds (timestamp + policyLeafHash)
 *   §6.3 three SHA-256 chains (binding, signedAttrs, leafTBS) + Bytes32ToHiLo
 *   §6.4 SignedAttrsParser + messageDigest === sha256(bindingBytes)
 *   §6.5 leafSpkiCommit + intSpkiCommit from real SPKI fixtures
 *   §6.6 X509SubjectSerial(leaf.der OID 2.5.4.5) + NullifierDerive
 *   §6.7 Sha256Var(parser.ctxBytes) + Bytes32ToHiLo → ctxHashHi/Lo
 *   §6.9 leafTbs ↔ leafCert byte-consistency over the subject-serial window
 *
 * leafTBS is now the REAL Diia leaf cert TBSCertificate (extracted from
 * leaf.der via the ASN.1 SEQUENCE walker above) — §6.9 requires the bytes
 * X509SubjectSerial reads from leafCertBytes to match leafTbsBytes at the
 * corresponding offset, which only holds if leafTbs is the genuine TBS.
 *
 * Public signals not yet wired (msgSender) stay anchored by _unusedHash;
 * §6.8 wires Secp256k1PkMatch + keccak256 → msgSender.
 */
async function buildV5SmokeWitness(): Promise<Record<string, unknown>> {
  const v2core = buildV2CoreWitnessFromFixture(FIXTURE_DIR);
  const fix = loadFixture(FIXTURE_DIR);
  const bindingBuf = readFileSync(resolve(FIXTURE_DIR, 'binding.qkb2.json'));

  // SHA-256 of the binding (the "bindingHash" public signal pair).
  const bindingDigest = createHash('sha256').update(bindingBuf).digest();
  const bindingHashHi = BigInt('0x' + bindingDigest.subarray(0, 16).toString('hex'));
  const bindingHashLo = BigInt('0x' + bindingDigest.subarray(16, 32).toString('hex'));
  const bindingPadded = shaPad(bindingBuf);

  // Synthetic signedAttrs containing messageDigest = sha256(binding).
  const sa = buildSyntheticSignedAttrs(bindingDigest);
  const saDigest = createHash('sha256').update(sa.bytes).digest();
  const signedAttrsHashHi = BigInt('0x' + saDigest.subarray(0, 16).toString('hex'));
  const signedAttrsHashLo = BigInt('0x' + saDigest.subarray(16, 32).toString('hex'));
  const saPadded = shaPad(sa.bytes);

  // Real Diia leaf cert TBSCertificate — extracted from leaf.der via the
  // ASN.1 SEQUENCE walker. §6.9 byte-consistency requires leafTbsBytes to
  // be the GENUINE TBS so the bytes at subjectSerialValueOffsetInTbs match
  // the bytes X509SubjectSerial reads from leafCertBytes at
  // subjectSerialValueOffset. The SHA chain in §6.3 also moves to a real
  // value (sha256 of real TBS instead of the prior 64-byte stand-in).
  const leafDerForTbs = readFileSync(resolve(FIXTURE_DIR, 'leaf.der'));
  const tbsLoc = findTbsInCert(leafDerForTbs);
  const leafTbsBuf = leafDerForTbs.subarray(tbsLoc.offset, tbsLoc.offset + tbsLoc.length);
  const leafTbsDigest = createHash('sha256').update(leafTbsBuf).digest();
  const leafTbsHashHi = BigInt('0x' + leafTbsDigest.subarray(0, 16).toString('hex'));
  const leafTbsHashLo = BigInt('0x' + leafTbsDigest.subarray(16, 32).toString('hex'));
  const leafTbsPadded = shaPad(leafTbsBuf);

  const policyLeafHash = BigInt('0x' + fix.expected.policyLeafHashHex);

  // §6.5 — real SPKI fixtures (leaf + intermediate from admin-ecdsa).
  // SpkiCommit() inside the circuit consumes the 6×43-bit LE limb
  // decomposition; the public-signal binding asserts equality with the
  // off-circuit `spkiCommit(spki)` reference value.
  const leafSpki = readFileSync(resolve(FIXTURE_DIR, 'leaf-spki.bin'));
  const intSpki = readFileSync(resolve(FIXTURE_DIR, 'intermediate-spki.bin'));
  const { x: leafX, y: leafY } = parseP256Spki(leafSpki);
  const { x: intX, y: intY } = parseP256Spki(intSpki);
  const leafXLimbs = decomposeTo643Limbs(leafX);
  const leafYLimbs = decomposeTo643Limbs(leafY);
  const intXLimbs = decomposeTo643Limbs(intX);
  const intYLimbs = decomposeTo643Limbs(intY);
  const leafSpkiCommit = await spkiCommit(leafSpki);
  const intSpkiCommit = await spkiCommit(intSpki);

  // §6.6 — Real Diia leaf cert (subject serialNumber = "TINUA-3627506575",
  // 16 bytes per ETSI EN 319 412-1). Walk the DER for OID 2.5.4.5, pack the
  // VALUE bytes into 4 × uint64 LE limbs, then derive the nullifier as
  // Poseidon₂(Poseidon₅(limbs+len), ctxHash) where ctxHash is the
  // field-domain PoseidonChunkHashVar over the parser's ctxBytes/ctxLen.
  // Fixture pins ctxHexLen=0, so ctxHash = Poseidon(16, [0×16]).
  const leafDer = readFileSync(resolve(FIXTURE_DIR, 'leaf.der'));
  const subjectSerial = findSubjectSerial(leafDer);
  const subjectSerialBytes = leafDer.subarray(
    subjectSerial.offset,
    subjectSerial.offset + subjectSerial.length,
  );
  const subjectSerialLimbs = subjectSerialBytesToLimbs(Buffer.from(subjectSerialBytes));
  // §6.9 — same subject-serial bytes within the TBS sub-DER. Offset is the
  // in-cert offset minus the TBS-tag offset (TBS lives at [tbsLoc.offset,
  // tbsLoc.offset + tbsLoc.length) inside leafDer).
  const subjectSerialValueOffsetInTbs = subjectSerial.offset - tbsLoc.offset;
  const ctxHashField = await poseidonChunkHashVarEmpty();
  // V5.1 wallet-bound nullifier construction (replaces V5's Poseidon₂(secret, ctxHash)):
  //   subjectPack          = Poseidon₅(serialLimbs[0..3], serialLen)  (was: secret)
  //   identityFingerprint  = Poseidon₂(subjectPack, FINGERPRINT_DOMAIN)
  //   identityCommitment   = Poseidon₂(subjectPack, walletSecret)
  //   nullifier            = Poseidon₂(walletSecret, ctxHashField)
  const subjectPack = await poseidonHash([
    ...subjectSerialLimbs,
    BigInt(subjectSerial.length),
  ]);
  const walletSecretField = reduceTo254(TEST_WALLET_SECRET);
  const expectedIdentityFingerprint = await poseidonHash([subjectPack, FINGERPRINT_DOMAIN]);
  const expectedIdentityCommitment = await poseidonHash([subjectPack, walletSecretField]);
  const expectedNullifier = await poseidonHash([walletSecretField, ctxHashField]);

  // §6.7 — Byte-domain SHA over parser.ctxBytes / parser.ctxLen. The
  // synthetic admin-ecdsa fixture pins ctxHexLen=0 → parser emits ctxLen=0
  // and ctxBytes all zeros, so the digest is sha256("") = e3b0c4...b855.
  // Canonical padding for an empty message is one 64-byte block:
  //   [0x80, 0x00 × 55, 0x00 × 8 (length trailer = 0)].
  const ctxPlain = Buffer.alloc(0);
  const ctxDigest = createHash('sha256').update(ctxPlain).digest();
  const ctxHashHi = BigInt('0x' + ctxDigest.subarray(0, 16).toString('hex'));
  const ctxHashLo = BigInt('0x' + ctxDigest.subarray(16, 32).toString('hex'));
  const ctxPaddedBuf = shaPad(ctxPlain);

  // §6.8 — Bind msg.sender to the binding's `pk` field (signed-over by
  // Diia). The fixture's pk is `0x04 || 0x11×32 || 0x22×32` (synthetic
  // SEC1-uncompressed admin-ecdsa key); decode → split into X (32) || Y
  // (32) → pack as 4×64-bit limbs (LE across limbs, BE within) for the
  // Secp256k1PkMatch witness side. msgSender = uint160(keccak256(pk[1:65])).
  const bindingObj = JSON.parse(bindingBuf.toString('utf8'));
  if (!bindingObj.pk || typeof bindingObj.pk !== 'string') {
    throw new Error('binding.qkb2.json: missing/non-string pk field');
  }
  const pkHex = (bindingObj.pk as string).startsWith('0x')
    ? (bindingObj.pk as string).slice(2)
    : (bindingObj.pk as string);
  const pkBytes = Buffer.from(pkHex, 'hex');
  if (pkBytes.length !== 65 || pkBytes[0] !== 0x04) {
    throw new Error('binding.pk must be 65-byte SEC1 uncompressed (0x04 || X || Y)');
  }
  const pkX = pkCoordToLimbs(pkBytes.subarray(1, 33));
  const pkY = pkCoordToLimbs(pkBytes.subarray(33, 65));
  const addrHex = ethersKeccak256(pkBytes.subarray(1, 65)) as string;
  const expectedMsgSender = BigInt('0x' + addrHex.slice(2 + 24));

  return {
    // 19 public inputs (canonical V5.1 order — orchestration §1.1, FROZEN).
    msgSender: expectedMsgSender,                  // §6.8
    timestamp: fix.expected.timestamp,             // §6.2
    nullifier: expectedNullifier,                  // §6.6 (V5.1: walletSecret-based)
    ctxHashHi,                                     // §6.7
    ctxHashLo,                                     // §6.7
    bindingHashHi,                                  // §6.3
    bindingHashLo,                                  // §6.3
    signedAttrsHashHi,                              // §6.3
    signedAttrsHashLo,                              // §6.3
    leafTbsHashHi,                                  // §6.3
    leafTbsHashLo,                                  // §6.3
    policyLeafHash,                                 // §6.2
    leafSpkiCommit,                                 // §6.5
    intSpkiCommit,                                  // §6.5
    // V5.1 additions (slots 14-18).
    identityFingerprint: expectedIdentityFingerprint,
    identityCommitment: expectedIdentityCommitment,
    rotationMode: 0n,                              // register-mode default
    rotationOldCommitment: expectedIdentityCommitment, // no-op under register
    rotationNewWallet: expectedMsgSender,              // no-op under register

    // Parser inputs (§6.2).
    bindingBytes: v2core.bytes,
    bindingLength: v2core.bcanonLen,
    bindingPaddedIn: rightPadZero(bindingPadded, V2CORE_MAX_BCANON),
    bindingPaddedLen: bindingPadded.length,
    pkValueOffset: v2core.pkValueOffset,
    schemeValueOffset: v2core.schemeValueOffset,
    assertionsValueOffset: v2core.assertionsValueOffset,
    statementSchemaValueOffset: v2core.statementSchemaValueOffset,
    nonceValueOffset: v2core.nonceValueOffset,
    ctxValueOffset: v2core.ctxValueOffset,
    ctxHexLen: v2core.ctxHexLen,
    policyIdValueOffset: v2core.policyIdValueOffset,
    policyIdLen: v2core.policyIdLen,
    policyLeafHashValueOffset: v2core.policyLeafHashValueOffset,
    policyBindingSchemaValueOffset: v2core.policyBindingSchemaValueOffset,
    policyVersionValueOffset: v2core.policyVersionValueOffset,
    policyVersionDigitCount: v2core.policyVersionDigitCount,
    tsValueOffset: v2core.tsValueOffset,
    tsDigitCount: v2core.tsDigitCount,
    versionValueOffset: v2core.versionValueOffset,
    nonceBytesIn: v2core.nonceBytesIn,
    policyIdBytesIn: v2core.policyIdBytesIn,
    policyVersionIn: v2core.policyVersionIn,

    // §6.3 / §6.4 inputs.
    signedAttrsBytes: rightPadZero(sa.bytes, MAX_SA),
    signedAttrsLength: sa.length,
    signedAttrsPaddedIn: rightPadZero(saPadded, MAX_SA),
    signedAttrsPaddedLen: saPadded.length,
    mdAttrOffset: sa.mdAttrOffset,

    leafTbsBytes: rightPadZero(leafTbsBuf, MAX_LEAF_TBS),
    leafTbsLength: leafTbsBuf.length,
    leafTbsPaddedIn: rightPadZero(leafTbsPadded, MAX_LEAF_TBS),
    leafTbsPaddedLen: leafTbsPadded.length,

    // §6.5 limb inputs — real fixtures (consumed by SpkiCommit instances).
    leafXLimbs,
    leafYLimbs,
    intXLimbs,
    intYLimbs,

    // §6.6 — Real Diia leaf cert + subject-serial walker output.
    leafCertBytes: rightPadZero(leafDer, MAX_CERT),
    subjectSerialValueOffset: subjectSerial.offset,
    subjectSerialValueLength: subjectSerial.length,
    // §6.9 — same serial offset measured from the start of TBSCertificate.
    subjectSerialValueOffsetInTbs,

    // §6.7 — ctx canonical-padded SHA inputs.
    ctxPaddedIn: rightPadZero(ctxPaddedBuf, MAX_CTX_PADDED),
    ctxPaddedLen: ctxPaddedBuf.length,

    // §6.8 — pkX/pkY limbs of the binding's wallet pubkey (Secp256k1PkMatch
    // asserts they repack identically to parser.pkBytes; Secp256k1AddressDerive
    // separately hashes parser.pkBytes[1..65] and binds to msgSender public).
    pkX: pkX.map((x) => x.toString()),
    pkY: pkY.map((y) => y.toString()),

    // V5.1 — wallet-bound nullifier secret (private input, range-checked
    // in-circuit via Num2Bits(254)).
    walletSecret: walletSecretField,
    // V5.1 — old-wallet-secret witness. Under register mode (rotationMode=0)
    // this is unconstrained (gate OFF); use the same value as walletSecret for
    // fixture stability. Range-checked in-circuit via Num2Bits(254).
    oldWalletSecret: walletSecretField,
  };
}

describe('QKBPresentationV5 — §6.2-§6.9 (full body — parser + 4× SHA + 2× SpkiCommit + nullifier + ctxHash + tbs↔cert + msgSender via keccak)', function () {
  this.timeout(1800000);

  let circuit: CompiledCircuit;

  before(async () => {
    circuit = await compile('QKBPresentationV5.circom');
  });

  it('compiles + accepts the QKB/2.0 fixture witness with all wired binds satisfied', async () => {
    const input = await buildV5SmokeWitness();
    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    // Sanity on what we passed in (the real soundness comes from the constraints).
    expect(input.timestamp).to.equal(1777478400);
    expect((input.policyLeafHash as bigint).toString(16)).to.equal(
      '2d00e73da8dd4dc99f04371d3ce01ecbcf4ad8e476c9017a304c57873494f812',
    );
  });

  // §6.6 happy-path — assert subject-serial extraction yields the correct
  // limbs against the real Diia leaf cert ("TINUA-3627506575") and the
  // public nullifier matches the off-circuit Poseidon derivation.
  it('extracts the real Diia subject serial into expected LE limbs (§6.6)', async () => {
    const leafDer = readFileSync(resolve(FIXTURE_DIR, 'leaf.der'));
    const ss = findSubjectSerial(leafDer);
    const bytes = Buffer.from(leafDer.subarray(ss.offset, ss.offset + ss.length));
    expect(bytes.toString('utf8')).to.equal('TINUA-3627506575');
    expect(ss.length).to.equal(16);

    // 16 bytes pack into limbs[0]+limbs[1] (8 bytes each LE), limbs[2..3] = 0.
    const limbs = subjectSerialBytesToLimbs(bytes);
    // "TINUA-36" → bytes 0x54 0x49 0x4E 0x55 0x41 0x2D 0x33 0x36, LE-packed:
    //   limb[0] = 0x36332D41554E4954
    expect(limbs[0]).to.equal(0x36332D41554E4954n);
    // "27506575" → 0x32 0x37 0x35 0x30 0x36 0x35 0x37 0x35
    //   limb[1] = 0x3537353630353732
    expect(limbs[1]).to.equal(0x3537353630353732n);
    expect(limbs[2]).to.equal(0n);
    expect(limbs[3]).to.equal(0n);
  });

  it('derives the expected nullifier from real Diia subject serial + empty ctx (§6.6)', async () => {
    const input = await buildV5SmokeWitness();
    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    // V5.1 off-circuit recomputation must equal the witnessed public signal:
    //   nullifier = Poseidon₂(walletSecret, ctxHash)   [V5.1, wallet-bound]
    // (V5 was Poseidon₂(Poseidon₅(serialLimbs, len), ctxHash) — pre-amendment.)
    const ctxHash = await poseidonChunkHashVarEmpty();
    const walletSecretField = reduceTo254(TEST_WALLET_SECRET);
    const expectedNullifier = await poseidonHash([walletSecretField, ctxHash]);
    expect(input.nullifier).to.equal(expectedNullifier);
  });

  it('rejects a tampered nullifier public signal (§6.6)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = { ...input, nullifier: (input.nullifier as bigint) + 1n };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a tampered subjectSerialValueLength while keeping the public nullifier (§6.6)', async () => {
    // Length mismatch breaks: (a) the limb packing (different masked bytes)
    // AND (b) the Poseidon-5 input (`subjectSerialLen` field changes), so
    // the derived nullifier no longer matches the witnessed public signal.
    const input = await buildV5SmokeWitness();
    const tampered = {
      ...input,
      subjectSerialValueLength: (input.subjectSerialValueLength as number) - 1,
    };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.2 tamper rejections
  it('rejects a tampered timestamp public signal (§6.2)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = { ...input, timestamp: 1777478401 };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a tampered policyLeafHash public signal (§6.2)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = {
      ...input,
      policyLeafHash: (input.policyLeafHash as bigint) + 1n,
    };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.3 tamper rejections — the SHA-chain binding is enforced via
  // bindingHashHi/Lo public-signal equality with Bytes32ToHiLo(sha256(bindingBytes)).
  it('rejects a tampered bindingHashHi public signal (§6.3)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = { ...input, bindingHashHi: (input.bindingHashHi as bigint) ^ 1n };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a tampered signedAttrsHashLo public signal (§6.3)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = {
      ...input,
      signedAttrsHashLo: (input.signedAttrsHashLo as bigint) ^ 1n,
    };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it('rejects a non-canonical bindingPaddedIn (§6.3 Sha256CanonPad)', async () => {
    const input = await buildV5SmokeWitness();
    // Flip the FIPS-required 0x80 marker byte at index dataLen (the byte
    // immediately after the message). Sha256CanonPad asserts paddedIn[dataLen] === 0x80;
    // changing it to anything else fails canonical-padding verification. Bytes
    // beyond paddedLen aren't checked, so we have to land within the active range.
    const dataLen = input.bindingLength as number;
    const tamperedPadded = [...(input.bindingPaddedIn as number[])];
    tamperedPadded[dataLen] = 0x81; // was 0x80 per FIPS canonical padding
    const tampered = { ...input, bindingPaddedIn: tamperedPadded };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.4 tamper rejection — the soundness chain. If signedAttrs.messageDigest
  // ≠ sha256(bindingBytes), the equality bindingDigestBytes[i] === saParser.messageDigestBytes[i]
  // must fail. This is THE load-bearing invariant for the §4 fixed-shape walker.
  it('rejects a signedAttrs whose messageDigest does not equal sha256(bindingBytes) (§6.4 — soundness chain)', async () => {
    const input = await buildV5SmokeWitness();
    // Flip one byte of the messageDigest content inside signedAttrsBytes.
    // The 32-byte content sits at SYNTH_MD_OFFSET + 17. Re-pad the SHA input
    // so the *bindingHash* public signal still matches (else we'd be testing
    // §6.3 instead of §6.4).
    const saBytes = [...(input.signedAttrsBytes as number[])];
    const mdContentStart = SYNTH_MD_OFFSET + 17;
    saBytes[mdContentStart] = ((saBytes[mdContentStart] as number) ^ 0xff) & 0xff;
    // Recompute SA padded form + hash so §6.3 stays satisfied; only the
    // §6.4 messageDigest === bindingHash equality is the failing constraint.
    const tamperedSaBuf = Buffer.from(saBytes.slice(0, input.signedAttrsLength as number));
    const tamperedSaDigest = createHash('sha256').update(tamperedSaBuf).digest();
    const tamperedSaPadded = shaPad(tamperedSaBuf);
    const tampered = {
      ...input,
      signedAttrsBytes: rightPadZero(tamperedSaBuf, MAX_SA),
      signedAttrsPaddedIn: rightPadZero(tamperedSaPadded, MAX_SA),
      signedAttrsPaddedLen: tamperedSaPadded.length,
      // Re-supply the matching new SA hash so §6.3 doesn't fire instead.
      signedAttrsHashHi: BigInt('0x' + tamperedSaDigest.subarray(0, 16).toString('hex')),
      signedAttrsHashLo: BigInt('0x' + tamperedSaDigest.subarray(16, 32).toString('hex')),
    };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.5 tamper rejection — flipping any single limb of leafXLimbs while
  // keeping leafSpkiCommit at the original Poseidon₂(Poseidon₆(X), Poseidon₆(Y))
  // breaks the public-signal binding. This catches silent SPKI substitution
  // (the contract-side spkiCommit-from-DER and the circuit-side
  // spkiCommit-from-limbs MUST agree on identical inputs).
  it('rejects a tampered leafXLimbs[0] while keeping leafSpkiCommit (§6.5)', async () => {
    const input = await buildV5SmokeWitness();
    const tamperedLimbs = [...(input.leafXLimbs as bigint[])];
    tamperedLimbs[0] = (tamperedLimbs[0] as bigint) + 1n;
    const tampered = { ...input, leafXLimbs: tamperedLimbs };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.7 happy-path — for empty ctx (ctxLen=0), digest is sha256("") =
  // e3b0c44298fc1c149afbf4c8996fb924 27ae41e4649b934ca495991b7852b855.
  it('binds ctxHashHi/Lo to sha256(empty) for the ctxLen=0 fixture (§6.7)', async () => {
    const input = await buildV5SmokeWitness();
    expect((input.ctxHashHi as bigint).toString(16).padStart(32, '0'))
      .to.equal('e3b0c44298fc1c149afbf4c8996fb924');
    expect((input.ctxHashLo as bigint).toString(16).padStart(32, '0'))
      .to.equal('27ae41e4649b934ca495991b7852b855');
  });

  // §6.7 tamper — flipping the public ctxHashHi while keeping the parser's
  // ctxBytes / canonical-pad witness must fail (Bytes32ToHiLo equality
  // constraint binds the SHA output to the public signal).
  it('rejects a tampered ctxHashHi public signal (§6.7)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = { ...input, ctxHashHi: (input.ctxHashHi as bigint) ^ 1n };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.7 tamper — non-canonical ctxPaddedIn (flip the FIPS 0x80 marker)
  // must fail Sha256CanonPad's shape constraint.
  it('rejects a non-canonical ctxPaddedIn (§6.7 Sha256CanonPad)', async () => {
    const input = await buildV5SmokeWitness();
    const dataLen = 0; // parser.ctxLen for the admin-ecdsa fixture
    const tamperedPadded = [...(input.ctxPaddedIn as number[])];
    tamperedPadded[dataLen] = 0x81; // FIPS-180-4 requires 0x80 here
    const tampered = { ...input, ctxPaddedIn: tamperedPadded };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.9 tamper — flip a byte of leafTbsBytes inside the cross-checked
  // serial-region window. The byte-equality gate should fire under the
  // active mask (i < subjectSerialValueLength). Recompute the leafTbsHash
  // off-circuit so §6.3 stays satisfied; the §6.9 byte-equality is the
  // failing constraint. (Without re-pad, §6.3 Sha256CanonPad would fail
  // first and we'd be testing the wrong gate.)
  it('rejects a leafTbsBytes byte flip inside the subject-serial window (§6.9)', async () => {
    const input = await buildV5SmokeWitness();
    const offsetInTbs = input.subjectSerialValueOffsetInTbs as number;
    const flipPos = offsetInTbs + 0; // first serial byte
    const tamperedTbs = [...(input.leafTbsBytes as number[])];
    tamperedTbs[flipPos] = ((tamperedTbs[flipPos] as number) ^ 0xff) & 0xff;
    // Recompute SHA + canonical pad over the tampered TBS so §6.3 still
    // passes; the only failing constraint should be the §6.9 byte-equality.
    const tbsLen = input.leafTbsLength as number;
    const tamperedTbsBuf = Buffer.from(tamperedTbs.slice(0, tbsLen));
    const tamperedDigest = createHash('sha256').update(tamperedTbsBuf).digest();
    const tamperedPadded = shaPad(tamperedTbsBuf);
    const tampered = {
      ...input,
      leafTbsBytes: tamperedTbs,
      leafTbsPaddedIn: rightPadZero(tamperedPadded, MAX_LEAF_TBS),
      leafTbsPaddedLen: tamperedPadded.length,
      leafTbsHashHi: BigInt('0x' + tamperedDigest.subarray(0, 16).toString('hex')),
      leafTbsHashLo: BigInt('0x' + tamperedDigest.subarray(16, 32).toString('hex')),
    };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.9 — wrong subjectSerialValueOffsetInTbs must fail (the bytes at
  // a different leafTbs offset won't match leafCert's serial bytes).
  it('rejects a wrong subjectSerialValueOffsetInTbs (§6.9)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = {
      ...input,
      subjectSerialValueOffsetInTbs:
        (input.subjectSerialValueOffsetInTbs as number) + 1,
    };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.8 happy-path — assert the witnessed msgSender matches the off-circuit
  // address derivation `keccak256(parser.pkBytes[1..65])[12..32]`.
  it('derives msgSender from the binding pk via keccak256 (§6.8)', async () => {
    const input = await buildV5SmokeWitness();
    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);
    // Synthetic admin-ecdsa fixture pk = 0x04 || 0x11×32 || 0x22×32. Derive
    // address off-circuit and verify the witness matches.
    const pkUncompressed = Buffer.concat([
      Buffer.alloc(32, 0x11),
      Buffer.alloc(32, 0x22),
    ]);
    const expectedAddrHex = ethersKeccak256(pkUncompressed).slice(2 + 24);
    expect((input.msgSender as bigint).toString(16).padStart(40, '0'))
      .to.equal(expectedAddrHex);
  });

  // §6.8 tamper — flip a limb of pkX. The Secp256k1PkMatch limb-equality
  // with parser.pkBytes (extracted from binding) fails on any single-limb
  // mismatch.
  it('rejects a tampered pkX[0] (§6.8 Secp256k1PkMatch)', async () => {
    const input = await buildV5SmokeWitness();
    const pkXTampered = [...(input.pkX as string[])];
    pkXTampered[0] = (BigInt(pkXTampered[0] as string) + 1n).toString();
    const tampered = { ...input, pkX: pkXTampered };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // §6.8 tamper — flip the public msgSender signal. The keccak256
  // chain (Secp256k1AddressDerive) outputs an address that no longer
  // matches the witnessed public signal.
  it('rejects a tampered msgSender public signal (§6.8 keccak link)', async () => {
    const input = await buildV5SmokeWitness();
    const tampered = { ...input, msgSender: (input.msgSender as bigint) ^ 1n };
    let threw = false;
    try {
      await circuit.calculateWitness(tampered, true);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // Suppress unused-import lint; reserved for §6.6+ wiring.
  void V2CORE_MAX_POLICY_ID;
});
