// Real-Diia V4 UA-leaf E2E smoke — parses a live Diia `.p7s` + QKB/2.0
// binding, builds the 16-signal leaf witness, and runs snarkjs.groth16.fullProve
// against the ceremonied zkey. If `verified: true`, task #24 closes.
//
// Usage:
//   node scripts/smoke-ua-leaf-v4-real-diia.mjs \
//     --binding '/home/alikvovk/Downloads/binding.qkb(5).json' \
//     --p7s     '/home/alikvovk/Downloads/binding.qkb(5).json.p7s'
//
// Or with env vars:
//   QKB_BINDING=... QKB_P7S=... node scripts/smoke-ua-leaf-v4-real-diia.mjs

import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { buildPoseidon } from 'circomlibjs';
import * as asn1js from 'asn1js';
import { Certificate, ContentInfo, SignedData, SignerInfo } from 'pkijs';
import * as snarkjs from 'snarkjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, '..');
const WASM = join(
  PKG_ROOT,
  'build/ua-leaf/QKBPresentationEcdsaLeafV4_UA_js/QKBPresentationEcdsaLeafV4_UA.wasm',
);
const ZKEY = join(PKG_ROOT, 'build/ua-leaf/ua_leaf_final.zkey');
const VKEY = join(PKG_ROOT, 'build/ua-leaf/vkey.json');
const OUT_DIR = join(PKG_ROOT, 'fixtures/integration/ua-v4');

const MAX_BCANON = 1024;
const MAX_SA = 1536;
const MAX_CERT = 1536;
const MERKLE_DEPTH = 16;
const MAX_POLICY_ID = 128;

// -- CLI --------------------------------------------------------------------
const argv = process.argv.slice(2);
function argVal(flag, fallbackEnv) {
  const i = argv.indexOf(flag);
  if (i >= 0 && i + 1 < argv.length) return argv[i + 1];
  if (fallbackEnv && process.env[fallbackEnv]) return process.env[fallbackEnv];
  return null;
}
const BINDING_PATH = argVal('--binding', 'QKB_BINDING');
const P7S_PATH = argVal('--p7s', 'QKB_P7S');
const RS_BIN = argVal('--rapidsnark-bin', 'QKB_RAPIDSNARK_BIN')
  ?? '/tmp/rapidsnark-bin/rapidsnark-linux-x86_64-v0.0.8/bin/prover';
if (!BINDING_PATH || !P7S_PATH) {
  console.error('usage: node smoke-ua-leaf-v4-real-diia.mjs --binding <path> --p7s <path> [--rapidsnark-bin <path>]');
  process.exit(2);
}
if (!existsSync(RS_BIN)) {
  console.error(`rapidsnark binary not found at ${RS_BIN}. pass --rapidsnark-bin <path> or set QKB_RAPIDSNARK_BIN.`);
  process.exit(2);
}

// -- Byte helpers (copied from synthetic smoke) -----------------------------
function sha256Pad(data) {
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
function zeroPadTo(data, max) {
  if (data.length > max) throw new Error(`buf ${data.length} > max ${max}`);
  const out = new Array(max).fill(0);
  for (let i = 0; i < data.length; i++) out[i] = data[i];
  return out;
}
function bytes32ToLimbs643(bytes) {
  if (bytes.length !== 32) throw new Error('expected 32 bytes');
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]);
  const limbs = [];
  const MASK = (1n << 43n) - 1n;
  for (let i = 0; i < 6; i++) {
    limbs.push(v & MASK);
    v >>= 43n;
  }
  return limbs;
}
function pkCoordToLimbs(bytes) {
  if (bytes.length !== 32) throw new Error('expected 32 bytes');
  const limbs = [];
  for (let l = 0; l < 4; l++) {
    let acc = 0n;
    const off = (3 - l) * 8;
    for (let j = 0; j < 8; j++) acc = (acc << 8n) | BigInt(bytes[off + j]);
    limbs.push(acc);
  }
  return limbs;
}
function subjectSerialBytesToLimbs(bytes) {
  if (bytes.length > 32) throw new Error('serial > 32 bytes');
  const limbs = [0n, 0n, 0n, 0n];
  for (let l = 0; l < 4; l++) {
    let acc = 0n;
    for (let b = 7; b >= 0; b--) {
      const idx = l * 8 + b;
      const byte = idx < bytes.length ? BigInt(bytes[idx]) : 0n;
      acc = acc * 256n + byte;
    }
    limbs[l] = acc;
  }
  return limbs;
}
function digestToField(bytes) {
  if (bytes.length !== 32) throw new Error('expected 32 bytes');
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

let P;
async function poseidon(inputs) {
  if (!P) P = await buildPoseidon();
  return P.F.toObject(P(inputs.map((v) => P.F.e(v))));
}

// -- CAdES + cert parsing via pkijs -----------------------------------------
function bytesToArrayBuffer(u8) {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

/** Parse a `.p7s` and extract the fields we need for the V4 leaf circuit. */
function parseCades(p7sBytes) {
  const asn = asn1js.fromBER(bytesToArrayBuffer(p7sBytes));
  if (asn.offset === -1) throw new Error('CAdES: invalid BER');
  const contentInfo = new ContentInfo({ schema: asn.result });
  const signed = new SignedData({ schema: contentInfo.content });

  if (signed.signerInfos.length !== 1) {
    throw new Error(`expected 1 signerInfo, got ${signed.signerInfos.length}`);
  }
  const signer = signed.signerInfos[0];
  if (!signer.signedAttrs) throw new Error('CAdES: missing signedAttrs');

  // Re-tag signedAttrs SET OF from [0] IMPLICIT to 0x31 (SET) for signing.
  const saBer = signer.signedAttrs.toSchema().toBER(false);
  const saView = new Uint8Array(saBer);
  const signedAttrs = new Uint8Array(saView.length);
  signedAttrs.set(saView);
  signedAttrs[0] = 0x31; // force SET tag (was 0xa0 [0] IMPLICIT)

  const signatureValue = new Uint8Array(signer.signature.valueBlock.valueHexView);

  const leaf = signed.certificates?.find((c) => c instanceof Certificate);
  if (!leaf) throw new Error('CAdES: no leaf cert in SignedData');
  const leafDer = new Uint8Array(leaf.toSchema().toBER(false));

  return { leaf, leafDer, signedAttrs, signatureValue };
}

/** Extract P-256 SPKI X,Y from a pkijs Certificate. */
function extractSpkiXY(leaf) {
  const spki = leaf.subjectPublicKeyInfo;
  const pubkeyBytes = new Uint8Array(spki.subjectPublicKey.valueBlock.valueHexView);
  if (pubkeyBytes.length !== 65 || pubkeyBytes[0] !== 0x04) {
    throw new Error(`unexpected SPKI shape: len=${pubkeyBytes.length}, b0=${pubkeyBytes[0]?.toString(16)}`);
  }
  return {
    X: Buffer.from(pubkeyBytes.subarray(1, 33)),
    Y: Buffer.from(pubkeyBytes.subarray(33, 65)),
  };
}

/** Find X and Y byte offsets of the SPKI point within the leaf cert DER. */
function findSpkiOffsetsInDer(leafDer, X, Y) {
  // SPKI point in DER is encoded as 03 42 00 04 <X 32> <Y 32> inside the
  // SubjectPublicKeyInfo BIT STRING. We locate the exact start of X by
  // finding the pattern [0x00, 0x04, X[0..4]] — the lead-in + X prefix.
  for (let i = 0; i < leafDer.length - 70; i++) {
    if (
      leafDer[i] === 0x00 &&
      leafDer[i + 1] === 0x04 &&
      leafDer[i + 2] === X[0] &&
      leafDer[i + 3] === X[1] &&
      leafDer[i + 4] === X[2]
    ) {
      const xOff = i + 2;
      const yOff = xOff + 32;
      // Verify full X + Y match.
      for (let k = 0; k < 32; k++) {
        if (leafDer[xOff + k] !== X[k]) return null;
        if (leafDer[yOff + k] !== Y[k]) return null;
      }
      return { xOff, yOff };
    }
  }
  return null;
}

/** Extract the subject.serialNumber RDN value bytes + byte offset inside leafDer. */
function findSubjectSerialNumber(leaf, leafDer) {
  // Subject is a SEQUENCE OF RelativeDistinguishedName, each RDN a SET OF
  // AttributeTypeAndValue. serialNumber OID is 2.5.4.5 (encoded 06 03 55 04 05).
  // Its value is a PrintableString (13 0x13) typically.
  const OID = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x05]);
  for (let i = 0; i < leafDer.length - OID.length - 2; i++) {
    let match = true;
    for (let k = 0; k < OID.length; k++) {
      if (leafDer[i + k] !== OID[k]) { match = false; break; }
    }
    if (!match) continue;
    // After OID: tag (PrintableString 0x13 or UTF8String 0x0c), length, value.
    const tag = leafDer[i + OID.length];
    const len = leafDer[i + OID.length + 1];
    if (tag !== 0x13 && tag !== 0x0c) continue;
    const valueOffset = i + OID.length + 2;
    return {
      valueOffset,
      valueLength: len,
      valueBytes: Buffer.from(leafDer.subarray(valueOffset, valueOffset + len)),
    };
  }
  throw new Error('subject.serialNumber not found in leaf DER');
}

/** Extract the binding.pk secp256k1 X,Y from the hex-encoded pk field. */
function extractBindingPkXY(pkHex) {
  if (!pkHex.startsWith('0x')) throw new Error('binding.pk must be 0x-prefixed');
  const bytes = Buffer.from(pkHex.slice(2), 'hex');
  if (bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new Error(`binding.pk unexpected shape: len=${bytes.length} b0=${bytes[0]}`);
  }
  return { X: bytes.subarray(1, 33), Y: bytes.subarray(33, 65) };
}

/** Find the offset of the 32-byte messageDigest VALUE inside the signedAttrs buffer. */
function findMdOffsetInSA(signedAttrs) {
  const needle = Buffer.from([
    // messageDigest OID 1.2.840.113549.1.9.4
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
    // SET (31) len (22) OCTET (04) len (20)
    0x31, 0x22, 0x04, 0x20,
  ]);
  const at = Buffer.from(signedAttrs).indexOf(needle);
  if (at < 0) throw new Error('messageDigest OID sequence not found in signedAttrs');
  return at + needle.length;
}

// -- Binding-offset scan (copied + adapted from synthetic smoke) ------------
function findOffset(buf, needle) {
  const n = Buffer.from(needle);
  outer: for (let i = 0; i + n.length <= buf.length; i++) {
    for (let j = 0; j < n.length; j++) if (buf[i + j] !== n[j]) continue outer;
    return i;
  }
  throw new Error(`offset not found: ${needle}`);
}
function scanBindingOffsets(binding) {
  const find = (lit) => findOffset(binding, lit) + Buffer.byteLength(lit);
  const pkValueOffset = find('"pk":"');
  const schemeValueOffset = find('"scheme":"');
  const statementSchemaValueOffset = find('"statementSchema":"');
  const nonceValueOffset = find('"nonce":"');
  const ctxValueOffset = find('"context":"');
  const policyIdValueOffset = find('"policyId":"');
  const policyLeafHashValueOffset = find('"leafHash":"');
  const policyBindingSchemaValueOffset = find('"bindingSchema":"');
  const versionValueOffset = find('"version":"');
  const policyVersionValueOffset = find('"policyVersion":');
  const tsValueOffset = find('"timestamp":');
  const assertionsValueOffset = find('"assertions":');

  const ctxAfterPrefix = ctxValueOffset + 2;
  let end = ctxAfterPrefix;
  while (end < binding.length && binding[end] !== 0x22) end++;
  const ctxHexLen = end - ctxAfterPrefix;

  end = policyIdValueOffset;
  while (end < binding.length && binding[end] !== 0x22) end++;
  const policyIdLen = end - policyIdValueOffset;

  end = policyVersionValueOffset;
  while (end < binding.length && binding[end] >= 0x30 && binding[end] <= 0x39) end++;
  const policyVersionDigitCount = end - policyVersionValueOffset;

  end = tsValueOffset;
  while (end < binding.length && binding[end] >= 0x30 && binding[end] <= 0x39) end++;
  const tsDigitCount = end - tsValueOffset;

  return {
    pkValueOffset, schemeValueOffset, assertionsValueOffset,
    statementSchemaValueOffset, nonceValueOffset, ctxValueOffset, ctxHexLen,
    policyIdValueOffset, policyIdLen, policyLeafHashValueOffset,
    policyBindingSchemaValueOffset, policyVersionValueOffset,
    policyVersionDigitCount, tsValueOffset, tsDigitCount, versionValueOffset,
  };
}

// -- Signature DER -> raw r,s ----------------------------------------------
function splitEcdsaSig(derSig) {
  // SEQUENCE { INTEGER r, INTEGER s }
  const bytes = Buffer.from(derSig);
  if (bytes[0] !== 0x30) throw new Error('ECDSA sig not a DER SEQUENCE');
  let p = 2;
  if (bytes[1] & 0x80) p += bytes[1] & 0x7f;
  if (bytes[p] !== 0x02) throw new Error('r INTEGER expected');
  const rLen = bytes[p + 1];
  let r = bytes.subarray(p + 2, p + 2 + rLen);
  p = p + 2 + rLen;
  if (bytes[p] !== 0x02) throw new Error('s INTEGER expected');
  const sLen = bytes[p + 1];
  let s = bytes.subarray(p + 2, p + 2 + sLen);
  if (r.length > 32 && r[0] === 0x00) r = r.subarray(1);
  if (s.length > 32 && s[0] === 0x00) s = s.subarray(1);
  const rPad = Buffer.alloc(32);
  const sPad = Buffer.alloc(32);
  r.copy(rPad, 32 - r.length);
  s.copy(sPad, 32 - s.length);
  return { r: rPad, s: sPad };
}

// -- DOB extraction: 2.5.29.9 → inner OID 1.2.804.2.1.1.1.11.1.4.11.1 → PrintableString
function extractDobYmd(leafDer) {
  // Outer OID 2.5.29.9: 06 03 55 1d 09
  const OUTER = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x09]);
  // Inner attr OID 1.2.804.2.1.1.1.11.1.4.11.1 (14 bytes incl TLV header):
  //   06 0c 2a 86 24 02 01 01 01 0b 01 04 0b 01
  const INNER = Buffer.from([0x06, 0x0c, 0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x0b, 0x01, 0x04, 0x0b, 0x01]);

  const outerAt = Buffer.from(leafDer).indexOf(OUTER);
  if (outerAt < 0) return { dobYmd: 0n, dobSupported: 0n };
  const innerAt = Buffer.from(leafDer).indexOf(INNER, outerAt);
  if (innerAt < 0) return { dobYmd: 0n, dobSupported: 0n };
  // After inner OID: expect PrintableString (0x13) length value "YYYYMMDD-NNNNN"
  // Typical Diia format: "YYYYMMDD-NNNNN" (9 or 15 chars).
  // The circuit interprets the first 8 ASCII digits as dobYmd.
  let p = innerAt + INNER.length;
  // May have a SET/SEQUENCE wrapper before the string.
  while (p < leafDer.length && leafDer[p] !== 0x13 && leafDer[p] !== 0x0c) p++;
  if (p >= leafDer.length) return { dobYmd: 0n, dobSupported: 0n };
  const tag = leafDer[p];
  const len = leafDer[p + 1];
  const valueBytes = leafDer.subarray(p + 2, p + 2 + len);
  // Parse first 8 ASCII digits.
  let dobYmd = 0n;
  for (let i = 0; i < 8 && i < valueBytes.length; i++) {
    const c = valueBytes[i];
    if (c < 0x30 || c > 0x39) return { dobYmd: 0n, dobSupported: 0n };
    dobYmd = dobYmd * 10n + BigInt(c - 0x30);
  }
  return { dobYmd, dobSupported: 1n, tag, stringValue: Buffer.from(valueBytes).toString('ascii') };
}

// -- Policy Merkle tree (single-leaf, depth 16) -----------------------------
// Canonical zero-hash convention — matches packages/web/src/lib/policyTree.ts
// and scripts/compute-policy-root.mjs:
//   zero[0] = 0
//   zero[i] = Poseidon(zero[i-1], zero[i-1])
// At level i the empty sibling is zero[i]. Using literal 0n at every level
// produces a non-canonical root that does NOT match what the web prover or
// on-chain policyRoot expect.
async function buildSingleLeafPolicyTree(leafHashField) {
  const zeros = new Array(MERKLE_DEPTH + 1);
  zeros[0] = 0n;
  for (let i = 1; i <= MERKLE_DEPTH; i++) {
    zeros[i] = await poseidon([zeros[i - 1], zeros[i - 1]]);
  }
  const path = new Array(MERKLE_DEPTH);
  const indices = new Array(MERKLE_DEPTH).fill(0);
  let cur = leafHashField;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    path[i] = zeros[i];
    cur = await poseidon([cur, zeros[i]]);
  }
  return { path, indices, root: cur };
}

// -- Main --------------------------------------------------------------------
async function main() {
  console.log('--- Real-Diia V4 UA-leaf smoke proof ---');
  console.log('binding :', BINDING_PATH);
  console.log('p7s     :', P7S_PATH);

  // Read real inputs
  const bindingBytes = readFileSync(BINDING_PATH);
  const p7sBytes = readFileSync(P7S_PATH);

  // Parse binding JSON (for pk + policy.leafHash + timestamp)
  const bindingObj = JSON.parse(bindingBytes.toString('utf8'));
  if (bindingObj.version !== 'QKB/2.0') {
    throw new Error(`binding.version must be QKB/2.0 (got ${bindingObj.version})`);
  }
  const { X: secpX, Y: secpY } = extractBindingPkXY(bindingObj.pk);
  const policyLeafHashHex = bindingObj.policy.leafHash.replace(/^0x/, '');
  const policyLeafHashBytes = Buffer.from(policyLeafHashHex, 'hex');
  const policyLeafHashField = digestToField(policyLeafHashBytes);
  const timestamp = bindingObj.timestamp;
  console.log('binding ok: version QKB/2.0, policyId=' + bindingObj.policy.policyId);

  // Parse CAdES
  const { leaf, leafDer, signedAttrs, signatureValue } = parseCades(p7sBytes);
  console.log('CAdES ok: leafDer', leafDer.length, 'B, signedAttrs', signedAttrs.length, 'B, sig', signatureValue.length, 'B');

  // Bind JSON sanity: bindingDigest matches messageDigest in signedAttrs
  const bindingDigest = createHash('sha256').update(bindingBytes).digest();
  const mdOffsetInSA = findMdOffsetInSA(signedAttrs);
  const mdInSA = Buffer.from(signedAttrs).subarray(mdOffsetInSA, mdOffsetInSA + 32);
  if (!mdInSA.equals(bindingDigest)) {
    throw new Error(
      `bindingDigest != messageDigest in signedAttrs\n` +
      `  expected: ${bindingDigest.toString('hex')}\n` +
      `  got:      ${mdInSA.toString('hex')}`
    );
  }
  console.log('messageDigest matches bindingDigest ✓');

  // Extract SPKI X,Y from leaf cert + locate in DER
  const { X: leafX, Y: leafY } = extractSpkiXY(leaf);
  const spkiOffsets = findSpkiOffsetsInDer(leafDer, leafX, leafY);
  if (!spkiOffsets) throw new Error('SPKI X/Y not found at expected offsets in leafDer');
  console.log('leaf SPKI X at', spkiOffsets.xOff, ', Y at', spkiOffsets.yOff);

  // Subject serial
  const serial = findSubjectSerialNumber(leaf, leafDer);
  console.log('subject.serialNumber:', serial.valueBytes.toString('ascii'), `(len ${serial.valueLength})`);

  // DOB extraction
  const dobInfo = extractDobYmd(leafDer);
  console.log('DOB: supported=' + dobInfo.dobSupported + ', ymd=' + dobInfo.dobYmd + (dobInfo.stringValue ? ' (raw="' + dobInfo.stringValue + '")' : ''));

  // Split ECDSA sig → r,s
  const { r: leafSigR, s: leafSigS } = splitEcdsaSig(signatureValue);

  // ECDSA public signals: pkX,pkY = secp256k1 from binding.pk
  const pkX = pkCoordToLimbs(secpX);
  const pkY = pkCoordToLimbs(secpY);
  const xLimbs = bytes32ToLimbs643(leafX);
  const yLimbs = bytes32ToLimbs643(leafY);
  const leafSpkiCommit = await poseidon([await poseidon(xLimbs), await poseidon(yLimbs)]);
  console.log('leafSpkiCommit:', leafSpkiCommit.toString());

  const ctxHash = 0n; // empty context (binding.context === "0x")
  const tree = await buildSingleLeafPolicyTree(policyLeafHashField);
  console.log('policyRoot (single-leaf):', tree.root.toString());

  // Nullifier = Poseidon(Poseidon(serial limbs || serialLen), ctxHash)
  const serialLimbs = subjectSerialBytesToLimbs(serial.valueBytes);
  const nullifierSecret = await poseidon([...serialLimbs, BigInt(serial.valueLength)]);
  const nullifier = await poseidon([nullifierSecret, ctxHash]);
  console.log('nullifier:', nullifier.toString());

  // DOB commit — circuit hard-codes sourceTag=1 regardless of support
  const dobCommit = await poseidon([dobInfo.dobYmd, 1n]);

  // Scan binding offsets
  const offsets = scanBindingOffsets(bindingBytes);

  // Build witness input
  const bcanonPadded = sha256Pad(bindingBytes);
  const saPadded = sha256Pad(signedAttrs);

  const policyIdBytes = new Array(MAX_POLICY_ID).fill(0);
  const policyIdSrc = Buffer.from(bindingObj.policy.policyId, 'ascii');
  for (let i = 0; i < policyIdSrc.length; i++) policyIdBytes[i] = policyIdSrc[i];

  const nonceHex = bindingObj.nonce.replace(/^0x/, '');
  const nonceBytes = Array.from(Buffer.from(nonceHex, 'hex'));
  while (nonceBytes.length < 32) nonceBytes.push(0);

  const input = {
    pkX: pkX.map(String), pkY: pkY.map(String),
    ctxHash: ctxHash.toString(),
    policyLeafHash: policyLeafHashField.toString(),
    policyRoot: tree.root.toString(),
    timestamp: timestamp.toString(),
    nullifier: nullifier.toString(),
    leafSpkiCommit: leafSpkiCommit.toString(),
    dobCommit: dobCommit.toString(),
    dobSupported: dobInfo.dobSupported.toString(),

    subjectSerialValueOffset: serial.valueOffset,
    subjectSerialValueLength: serial.valueLength,

    bindingCore: zeroPadTo(bindingBytes, MAX_BCANON),
    bindingCoreLen: bindingBytes.length,
    bindingCorePaddedIn: zeroPadTo(bcanonPadded, MAX_BCANON),
    bindingCorePaddedLen: bcanonPadded.length,
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
    nonceBytes,
    policyIdBytes,
    policyVersion: bindingObj.policy.policyVersion.toString(),

    signedAttrs: zeroPadTo(signedAttrs, MAX_SA),
    signedAttrsLen: signedAttrs.length,
    signedAttrsPaddedIn: zeroPadTo(saPadded, MAX_SA),
    signedAttrsPaddedLen: saPadded.length,
    mdOffsetInSA,

    leafDER: zeroPadTo(leafDer, MAX_CERT),
    leafDerLen: leafDer.length,
    leafSpkiXOffset: spkiOffsets.xOff,
    leafSpkiYOffset: spkiOffsets.yOff,
    leafSigR: bytes32ToLimbs643(leafSigR).map(String),
    leafSigS: bytes32ToLimbs643(leafSigS).map(String),

    policyMerklePath: tree.path.map(String),
    policyMerkleIndices: tree.indices.map(String),
  };

  // --- Rapidsnark prove path (snarkjs-fullProve replaced) -----------------
  //   step 1: snarkjs.wtns.calculate(input, wasm, wtnsPath) — cheap, <10s, <1GB
  //   step 2: spawn rapidsnark prover binary with (zkey, wtns, proof, public)
  //           — ~30–60 s for 6.38M constraints, peak RAM ~3–4 GB
  //   step 3: snarkjs.groth16.verify(vkey, public, proof) — verify locally
  const work = mkdtempSync(join(tmpdir(), 'qkb-real-diia-'));
  const wtnsPath = join(work, 'leaf.wtns');
  const rsProofPath = join(work, 'leaf.proof.json');
  const rsPublicPath = join(work, 'leaf.public.json');

  console.log('\n[leaf] snarkjs.wtns.calculate start');
  const twtns0 = Date.now();
  await snarkjs.wtns.calculate(input, WASM, wtnsPath);
  const twtns = ((Date.now() - twtns0) / 1000).toFixed(1);
  console.log(`[leaf] wtns.calculate done (${twtns}s)`);

  console.log(`[leaf] rapidsnark prove start (bin: ${RS_BIN})`);
  const tprv0 = Date.now();
  const rs = spawnSync(RS_BIN, [ZKEY, wtnsPath, rsProofPath, rsPublicPath], {
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  const tprv = ((Date.now() - tprv0) / 1000).toFixed(1);
  if (rs.status !== 0) {
    console.error(`rapidsnark exited ${rs.status}`);
    process.exit(1);
  }
  console.log(`[leaf] rapidsnark prove done (${tprv}s)`);

  const proof = JSON.parse(readFileSync(rsProofPath, 'utf8'));
  const publicSignals = JSON.parse(readFileSync(rsPublicPath, 'utf8'));

  const vkey = JSON.parse(readFileSync(VKEY, 'utf8'));
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  console.log('[leaf] verified:', ok);

  if (!ok) {
    console.error('VERIFY FAILED — not writing bundle');
    rmSync(work, { recursive: true, force: true });
    process.exit(1);
  }

  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(join(OUT_DIR, 'leaf-real-diia.proof.json'), JSON.stringify(proof, null, 2));
  writeFileSync(join(OUT_DIR, 'leaf-real-diia.public.json'), JSON.stringify(publicSignals, null, 2));

  // --- Proof bundle for forge test ---------------------------------------
  // Chain signals are stubbed (MockChainVerifier in the forge test accepts any
  // proof; the chain side is validated separately via V3 byte-identical reuse).
  // leafSpkiCommit must glue: chainSignals[2] === leafSignals[13].
  const bundle = {
    schema: 'qkb-v4-leaf-proof-bundle/v1',
    country: 'UA',
    trustedListRoot: '0x25ce7bfa7693e391a7e1d5df666caa5b622bf709cc6797289a74bfc272462b3e',
    policyRoot: '0x' + BigInt(tree.root).toString(16).padStart(64, '0'),
    leafProof: { pi_a: proof.pi_a, pi_b: proof.pi_b, pi_c: proof.pi_c },
    leafSignals: publicSignals,
    chainSignals: [
      '0x25ce7bfa7693e391a7e1d5df666caa5b622bf709cc6797289a74bfc272462b3e',
      '1',
      publicSignals[13],
    ],
    prover: { backend: 'rapidsnark', bin: RS_BIN },
    timing: { wtnsCalculateSec: twtns, proveSec: tprv },
  };
  writeFileSync(join(OUT_DIR, 'proof-bundle.json'), JSON.stringify(bundle, null, 2));

  console.log('\n--- ACK ---');
  console.log('public[12] nullifier    :', publicSignals[12]);
  console.log('public[14] dobCommit    :', publicSignals[14]);
  console.log('public[15] dobSupported :', publicSignals[15]);
  console.log('wtns wall               :', twtns, 's');
  console.log('prove wall (rapidsnark) :', tprv, 's');
  console.log('bundle                  :', join(OUT_DIR, 'proof-bundle.json'));

  rmSync(work, { recursive: true, force: true });
}

main().catch((e) => {
  console.error('real-diia smoke failed:', e);
  process.exit(1);
});
