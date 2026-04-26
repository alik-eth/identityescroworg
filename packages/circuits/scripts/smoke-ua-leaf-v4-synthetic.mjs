// M7.5 — V4 UA-leaf synthetic smoke proof (option 3 of the 2026-04-24 block).
//
// Goal: round-trip the UA-leaf ceremonied zkey + vkey with a witness that
// satisfies every V4 leaf constraint end-to-end. No Diia, no QTSP, no real
// .p7s — an ephemeral P-256 signer + a hand-crafted QKB/2.0 binding. If
// snarkjs.groth16.verify prints OK, the ceremony trio (wasm, zkey, vkey)
// is internally consistent.
//
// Constraints the synthetic witness satisfies:
//   * BindingParseV2Core: QKB/2.0 binding JSON with all required fields,
//     JCS-sorted, exact-literal assertions + statementSchema + policy.bindingSchema.
//   * sha256(bindingCore) == messageDigest inside signedAttrs at mdOffsetInSA.
//   * ECDSA-P256 over sha256(signedAttrs) verified by leaf SPKI (X,Y limbs).
//   * Policy Merkle inclusion: single-leaf tree at DEPTH 16, indices = all 0.
//   * ctxHash: empty context → ctxHash = 0.
//   * leafSpkiCommit = Poseidon(Poseidon(xLimbs), Poseidon(yLimbs)).
//   * Nullifier = Poseidon(Poseidon(serialLimbs ‖ serialLen), ctxHash).
//   * DobExtractorDiiaUA: no 2.5.29.9 outer OID in synthetic leaf DER →
//     dobSupported=0, dobYmd=0, sourceTag=1 (hardcoded), dobCommit=Poseidon(0,1).
//
// Output (committed under packages/circuits/fixtures/integration/ua-v4/):
//   - leaf-synthetic-qkb2.proof.json
//   - leaf-synthetic-qkb2.public.json
//   - README.md

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, generateKeyPairSync, createSign } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';

// ---------------------------------------------------------------------------
// Layout: this script is at .../packages/circuits/scripts/. Ceremony artifacts
// are under .../packages/circuits/build/ua-leaf/. Commit target is
// .../packages/circuits/fixtures/integration/ua-v4/.
// ---------------------------------------------------------------------------
const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, '..');
const WASM = join(
  PKG_ROOT,
  'build/ua-leaf/QKBPresentationEcdsaLeafV4_UA_js/QKBPresentationEcdsaLeafV4_UA.wasm',
);
const ZKEY = join(PKG_ROOT, 'build/ua-leaf/ua_leaf_final.zkey');
const VKEY = join(PKG_ROOT, 'build/ua-leaf/vkey.json');
const OUT_DIR = join(PKG_ROOT, 'fixtures/integration/ua-v4');

// ---------------------------------------------------------------------------
// Circuit caps — MUST match the on-circuit var declarations.
// ---------------------------------------------------------------------------
const MAX_BCANON = 1024;
const MAX_SA = 1536;
const MAX_CERT = 1536;
const MERKLE_DEPTH = 16;
const MAX_POLICY_ID = 128;

// ---------------------------------------------------------------------------
// Byte helpers.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Poseidon (matches circuit: Poseidon-6 for limbs, Poseidon-2 for pair-up,
// Poseidon-5 for serial ‖ len, Poseidon-2 for nullifier, Poseidon-2 for
// Merkle, Poseidon-2 for dobCommit).
// ---------------------------------------------------------------------------
let P;
async function poseidon(inputs) {
  if (!P) P = await buildPoseidon();
  return P.F.toObject(P(inputs.map((v) => P.F.e(v))));
}

// ---------------------------------------------------------------------------
// 1. Generate an ephemeral P-256 keypair (for the leaf/CMS signer).
// ---------------------------------------------------------------------------
function generateP256Keypair() {
  const kp = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spkiDer = kp.publicKey.export({ format: 'der', type: 'spki' });
  // Standard SPKI shape for ecPublicKey P-256:
  //   30 59 30 13 06 07 2A8648CE3D0201 06 08 2A8648CE3D030107
  //   03 42 00 04 <X 32> <Y 32>
  // So X starts at offset 27, Y at offset 59 within the SPKI DER.
  if (spkiDer.length !== 91 || spkiDer[26] !== 0x04) {
    throw new Error('unexpected P-256 SPKI shape: ' + spkiDer.toString('hex'));
  }
  const X = Buffer.from(spkiDer.subarray(27, 59));
  const Y = Buffer.from(spkiDer.subarray(59, 91));
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, X, Y };
}

// ---------------------------------------------------------------------------
// 2. Generate an ephemeral secp256k1 keypair (for the binding `pk` field).
//    The V4 leaf only checks parser(pk) == pkX/pkY public-input limbs —
//    no signature with this key. So any valid pair works.
// ---------------------------------------------------------------------------
function generateSecp256k1Keypair() {
  const kp = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const spkiDer = kp.publicKey.export({ format: 'der', type: 'spki' });
  // secp256k1 SPKI is the same shape (ecPublicKey, 88 bytes: shorter curve OID).
  // We don't actually need the DER, only the X,Y.
  // Extract by looking for the 0x04 uncompressed marker then 64 bytes.
  let idx = -1;
  for (let i = 1; i + 65 <= spkiDer.length; i++) {
    if (spkiDer[i] === 0x04 && spkiDer[i - 1] === 0x00) {
      idx = i;
      break;
    }
  }
  if (idx < 0) throw new Error('secp256k1 uncompressed point not found');
  const X = Buffer.from(spkiDer.subarray(idx + 1, idx + 33));
  const Y = Buffer.from(spkiDer.subarray(idx + 33, idx + 65));
  return { X, Y };
}

// ---------------------------------------------------------------------------
// 3. Build a minimal "leaf DER" container — a byte buffer that holds the
//    P-256 X,Y at predictable offsets and a subject.serialNumber RDN TLV.
//    This is NOT a valid X.509 cert — the V4 leaf circuit only reads fixed
//    offsets, not the full ASN.1 structure.
//
// Layout (all other bytes zero):
//   bytes[0..15]   pad
//   bytes[16..47]  leafX (32 bytes)
//   bytes[48..79]  leafY (32 bytes)
//   bytes[80..91]  subject.serialNumber RDN TLV:
//                    06 03 55 04 05         (OID 2.5.4.5)
//                    13 0C "QKB-SMOKE-01"   (PrintableString, 12 bytes)
//   bytes[92..119] zero tail
//   leafDerLen = 120
// ---------------------------------------------------------------------------
function buildLeafDerContainer(X, Y) {
  const len = 120;
  const der = Buffer.alloc(len);
  X.copy(der, 16);
  Y.copy(der, 48);
  // 06 03 55 04 05 — OID 2.5.4.5 TLV at offset 80
  der[80] = 0x06;
  der[81] = 0x03;
  der[82] = 0x55;
  der[83] = 0x04;
  der[84] = 0x05;
  // 13 0C <12 bytes> — PrintableString "QKB-SMOKE-01" at offset 85
  der[85] = 0x13;
  der[86] = 0x0c;
  Buffer.from('QKB-SMOKE-01', 'ascii').copy(der, 87);
  return {
    der,
    derLen: len,
    leafSpkiXOffset: 16,
    leafSpkiYOffset: 48,
    subjectSerialValueOffset: 87,
    subjectSerialValueLength: 12,
  };
}

// ---------------------------------------------------------------------------
// 4. Build the QKB/2.0 binding JSON (JCS key-sort order, no whitespace,
//    lowercase hex).
// ---------------------------------------------------------------------------
function buildBindingCore({ secpX, secpY, nonce32, policyLeafHashHex }) {
  const pkHex = '04' + secpX.toString('hex') + secpY.toString('hex');
  const nonceHex = nonce32.toString('hex');
  const timestamp = 1776700000; // 2026-04-23ish UTC epoch, decimal
  // Build manually to guarantee JCS key order + no whitespace.
  // Required JCS order at top level:
  //   assertions < context < nonce < pk < policy < scheme < statementSchema < timestamp < version
  const assertions =
    '{"acceptsAttribution":true,"bindsContext":true,"keyControl":true,"revocationRequired":true}';
  const policy =
    `{"bindingSchema":"qkb-binding-core/v1",` +
    `"leafHash":"0x${policyLeafHashHex}",` +
    `"policyId":"qkb-smoke/v1",` +
    `"policyVersion":1}`;
  const json =
    `{"assertions":${assertions},` +
    `"context":"0x",` +
    `"nonce":"0x${nonceHex}",` +
    `"pk":"0x${pkHex}",` +
    `"policy":${policy},` +
    `"scheme":"secp256k1",` +
    `"statementSchema":"qkb-binding-core/v1",` +
    `"timestamp":${timestamp},` +
    `"version":"QKB/2.0"}`;
  return { jsonBytes: Buffer.from(json, 'utf8'), timestamp };
}

// ---------------------------------------------------------------------------
// 5. Scan the binding bytes for each required value offset. The circuit's
//    `valueOffset` points at the FIRST byte of the value content (NOT the
//    opening quote for string values, NOT the colon for integers).
// ---------------------------------------------------------------------------
function findOffset(buf, needle) {
  const n = Buffer.from(needle);
  outer: for (let i = 0; i + n.length <= buf.length; i++) {
    for (let j = 0; j < n.length; j++) if (buf[i + j] !== n[j]) continue outer;
    return i;
  }
  throw new Error(`offset not found: ${needle}`);
}
function scanBindingOffsets(binding) {
  // For each key literal, the circuit expects:
  //   - bytes[valueOffset - KEY_LEN .. valueOffset - 1] == KEY_LITERAL
  // where KEY_LITERAL includes the quote/colon terminator. For string
  // fields the key is '"K":"' — valueOffset points at the first content
  // byte (the '0' of "0x..." or the first letter). For number fields the
  // key is '"K":' — valueOffset points at the first digit.
  //
  // We scan for the key-literal and then add its length to get the
  // value-start offset.
  const find = (lit) => findOffset(binding, lit) + Buffer.byteLength(lit);
  // String-valued fields (append '"' after ':').
  const pkValueOffset = find('"pk":"');
  const schemeValueOffset = find('"scheme":"');
  const statementSchemaValueOffset = find('"statementSchema":"');
  const nonceValueOffset = find('"nonce":"');
  const ctxValueOffset = find('"context":"');
  const policyIdValueOffset = find('"policyId":"');
  const policyLeafHashValueOffset = find('"leafHash":"');
  const policyBindingSchemaValueOffset = find('"bindingSchema":"');
  const versionValueOffset = find('"version":"');
  // Number-valued fields (no trailing '"').
  const policyVersionValueOffset = find('"policyVersion":');
  const tsValueOffset = find('"timestamp":');
  // `assertions` value starts at the '{' after '":'.
  const assertionsValueOffset = find('"assertions":');

  // Lengths that circuit needs: ctxHexLen, policyIdLen, policyVersionDigitCount,
  // tsDigitCount.
  // ctx is "0x" + ctxHexLen hex chars: here "0x" with zero hex → ctxHexLen=0.
  const ctxAfterPrefix = ctxValueOffset + 2; // past "0x"
  let end = ctxAfterPrefix;
  while (end < binding.length && binding[end] !== 0x22) end++;
  const ctxHexLen = end - ctxAfterPrefix;

  // policyId length: content chars up to closing '"'.
  end = policyIdValueOffset;
  while (end < binding.length && binding[end] !== 0x22) end++;
  const policyIdLen = end - policyIdValueOffset;

  // policyVersion digits.
  end = policyVersionValueOffset;
  while (end < binding.length && binding[end] >= 0x30 && binding[end] <= 0x39) end++;
  const policyVersionDigitCount = end - policyVersionValueOffset;

  // timestamp digits.
  end = tsValueOffset;
  while (end < binding.length && binding[end] >= 0x30 && binding[end] <= 0x39) end++;
  const tsDigitCount = end - tsValueOffset;

  return {
    pkValueOffset,
    schemeValueOffset,
    assertionsValueOffset,
    statementSchemaValueOffset,
    nonceValueOffset,
    ctxValueOffset,
    ctxHexLen,
    policyIdValueOffset,
    policyIdLen,
    policyLeafHashValueOffset,
    policyBindingSchemaValueOffset,
    policyVersionValueOffset,
    policyVersionDigitCount,
    tsValueOffset,
    tsDigitCount,
    versionValueOffset,
  };
}

// ---------------------------------------------------------------------------
// 6. Build a minimal CMS signedAttrs. Three attributes in SET-OF order
//    (sorted by DER-encoded bytes per CMS rules, here alphabetical by OID):
//       - contentType (1.2.840.113549.1.9.3)  = id-data (1.2.840.113549.1.7.1)
//       - signingTime (1.2.840.113549.1.9.5)  = UTCTime "260424120000Z"
//       - messageDigest (1.2.840.113549.1.9.4) = OCTET STRING <sha256(bindingCore)>
//    Wrapped in SET tag 0x31 for signing (CAdES re-tags SET-OF from [0] IMPLICIT).
// ---------------------------------------------------------------------------
function der(tag, content) {
  const out = [tag];
  if (content.length < 0x80) {
    out.push(content.length);
  } else if (content.length < 0x100) {
    out.push(0x81, content.length);
  } else {
    out.push(0x82, (content.length >> 8) & 0xff, content.length & 0xff);
  }
  return Buffer.concat([Buffer.from(out), content]);
}
function buildSignedAttrs(bindingDigest) {
  // contentType attr:
  //   SEQUENCE {
  //     OID 1.2.840.113549.1.9.3
  //     SET { OID 1.2.840.113549.1.7.1 (id-data) }
  //   }
  const oidCT = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03]);
  const oidData = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]);
  const attrCT = der(0x30, Buffer.concat([oidCT, der(0x31, oidData)]));

  // signingTime attr:
  //   SEQUENCE { OID 1.2.840.113549.1.9.5, SET { UTCTime "260424120000Z" } }
  const oidST = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05]);
  const time = Buffer.from('260424120000Z', 'ascii');
  const attrST = der(0x30, Buffer.concat([oidST, der(0x31, der(0x17, time))]));

  // messageDigest attr:
  //   SEQUENCE { OID 1.2.840.113549.1.9.4, SET { OCTET STRING <32 bytes> } }
  const oidMD = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04]);
  const mdOctet = der(0x04, Buffer.from(bindingDigest));
  const attrMD = der(0x30, Buffer.concat([oidMD, der(0x31, mdOctet)]));

  // SET tag 0x31 is used when computing the signature over signedAttrs.
  // Per DER-SET-OF rules, the three attrs must be sorted by their DER-encoded
  // byte representation. Our three OIDs differ only in the last byte (3,5,4),
  // so the DER order is: 01 contentType (..03), 02 messageDigest (..04),
  // 03 signingTime (..05). That ordering is what we serialize.
  const setBody = Buffer.concat([attrCT, attrMD, attrST]);
  const signedAttrs = der(0x31, setBody);

  // Find the offset of the 32-byte messageDigest VALUE within signedAttrs.
  // Scan for the contentType MD OID followed by 31 22 04 20 <32 bytes>.
  const needle = Buffer.concat([
    oidMD,
    Buffer.from([0x31, 0x22, 0x04, 0x20]),
  ]);
  const at = signedAttrs.indexOf(needle);
  if (at < 0) throw new Error('messageDigest OID not found in signedAttrs');
  const mdOffsetInSA = at + needle.length;

  return { signedAttrs, mdOffsetInSA };
}

// ---------------------------------------------------------------------------
// 7. Sign sha256(signedAttrs) with the P-256 signer. Convert DER ECDSA
//    signature → raw (r,s) 32-byte each.
// ---------------------------------------------------------------------------
function signP256(privateKey, message) {
  const signer = createSign('sha256');
  signer.update(message);
  signer.end();
  const derSig = signer.sign(privateKey); // DER-encoded ECDSA sig
  // Parse DER: SEQUENCE { INTEGER r, INTEGER s }
  if (derSig[0] !== 0x30) throw new Error('not DER sig');
  let p = 2;
  if (derSig[1] & 0x80) p += derSig[1] & 0x7f;
  if (derSig[p] !== 0x02) throw new Error('r INTEGER expected');
  const rLen = derSig[p + 1];
  let r = derSig.subarray(p + 2, p + 2 + rLen);
  p = p + 2 + rLen;
  if (derSig[p] !== 0x02) throw new Error('s INTEGER expected');
  const sLen = derSig[p + 1];
  let s = derSig.subarray(p + 2, p + 2 + sLen);
  // Strip leading zero (DER INTEGER positive sign byte) if present.
  if (r.length > 32 && r[0] === 0x00) r = r.subarray(1);
  if (s.length > 32 && s[0] === 0x00) s = s.subarray(1);
  // Left-pad to 32.
  const rPad = Buffer.alloc(32);
  const sPad = Buffer.alloc(32);
  r.copy(rPad, 32 - r.length);
  s.copy(sPad, 32 - s.length);
  return { r: rPad, s: sPad };
}

// ---------------------------------------------------------------------------
// 8. Policy Merkle tree: single-leaf tree at DEPTH=16, leaf at index 0
//    (indices = all 0s), siblings = all 0s. Root = Poseidon-chain from leaf
//    up 16 levels, each combining (cur, 0).
// ---------------------------------------------------------------------------
async function buildSingleLeafPolicyTree(leafHashField) {
  const path = new Array(MERKLE_DEPTH).fill(0n);
  const indices = new Array(MERKLE_DEPTH).fill(0);
  let cur = leafHashField;
  for (let i = 0; i < MERKLE_DEPTH; i++) {
    // indices[i]=0 → cur is left, sibling is right.
    cur = await poseidon([cur, 0n]);
  }
  return { path, indices, root: cur };
}

// ---------------------------------------------------------------------------
// 9. Main.
// ---------------------------------------------------------------------------
async function main() {
  console.log('--- M7.5 synthetic V4 UA-leaf smoke proof ---');

  // 9.1 Synthesize keys, leaf DER, binding, signedAttrs, signature.
  const signer = generateP256Keypair();
  const secp = generateSecp256k1Keypair();
  const leaf = buildLeafDerContainer(signer.X, signer.Y);

  // Pick a random policy leaf hash in the BN254 field (reduce mod p by
  // trimming top bits). Simpler: use 32 random bytes and reduce by
  // taking them mod 2^254 (safely below p).
  // Use a 32-byte hash with top byte = 0x01 so the big-endian-packed value
  // is ~2^248, safely below the BN254 field modulus p ≈ 2^253.4.
  const policyLeafHashBytes = Buffer.from(
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    'hex',
  );
  policyLeafHashBytes[0] = 0x01;
  const policyLeafHashHex = policyLeafHashBytes.toString('hex');
  const policyLeafHashField = digestToField(policyLeafHashBytes);

  const nonce32 = Buffer.from(
    'deadbeefcafef00d0123456789abcdef0123456789abcdef0123456789abcdef',
    'hex',
  );
  const { jsonBytes: binding, timestamp } = buildBindingCore({
    secpX: secp.X,
    secpY: secp.Y,
    nonce32,
    policyLeafHashHex,
  });
  console.log('bindingLen:', binding.length);
  if (binding.length > MAX_BCANON) {
    throw new Error(`binding ${binding.length} > MAX_BCANON ${MAX_BCANON}`);
  }

  const offsets = scanBindingOffsets(binding);

  // bindingDigest = sha256(bindingCore).
  const bindingDigest = createHash('sha256').update(binding).digest();
  const { signedAttrs, mdOffsetInSA } = buildSignedAttrs(bindingDigest);
  console.log('signedAttrsLen:', signedAttrs.length, 'mdOffsetInSA:', mdOffsetInSA);

  // Sign signedAttrs with P-256 (createSign('sha256') does the inner
  // sha256 for us).
  const { r: leafSigR, s: leafSigS } = signP256(signer.privateKey, signedAttrs);

  // 9.2 Compute all Poseidon public signals off-circuit.
  const pkX = pkCoordToLimbs(secp.X);
  const pkY = pkCoordToLimbs(secp.Y);
  const xLimbs = bytes32ToLimbs643(signer.X);
  const yLimbs = bytes32ToLimbs643(signer.Y);
  const leafSpkiCommit = await poseidon([
    await poseidon(xLimbs),
    await poseidon(yLimbs),
  ]);
  console.log('leafSpkiCommit:', leafSpkiCommit.toString());

  const ctxHash = 0n; // empty ctx

  // Merkle root / path / indices.
  const tree = await buildSingleLeafPolicyTree(policyLeafHashField);
  console.log('policyRoot:', tree.root.toString());

  // Nullifier.
  const serialBytes = Buffer.from('QKB-SMOKE-01', 'ascii');
  const serialLimbs = subjectSerialBytesToLimbs(serialBytes);
  const secret = await poseidon([...serialLimbs, BigInt(serialBytes.length)]);
  const nullifier = await poseidon([secret, ctxHash]);
  console.log('nullifier:', nullifier.toString());

  // DOB: no 2.5.29.9 OID in synthetic leaf DER → dobSupported=0,
  // dobYmd=0, sourceTag=1. dobCommit = Poseidon(0, 1).
  const dobCommit = await poseidon([0n, 1n]);
  const dobSupported = 0n;

  // 9.3 Build witness input JSON.
  const bcanonPadded = sha256Pad(binding);
  const saPadded = sha256Pad(signedAttrs);

  // policyId bytes padded to 128.
  const policyIdBytes = new Array(MAX_POLICY_ID).fill(0);
  const policyIdSrc = Buffer.from('qkb-smoke/v1', 'ascii');
  for (let i = 0; i < policyIdSrc.length; i++) policyIdBytes[i] = policyIdSrc[i];

  // nonce bytes (32).
  const nonceBytes = Array.from(nonce32);

  const input = {
    // Public signals (16)
    pkX: pkX.map((v) => v.toString()),
    pkY: pkY.map((v) => v.toString()),
    ctxHash: ctxHash.toString(),
    policyLeafHash: policyLeafHashField.toString(),
    policyRoot: tree.root.toString(),
    timestamp: timestamp.toString(),
    nullifier: nullifier.toString(),
    leafSpkiCommit: leafSpkiCommit.toString(),
    dobCommit: dobCommit.toString(),
    dobSupported: dobSupported.toString(),

    // Private — nullifier extraction
    subjectSerialValueOffset: leaf.subjectSerialValueOffset,
    subjectSerialValueLength: leaf.subjectSerialValueLength,

    // Private — binding
    bindingCore: zeroPadTo(binding, MAX_BCANON),
    bindingCoreLen: binding.length,
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
    policyVersion: '1',

    // Private — signedAttrs
    signedAttrs: zeroPadTo(signedAttrs, MAX_SA),
    signedAttrsLen: signedAttrs.length,
    signedAttrsPaddedIn: zeroPadTo(saPadded, MAX_SA),
    signedAttrsPaddedLen: saPadded.length,
    mdOffsetInSA,

    // Private — leaf DER + sig
    leafDER: zeroPadTo(leaf.der, MAX_CERT),
    leafDerLen: leaf.derLen,
    leafSpkiXOffset: leaf.leafSpkiXOffset,
    leafSpkiYOffset: leaf.leafSpkiYOffset,
    leafSigR: bytes32ToLimbs643(leafSigR).map((v) => v.toString()),
    leafSigS: bytes32ToLimbs643(leafSigS).map((v) => v.toString()),

    // Private — policy Merkle
    policyMerklePath: tree.path.map((v) => v.toString()),
    policyMerkleIndices: tree.indices.map((v) => v.toString()),
  };

  // EXPORT_INPUT_ONLY=1 dumps the assembled `input` object as a committable
  // fixture and exits before the (~5-minute, build-artifact-dependent) prove.
  // Used to feed the browser wasm-prover benchmark without re-running the
  // synthetic key generation each time.
  if (process.env.EXPORT_INPUT_ONLY === '1') {
    mkdirSync(OUT_DIR, { recursive: true });
    const inputPath = join(OUT_DIR, 'leaf-synthetic-qkb2.input.json');
    writeFileSync(inputPath, JSON.stringify(input, null, 2));
    console.log('wrote', inputPath);
    process.exit(0);
  }

  // 9.4 fullProve (witness + prove + verify).
  console.log('calling snarkjs.groth16.fullProve — expect ~5 min for 6.38M constraints');
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const wall = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`fullProve wall: ${wall}s`);
  console.log('publicSignals:', publicSignals);

  const vkey = JSON.parse(readFileSync(VKEY, 'utf8'));
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  console.log('verified:', ok);
  if (!ok) {
    console.error('VERIFY FAILED — NOT committing fixture');
    process.exit(1);
  }

  // 9.5 Write KAT fixtures.
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(
    join(OUT_DIR, 'leaf-synthetic-qkb2.proof.json'),
    JSON.stringify(proof, null, 2),
  );
  writeFileSync(
    join(OUT_DIR, 'leaf-synthetic-qkb2.public.json'),
    JSON.stringify(publicSignals, null, 2),
  );
  console.log('wrote', OUT_DIR);

  // 9.6 Ack summary to stdout.
  const proofKeccak = createHash('sha256') // keccak isn't in node:crypto; sha256 is fine for smoke ack
    .update(JSON.stringify(proof))
    .digest('hex');
  console.log('\n--- ACK ---');
  console.log('public[12] nullifier:', publicSignals[12]);
  console.log('public[14] dobCommit:', publicSignals[14]);
  console.log('proof.json sha256 first-8:', proofKeccak.slice(0, 8));
  console.log('wall:', wall, 's');
  process.exit(0);
}

main().catch((e) => {
  console.error('smoke failed:', e);
  process.exit(1);
});
