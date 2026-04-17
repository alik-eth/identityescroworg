// Synthetic RSA-QES fixture builder.
//
// Produces the artifacts the QKBPresentationRsa main circuit needs for an
// end-to-end integration test, WITHOUT requiring a real EU QTSP. The
// construction mirrors a real detached CAdES-BES signature:
//
//   Intermediate CA   (self-signed, RSA-2048) → treated as the trusted-list
//                     listed CA (its canonicalized DER is the Merkle leaf).
//   Leaf certificate  (RSA-2048, signed by Intermediate) → the "user's QES
//                     signing certificate".
//   Detached CMS      SignedAttrs with contentType + messageDigest(Bcanon),
//                     signed by Leaf with RSA-PKCS1v1.5 / SHA-256.
//
// Outputs (committed under fixtures/integration/synth-rsa/):
//   binding.qkb.json            the JCS bytes being signed (admin binding)
//   intermediate.der            intermediate CA DER
//   leaf.der                    leaf cert DER
//   leaf.p7s                    detached CMS SignedData (.p7s shape)
//   fixture.json                all offsets + bytes needed by the circuit
//                               witness builder (modulus/exponent/TBS/sig/
//                               signedAttrs/messageDigest/Bcanon/field
//                               offsets), plus the single-leaf Merkle tree
//                               (depth 16) containing the intermediate.

import {
  Certificate,
  AttributeTypeAndValue,
  BasicConstraints,
  Extension,
  CryptoEngine,
  setEngine,
  SignedData,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  SignerInfo,
  SignedAndUnsignedAttributes,
  Attribute,
} from 'pkijs';
import { Integer, OctetString } from 'asn1js';
import { webcrypto } from 'node:crypto';
import { createHash } from 'node:crypto';
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { buildPoseidon } from 'circomlibjs';
import { Buffer } from 'node:buffer';

// =============================================================================
// Crypto engine bootstrap (Node's webcrypto satisfies pkijs).
// =============================================================================

const crypto = (webcrypto as unknown) as Crypto;
setEngine(
  'node',
  new CryptoEngine({ name: 'node', crypto, subtle: crypto.subtle }),
);

// =============================================================================
// Helpers
// =============================================================================

const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_DATA = '1.2.840.113549.1.7.1';

async function generateRsaKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: 'SHA-256' },
    } as RsaHashedKeyGenParams,
    true,
    ['sign', 'verify'],
  ) as Promise<CryptoKeyPair>;
}

function cnAttr(cn: string): AttributeTypeAndValue {
  return new AttributeTypeAndValue({
    type: '2.5.4.3',
    value: new (require('asn1js').Utf8String)({ value: cn }),
  });
}

async function buildCert(opts: {
  subjectCN: string;
  issuerCN: string;
  subjectKey: CryptoKeyPair;
  issuerPrivateKey: CryptoKey;
  isCA: boolean;
  serial: number;
}): Promise<Certificate> {
  const c = new Certificate();
  c.version = 2;
  c.serialNumber = new Integer({ value: opts.serial });
  c.issuer.typesAndValues.push(cnAttr(opts.issuerCN));
  c.subject.typesAndValues.push(cnAttr(opts.subjectCN));
  c.notBefore.value = new Date('2025-01-01T00:00:00Z');
  c.notAfter.value = new Date('2030-01-01T00:00:00Z');
  await c.subjectPublicKeyInfo.importKey(opts.subjectKey.publicKey);
  if (opts.isCA) {
    const basicConstraints = new BasicConstraints({ cA: true, pathLenConstraint: 0 });
    c.extensions = [
      new Extension({
        extnID: '2.5.29.19',
        critical: true,
        extnValue: basicConstraints.toSchema().toBER(false),
        parsedValue: basicConstraints,
      }),
    ];
  }
  await c.sign(opts.issuerPrivateKey, 'SHA-256');
  return c;
}

function derOf(cert: Certificate): Uint8Array {
  return new Uint8Array(cert.toSchema(true).toBER(false));
}

function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

// Find the first occurrence of a DER template pattern inside a buffer.
function findOffset(haystack: Uint8Array, needle: number[]): number {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

// Given an RSA SPKI region inside a DER cert, locate modulus + exponent
// offsets and return them.
function extractRsaSpki(der: Uint8Array, spkiStart: number): {
  modulusOffset: number;
  exponentOffset: number;
} {
  // Scan from spkiStart for `02 82 01 01 00 <256 bytes>`.
  let modOff = -1;
  for (let i = spkiStart; i + 5 + 256 <= der.length; i++) {
    if (
      der[i] === 0x02 &&
      der[i + 1] === 0x82 &&
      der[i + 2] === 0x01 &&
      der[i + 3] === 0x01 &&
      der[i + 4] === 0x00
    ) {
      modOff = i + 5;
      break;
    }
  }
  if (modOff < 0) throw new Error('modulus TLV not found');
  let expOff = -1;
  for (let i = modOff + 256; i + 5 <= der.length; i++) {
    if (
      der[i] === 0x02 &&
      der[i + 1] === 0x03 &&
      der[i + 2] === 0x01 &&
      der[i + 3] === 0x00 &&
      der[i + 4] === 0x01
    ) {
      expOff = i + 2;
      break;
    }
  }
  if (expOff < 0) throw new Error('exponent TLV not found');
  return { modulusOffset: modOff, exponentOffset: expOff };
}

// Extract tbsCertificate slice (DER encoding). The tbsCertificate is the
// first inner SEQUENCE of the top-level SEQUENCE.
function extractTbs(der: Uint8Array): { offset: number; length: number } {
  // der[0] = 0x30 (SEQUENCE), der[1..] = length. Parse outer length.
  if (der[0] !== 0x30) throw new Error('cert is not a SEQUENCE');
  let cursor = 1;
  const lb = der[cursor++]!;
  if (lb & 0x80) cursor += lb & 0x7f;
  // cursor now points at the first inner field (tbsCertificate).
  const tbsStart = cursor;
  if (der[cursor] !== 0x30) throw new Error('tbs is not a SEQUENCE');
  const tbsLb = der[cursor + 1]!;
  let tbsHeaderLen = 2;
  let tbsContentLen = 0;
  if (tbsLb & 0x80) {
    const nLenBytes = tbsLb & 0x7f;
    tbsHeaderLen = 2 + nLenBytes;
    for (let i = 0; i < nLenBytes; i++) {
      tbsContentLen = tbsContentLen * 256 + der[cursor + 2 + i]!;
    }
  } else {
    tbsContentLen = tbsLb;
  }
  return { offset: tbsStart, length: tbsHeaderLen + tbsContentLen };
}

// Extract the raw RSA-PKCS1v1.5 signature value from a cert's signatureValue
// BIT STRING. The cert is three top-level SEQUENCE elements: tbsCertificate,
// signatureAlgorithm, signatureValue (BIT STRING).
function extractCertSignature(der: Uint8Array): Uint8Array {
  const { offset: tbsOff, length: tbsLen } = extractTbs(der);
  const afterTbs = tbsOff + tbsLen;
  // Skip signatureAlgorithm SEQUENCE.
  if (der[afterTbs] !== 0x30) throw new Error('signatureAlgorithm not SEQUENCE');
  const algLenByte = der[afterTbs + 1]!;
  let algHdr = 2;
  let algContent = 0;
  if (algLenByte & 0x80) {
    const n = algLenByte & 0x7f;
    algHdr = 2 + n;
    for (let i = 0; i < n; i++) algContent = algContent * 256 + der[afterTbs + 2 + i]!;
  } else {
    algContent = algLenByte;
  }
  const sigStart = afterTbs + algHdr + algContent;
  if (der[sigStart] !== 0x03) throw new Error('signatureValue not BIT STRING');
  const sigLenByte = der[sigStart + 1]!;
  let bitsHdr = 2;
  let bitsContent = 0;
  if (sigLenByte & 0x80) {
    const n = sigLenByte & 0x7f;
    bitsHdr = 2 + n;
    for (let i = 0; i < n; i++) bitsContent = bitsContent * 256 + der[sigStart + 2 + i]!;
  } else {
    bitsContent = sigLenByte;
  }
  // BIT STRING content starts with an unused-bits byte (0x00 for byte-aligned
  // RSA signatures); skip it.
  return der.slice(sigStart + bitsHdr + 1, sigStart + bitsHdr + bitsContent);
}

// =============================================================================
// Poseidon depth-16 Merkle with a single leaf (cert hash) at index 0.
// =============================================================================

async function buildMerkle(
  leaf: bigint,
): Promise<{
  root: bigint;
  path: bigint[];
  indices: number[];
}> {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  // Empty-subtree defaults: emptyHash[d] = Poseidon(emptyHash[d-1], emptyHash[d-1])
  const empty: bigint[] = new Array(17).fill(0n);
  empty[0] = 0n;
  for (let d = 1; d <= 16; d++) {
    const h = poseidon([F.e(empty[d - 1]), F.e(empty[d - 1])]);
    empty[d] = F.toObject(h);
  }
  // Path for index 0: sibling at each level is empty[level].
  const path: bigint[] = [];
  const indices: number[] = [];
  let node = leaf;
  for (let d = 0; d < 16; d++) {
    path.push(empty[d]);
    indices.push(0);
    const h = poseidon([F.e(node), F.e(empty[d])]);
    node = F.toObject(h);
  }
  return { root: node, path, indices };
}

// Mirror of flattener canonicalizeCertHash.
async function canonicalizeCertHash(data: Uint8Array): Promise<bigint> {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const CHUNK = 31;
  const RATE = 15;
  const chunks: bigint[] = [];
  for (let i = 0; i < data.length; i += CHUNK) {
    const end = Math.min(i + CHUNK, data.length);
    let v = 0n;
    for (let j = i; j < end; j++) v = (v << 8n) | BigInt(data[j]!);
    chunks.push(v);
  }
  chunks.push(BigInt(data.length));
  let state: unknown = F.e(0n);
  for (let i = 0; i < chunks.length; i += RATE) {
    const w: unknown[] = new Array(RATE + 1);
    w[0] = state;
    for (let j = 0; j < RATE; j++) {
      const c = chunks[i + j];
      w[j + 1] = F.e(c === undefined ? 0n : c);
    }
    state = poseidon(w);
  }
  return F.toObject(state);
}

// =============================================================================
// CMS SignedData assembly (detached, raw RSA-PKCS1v1.5 over signedAttrs).
// =============================================================================

async function buildDetachedCms(opts: {
  content: Uint8Array;
  leaf: Certificate;
  leafPrivateKey: CryptoKey;
}): Promise<{ cmsDer: Uint8Array; signedAttrsDer: Uint8Array; messageDigest: Uint8Array }> {
  const messageDigest = sha256(opts.content);

  // Manually assemble DER SET OF SignedAttribute bytes so we can compute
  // messageDigest offset inside later. pkijs offers a path but extracting
  // raw bytes round-trip is fiddly. Simpler: use pkijs to produce the full
  // CMS and then locate the signedAttrs substring.
  const contentTypeAttr = new Attribute({
    type: OID_CONTENT_TYPE,
    values: [new (require('asn1js').ObjectIdentifier)({ value: OID_DATA })],
  });
  const messageDigestAttr = new Attribute({
    type: OID_MESSAGE_DIGEST,
    values: [new OctetString({ valueHex: messageDigest.slice().buffer as ArrayBuffer })],
  });
  const signingTimeAttr = new Attribute({
    type: OID_SIGNING_TIME,
    values: [new (require('asn1js').UTCTime)({ valueDate: new Date() })],
  });

  const signerInfo = new SignerInfo({
    version: 1,
    sid: new IssuerAndSerialNumber({
      issuer: opts.leaf.issuer,
      serialNumber: opts.leaf.serialNumber,
    }),
    digestAlgorithm: new (require('pkijs').AlgorithmIdentifier)({
      algorithmId: '2.16.840.1.101.3.4.2.1', // sha-256
    }),
    signedAttrs: new SignedAndUnsignedAttributes({
      type: 0,
      attributes: [contentTypeAttr, messageDigestAttr, signingTimeAttr],
    }),
    signatureAlgorithm: new (require('pkijs').AlgorithmIdentifier)({
      algorithmId: '1.2.840.113549.1.1.1', // rsaEncryption
    }),
  });

  const cms = new SignedData({
    version: 1,
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: OID_DATA,
    }),
    digestAlgorithms: [
      new (require('pkijs').AlgorithmIdentifier)({
        algorithmId: '2.16.840.1.101.3.4.2.1',
      }),
    ],
    certificates: [opts.leaf],
    signerInfos: [signerInfo],
  });

  await cms.sign(opts.leafPrivateKey, 0, 'SHA-256', opts.content);

  // Extract signedAttrs DER (SET OF, tag 0x31) — what was actually signed.
  // pkijs stores it on signerInfo.signedAttrs after sign().
  const signedAttrsSet = (signerInfo.signedAttrs!.toSchema() as {
    toBER(sizeOnly: boolean): ArrayBuffer;
  });
  // The digest is computed over SET OF encoded with tag 0x31 (not the [0]
  // IMPLICIT tag used in the DER-encoded SignerInfo container).
  const raw = new Uint8Array(signedAttrsSet.toBER(false));
  // The first byte should already be 0xA0 (context-specific [0] IMPLICIT) —
  // per CMS §5.4, signing is over the SET OF encoding (0x31).
  const signedAttrsDer = new Uint8Array(raw.length);
  signedAttrsDer.set(raw);
  if (signedAttrsDer[0] === 0xa0) signedAttrsDer[0] = 0x31;

  const ContentInfo = require('pkijs').ContentInfo;
  const ci = new ContentInfo({
    contentType: '1.2.840.113549.1.7.2',
    content: cms.toSchema(true),
  });
  const cmsDer = new Uint8Array(ci.toSchema().toBER(false));
  return { cmsDer, signedAttrsDer, messageDigest };
}

// =============================================================================
// Main
// =============================================================================

async function main(): Promise<void> {
  const outDir = resolve(__dirname, '..', 'fixtures', 'integration', 'synth-rsa');
  mkdirSync(outDir, { recursive: true });

  // 1. Load admin binding (path is relative to the circuits package root
  //    so the script is portable across main checkout / worktree).
  const pkgRoot = resolve(__dirname, '..');
  const bindingPath = resolve(pkgRoot, '..', '..', 'fixtures', 'qes', 'admin-binding.qkb.json');
  const binding = readFileSync(bindingPath);

  // 2. Generate intermediate CA (self-signed) + leaf.
  const interKp = await generateRsaKeyPair();
  const leafKp = await generateRsaKeyPair();

  const interCert = await buildCert({
    subjectCN: 'QKB Synth-RSA Intermediate CA',
    issuerCN: 'QKB Synth-RSA Intermediate CA',
    subjectKey: interKp,
    issuerPrivateKey: interKp.privateKey,
    isCA: true,
    serial: 1,
  });
  const leafCert = await buildCert({
    subjectCN: 'QKB Synth-RSA Leaf',
    issuerCN: 'QKB Synth-RSA Intermediate CA',
    subjectKey: leafKp,
    issuerPrivateKey: interKp.privateKey,
    isCA: false,
    serial: 2,
  });

  const interDer = derOf(interCert);
  const leafDer = derOf(leafCert);
  writeFileSync(resolve(outDir, 'intermediate.der'), interDer);
  writeFileSync(resolve(outDir, 'leaf.der'), leafDer);
  writeFileSync(resolve(outDir, 'binding.qkb.json'), binding);

  // 3. Detached CMS over binding bytes.
  const { cmsDer, signedAttrsDer, messageDigest } = await buildDetachedCms({
    content: binding,
    leaf: leafCert,
    leafPrivateKey: leafKp.privateKey,
  });
  writeFileSync(resolve(outDir, 'leaf.p7s'), cmsDer);

  // 4. Extract offsets.
  // 4a. Leaf/intermediate modulus + exponent offsets (within each DER).
  // SPKI is inside TBS; rather than parse, scan from tbsOffset forwards.
  const interTbs = extractTbs(interDer);
  const leafTbs = extractTbs(leafDer);
  const interSpki = extractRsaSpki(interDer, interTbs.offset);
  const leafSpki = extractRsaSpki(leafDer, leafTbs.offset);

  // 4b. Certificate signatures.
  const leafSig = extractCertSignature(leafDer); // signed by intermediate
  const interSig = extractCertSignature(interDer); // self-signed (self-check)

  // 4c. Locate messageDigest OCTET STRING (32 bytes) inside signedAttrsDer:
  //     its OID encoding is 1.2.840.113549.1.9.4 = 06 09 2A 86 48 86 F7 0D 01 09 04,
  //     followed by SET (31 22 04 20 <32-byte digest>).
  const mdOidBytes = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
  ];
  const mdOidPos = findOffset(signedAttrsDer, mdOidBytes);
  if (mdOidPos < 0) throw new Error('messageDigest OID not found');
  const mdDigestPos = mdOidPos + mdOidBytes.length + 4; // SET(31 22) OCTET(04 20)
  const mdInSignedAttrs = signedAttrsDer.slice(mdDigestPos, mdDigestPos + 32);
  if (!Buffer.from(mdInSignedAttrs).equals(Buffer.from(messageDigest))) {
    throw new Error('messageDigest offset mismatch');
  }

  // 4d. Intermediate Poseidon canonical hash + Merkle path.
  const interHash = await canonicalizeCertHash(interDer);
  const merkle = await buildMerkle(interHash);

  // 4e. Compute JCS field offsets inline from the admin binding bytes.
  const textOf = binding.toString('utf8');
  const offsetOf = (key: string, after: number = 0): number => {
    const needle = `"${key}":`;
    const idx = textOf.indexOf(needle, after);
    if (idx < 0) throw new Error(`${key} not found`);
    const valueStart = idx + needle.length;
    return textOf[valueStart] === '"' ? valueStart + 1 : valueStart;
  };
  const contextOffset = offsetOf('context');
  const declOffset = offsetOf('declaration');
  const pkOffset = offsetOf('pk');
  const schemeOffset = offsetOf('scheme');
  const tsOffset = offsetOf('timestamp');
  // Declaration length: scan until the closing unescaped '"'. Admin binding
  // has no escape sequences in the declaration (pure ASCII).
  let declEnd = declOffset;
  while (textOf[declEnd] !== '"') declEnd++;
  const declarationBytesLength = declEnd - declOffset;
  const adminJcs = {
    offsets: {
      context: contextOffset,
      declaration: declOffset,
      pk: pkOffset,
      scheme: schemeOffset,
      timestamp: tsOffset,
    },
    declarationBytesLength,
  };

  const fixture = {
    version: '1.0',
    derPaths: {
      intermediate: 'intermediate.der',
      leaf: 'leaf.der',
      cms: 'leaf.p7s',
      binding: 'binding.qkb.json',
    },
    intermediate: {
      derLength: interDer.length,
      tbs: interTbs,
      modulusOffset: interSpki.modulusOffset,
      exponentOffset: interSpki.exponentOffset,
      selfSignature: Buffer.from(interSig).toString('hex'),
      poseidonHash: interHash.toString(),
    },
    leaf: {
      derLength: leafDer.length,
      tbs: leafTbs,
      modulusOffset: leafSpki.modulusOffset,
      exponentOffset: leafSpki.exponentOffset,
      signatureByIntermediate: Buffer.from(leafSig).toString('hex'),
    },
    cms: {
      derLength: cmsDer.length,
      signedAttrsHex: Buffer.from(signedAttrsDer).toString('hex'),
      signedAttrsLength: signedAttrsDer.length,
      messageDigestOffsetInSignedAttrs: mdDigestPos,
      messageDigestHex: Buffer.from(messageDigest).toString('hex'),
    },
    binding: {
      bytesLength: binding.length,
      offsets: adminJcs.offsets,
      declarationBytesLength: adminJcs.declarationBytesLength,
    },
    merkle: {
      depth: 16,
      root: merkle.root.toString(),
      path: merkle.path.map((v) => v.toString()),
      indices: merkle.indices,
      leafIndex: 0,
    },
  };
  writeFileSync(resolve(outDir, 'fixture.json'), JSON.stringify(fixture, null, 2) + '\n');
  console.log('Synthetic RSA fixture written to', outDir);
  console.log(
    '  intermediate:', interDer.length, 'B  modOff', interSpki.modulusOffset,
  );
  console.log('  leaf:        ', leafDer.length, 'B  modOff', leafSpki.modulusOffset);
  console.log('  cms:         ', cmsDer.length, 'B  signedAttrs', signedAttrsDer.length, 'B');
  console.log('  merkle root: ', merkle.root.toString().slice(0, 24), '…');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
