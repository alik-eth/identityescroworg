#!/usr/bin/env node
// Real-QES detached-CAdES verifier.
//
//   pnpm verify:real-qes <binding.qkb.json> <binding.qkb.json.p7s>
//
// Parses a real-world UA Diia QES (CAdES-BES detached, RSA-PKCS1 v1.5 or
// ECDSA-P256, SHA-256), extracts the signer + intermediate certs, verifies
// the signed-attributes hash chain against the JCS-canonicalized binding
// bytes, and prints a redacted PASS/FAIL summary suitable for an activity
// log (no PII — subject CN is sha256-hashed, cert serial omitted).
//
// Mirrors the Phase-1 R_QKB rules implemented in src/lib/cades.ts +
// src/lib/qesVerify.ts but runs server-side via Node's WebCrypto so the
// team lead can validate fixtures before promoting them.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

pkijs.setEngine(
  'node-webcrypto',
  new pkijs.CryptoEngine({ name: 'node', crypto: globalThis.crypto }),
);

const OID = {
  id_signedData: '1.2.840.113549.1.7.2',
  id_data: '1.2.840.113549.1.7.1',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  sha256: '2.16.840.1.101.3.4.2.1',
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  ecPublicKey: '1.2.840.10045.2.1',
  ecdsaSha256: '1.2.840.10045.4.3.2',
  p256: '1.2.840.10045.3.1.7',
  p384: '1.2.840.10045.3.1.34',
  cn: '2.5.4.3',
  o: '2.5.4.10',
  c: '2.5.4.6',
};

const args = process.argv.slice(2);
let trustedCasPath = null;
const positional = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--trusted-cas') {
    trustedCasPath = args[++i];
  } else if (a.startsWith('--trusted-cas=')) {
    trustedCasPath = a.slice('--trusted-cas='.length);
  } else {
    positional.push(a);
  }
}
if (positional.length !== 2) {
  console.error(
    'usage: verify-real-qes <binding.qkb.json> <binding.qkb.json.p7s> [--trusted-cas <path>]',
  );
  process.exit(2);
}
const bindingPath = resolve(positional[0]);
const p7sPath = resolve(positional[1]);
const trustedCas = trustedCasPath ? loadTrustedCas(resolve(trustedCasPath)) : null;

const bindingBytes = new Uint8Array(readFileSync(bindingPath));
const cmsBytes = new Uint8Array(readFileSync(p7sPath));
const bindingSha = sha256Hex(bindingBytes);

const ci = asn1js.fromBER(toAB(cmsBytes));
if (ci.offset === -1) fatal('asn1: cannot parse CMS BER');
const contentInfo = new pkijs.ContentInfo({ schema: ci.result });
if (contentInfo.contentType !== OID.id_signedData) {
  fatal(`ContentInfo.contentType is ${contentInfo.contentType}, expected id-signedData`);
}
const signed = new pkijs.SignedData({ schema: contentInfo.content });

if (signed.signerInfos.length !== 1) fatal(`expected 1 signer, got ${signed.signerInfos.length}`);
const signer = signed.signerInfos[0];
if (!signer.signedAttrs) fatal('signedAttrs missing');

const digestAlgOid = signer.digestAlgorithm.algorithmId;
const sigAlgOid = signer.signatureAlgorithm.algorithmId;
if (digestAlgOid !== OID.sha256) fatal(`digestAlgorithm ${digestAlgOid} != sha-256`);

const certs = (signed.certificates ?? []).filter((c) => c instanceof pkijs.Certificate);
if (certs.length === 0) fatal('no certificates in CMS');

const leaf = findLeaf(certs, signer.sid);
if (!leaf) fatal('signer cert (matching SignerInfo.sid) not present');
let intermediate = findIssuer(certs, leaf);
let intermediateSource = intermediate ? 'inline-cms' : null;
let intermediateMerkleIndex = null;
if (!intermediate && trustedCas) {
  const resolved = resolveIntermediateFromLotl(leaf.issuer, trustedCas);
  if (resolved) {
    intermediate = resolved.cert;
    intermediateSource = 'lotl';
    intermediateMerkleIndex = resolved.merkleIndex;
  } else {
    fatal('CADES_INTERMEDIATE_NOT_IN_LOTL: leaf-only CMS and issuer DN absent from --trusted-cas');
  }
}

// 1. messageDigest attr must equal SHA-256(binding bytes).
const mdAttr = signer.signedAttrs.attributes.find((a) => a.type === OID.messageDigest);
if (!mdAttr) fatal('messageDigest attribute missing');
const mdBytes = new Uint8Array(mdAttr.values[0].valueBlock.valueHexView);
const mdHex = bytesToHex(mdBytes);
if (mdHex !== bindingSha) {
  fatal(`messageDigest ${mdHex} != sha256(binding) ${bindingSha}`);
}

// 2. RSA/ECDSA-verify the signedAttrs SET re-encoding using the leaf's SPKI.
const signedAttrsDer = encodeSignedAttrsSetForSig(signer);
const sigBytes = new Uint8Array(signer.signature.valueBlock.valueHexView);
const leafSpkiDer = new Uint8Array(leaf.subjectPublicKeyInfo.toSchema().toBER(false));
const leafAlgOid = leaf.subjectPublicKeyInfo.algorithm.algorithmId;

let scheme;
let keyBits;
let sigOk;
if (leafAlgOid === OID.rsaEncryption) {
  scheme = 'RSA-PKCS1v1_5/SHA-256';
  const mod = leaf.subjectPublicKeyInfo.parsedKey?.modulus?.valueBlock?.valueHexView;
  keyBits = mod ? mod.byteLength * 8 - (mod[0] === 0 ? 8 : 0) : null;
  if (sigAlgOid !== OID.rsaEncryption && sigAlgOid !== OID.sha256WithRSA) {
    fatal(`SignerInfo signatureAlgorithm ${sigAlgOid} mismatch with RSA leaf`);
  }
  const key = await globalThis.crypto.subtle.importKey(
    'spki',
    toAB(leafSpkiDer),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  sigOk = await globalThis.crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    toAB(sigBytes),
    toAB(signedAttrsDer),
  );
} else if (leafAlgOid === OID.ecPublicKey) {
  if (sigAlgOid !== OID.ecdsaSha256) {
    fatal(`SignerInfo signatureAlgorithm ${sigAlgOid} not ecdsa-with-SHA256`);
  }
  const curveOid = leaf.subjectPublicKeyInfo.algorithm.algorithmParams?.valueBlock?.toString?.();
  if (curveOid === OID.p256) {
    scheme = 'ECDSA-P256/SHA-256';
    keyBits = 256;
  } else if (curveOid === OID.p384) {
    scheme = 'ECDSA-P384/SHA-256';
    keyBits = 384;
  } else {
    fatal(`unsupported EC curve OID ${curveOid}`);
  }
  const key = await globalThis.crypto.subtle.importKey(
    'spki',
    toAB(leafSpkiDer),
    { name: 'ECDSA', namedCurve: keyBits === 256 ? 'P-256' : 'P-384' },
    false,
    ['verify'],
  );
  const rawSig = ecdsaDerToRaw(sigBytes, keyBits / 8);
  sigOk = await globalThis.crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    toAB(rawSig),
    toAB(signedAttrsDer),
  );
} else {
  fatal(`unsupported leaf SPKI algorithm ${leafAlgOid}`);
}

const signingTime = extractSigningTime(signer.signedAttrs);
const validFrom = leaf.notBefore.value;
const validTo = leaf.notAfter.value;
const subjectCn = readCn(leaf.subject);
const issuerCn = readCn(leaf.issuer);
const issuerO = readAttr(leaf.issuer, OID.o);
const issuerC = readAttr(leaf.issuer, OID.c);

const summary = {
  outcome: sigOk ? 'PASS' : 'FAIL',
  scheme,
  keyBits,
  digestAlgorithmOid: digestAlgOid,
  signatureAlgorithmOid: sigAlgOid,
  binding: { path: bindingPath, sha256: '0x' + bindingSha, bytes: bindingBytes.length },
  cms: { path: p7sPath, bytes: cmsBytes.length, certCount: certs.length },
  signer: {
    subjectCnSha256: '0x' + sha256Hex(new TextEncoder().encode(subjectCn ?? '')),
    issuerCn,
    issuerOrganization: issuerO,
    issuerCountry: issuerC,
    intermediatePresent: !!intermediate,
    intermediateSource,
    intermediateMerkleIndex,
    notBefore: validFrom.toISOString(),
    notAfter: validTo.toISOString(),
    signingTime: signingTime ? signingTime.toISOString() : null,
  },
};

console.error(`[verify-real-qes] outcome: ${summary.outcome}`);
console.error(`  scheme           : ${summary.scheme} (${summary.keyBits} bits)`);
console.error(`  binding sha256   : ${summary.binding.sha256}`);
console.error(`  binding bytes    : ${summary.binding.bytes}`);
console.error(`  CMS bytes        : ${summary.cms.bytes}`);
console.error(`  certs in CMS     : ${summary.cms.certCount}`);
console.error(
  `  intermediate     : ${summary.signer.intermediatePresent ? `present (${intermediateSource}${intermediateMerkleIndex !== null ? `, merkleIndex=${intermediateMerkleIndex}` : ''})` : 'absent (no chain link verified)'}`,
);
console.error(`  issuer (QTSP)    : ${summary.signer.issuerCn} / ${summary.signer.issuerOrganization} / ${summary.signer.issuerCountry}`);
console.error(`  cert validity    : ${summary.signer.notBefore} → ${summary.signer.notAfter}`);
console.error(`  signing time     : ${summary.signer.signingTime ?? '(absent)'}`);
console.error(`  subject CN sha256: ${summary.signer.subjectCnSha256}`);
console.error('');
console.log(JSON.stringify(summary, null, 2));

if (!sigOk) process.exit(1);

// ---------------------------------------------------------------------------
// helpers

function encodeSignedAttrsSetForSig(signer) {
  // RFC 5652 §5.4: the bytes signed are the SET OF Attribute, NOT the
  // [0] IMPLICIT context-specific tag. Re-encode here.
  const set = new asn1js.Set({
    value: signer.signedAttrs.attributes.map((a) => a.toSchema()),
  });
  return new Uint8Array(set.toBER(false));
}

function findLeaf(certs, sid) {
  if (sid instanceof pkijs.IssuerAndSerialNumber) {
    return certs.find(
      (c) =>
        c.serialNumber.isEqual(sid.serialNumber) && rdnEqual(c.issuer, sid.issuer),
    );
  }
  return undefined;
}

function loadTrustedCas(path) {
  let raw;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    fatal(`cannot read --trusted-cas ${path}: ${e?.message ?? e}`);
  }
  if (!raw || !Array.isArray(raw.cas)) fatal(`malformed trusted-cas at ${path}`);
  return raw;
}

function resolveIntermediateFromLotl(leafIssuer, file) {
  const want = bytesToHex(new Uint8Array(leafIssuer.toSchema().toBER(false)));
  for (const ca of file.cas) {
    let der;
    try {
      der = b64ToBytes(ca.certDerB64);
    } catch {
      continue;
    }
    let cert;
    try {
      const asn = asn1js.fromBER(toAB(der));
      if (asn.offset === -1) continue;
      cert = new pkijs.Certificate({ schema: asn.result });
    } catch {
      continue;
    }
    const subjDer = bytesToHex(new Uint8Array(cert.subject.toSchema().toBER(false)));
    if (subjDer === want) {
      return { cert, merkleIndex: ca.merkleIndex };
    }
  }
  return null;
}

function b64ToBytes(s) {
  const bin = Buffer.from(s, 'base64');
  return new Uint8Array(bin);
}

function findIssuer(certs, leaf) {
  return certs.find((c) => c !== leaf && rdnEqual(c.subject, leaf.issuer));
}

function rdnEqual(a, b) {
  const ad = new Uint8Array(a.toSchema().toBER(false));
  const bd = new Uint8Array(b.toSchema().toBER(false));
  if (ad.length !== bd.length) return false;
  for (let i = 0; i < ad.length; i++) if (ad[i] !== bd[i]) return false;
  return true;
}

function readCn(rdn) {
  return readAttr(rdn, OID.cn);
}

function readAttr(rdn, oid) {
  for (const tv of rdn.typesAndValues ?? []) {
    if (tv.type === oid) {
      const v = tv.value;
      const blockValue = v?.valueBlock?.value;
      if (typeof blockValue === 'string') return blockValue;
      if (typeof v?.toString === 'function') return v.toString();
      return null;
    }
  }
  return null;
}

function extractSigningTime(signedAttrs) {
  const a = signedAttrs.attributes.find((x) => x.type === OID.signingTime);
  if (!a || !a.values || a.values.length === 0) return null;
  const v = a.values[0];
  // UTCTime or GeneralizedTime — both expose .toDate()
  if (typeof v.toDate === 'function') return v.toDate();
  return null;
}

function ecdsaDerToRaw(der, half) {
  const asn = asn1js.fromBER(toAB(der));
  if (asn.offset === -1) fatal('ECDSA signature: bad DER');
  const seq = asn.result;
  const [rNode, sNode] = seq.valueBlock.value;
  const r = stripLead(new Uint8Array(rNode.valueBlock.valueHexView));
  const s = stripLead(new Uint8Array(sNode.valueBlock.valueHexView));
  const out = new Uint8Array(half * 2);
  out.set(padLeft(r, half), 0);
  out.set(padLeft(s, half), half);
  return out;
}

function stripLead(b) {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
}

function padLeft(b, n) {
  if (b.length === n) return b;
  if (b.length > n) fatal('ECDSA signature: integer too wide for curve');
  const out = new Uint8Array(n);
  out.set(b, n - b.length);
  return out;
}

function sha256Hex(b) {
  return createHash('sha256').update(b).digest('hex');
}

function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function toAB(b) {
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  return ab;
}

function fatal(msg) {
  console.error(`[verify-real-qes] FATAL: ${msg}`);
  process.exit(1);
}
