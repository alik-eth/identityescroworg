// Real-Diia ECDSA admin fixture extractor.
//
// Pulls every witness-side artifact we can derive from the authentic
// admin-binding.qkb.json + admin-binding.qkb.json.p7s pair (a genuine
// Diia-signed CAdES-BES detached QES) — excluding anything that needs
// the Diia intermediate CA, which the repo does not yet carry (blocked
// on flattener T10 LOTL pump or an offline fetch).
//
// Output (committed under fixtures/integration/admin-ecdsa/):
//   binding.qkb.json               unchanged real admin binding
//   leaf.der                       real Diia-issued leaf (user cert)
//   leaf.p7s                       copy of real admin p7s (for traceability)
//   fixture.json                   witness-builder manifest covering:
//                                    - leaf tbs offset/length, SPKI EC coords
//                                    - leaf ECDSA signature over signedAttrs
//                                      (extracted from SignerInfo) + (r, s)
//                                    - signedAttrs DER + messageDigest offset
//                                    - binding field offsets (pk/ctx/decl/
//                                      scheme/timestamp) + declLen
//
// This fixture is sufficient for the main circuit's constraints 1, 2, 5, 6
// (leaf QES signature, binding ↔ signature, binding content ↔ public inputs,
// cert validity). Constraints 3 + 4 (intermediate signs leaf, intermediate
// in trusted list) are deferred until the Diia CA DER is available.

import { Certificate, CryptoEngine, setEngine, SignedData, ContentInfo } from 'pkijs';
import { fromBER } from 'asn1js';
import { webcrypto } from 'node:crypto';
import { createHash } from 'node:crypto';
import { writeFileSync, mkdirSync, readFileSync, copyFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Buffer } from 'node:buffer';

const crypto = (webcrypto as unknown) as Crypto;
setEngine(
  'node',
  new CryptoEngine({ name: 'node', crypto, subtle: crypto.subtle }),
);

// ---------------------------------------------------------------------------
// DER helpers
// ---------------------------------------------------------------------------

function extractTbs(der: Uint8Array): { offset: number; length: number } {
  if (der[0] !== 0x30) throw new Error('cert not a SEQUENCE');
  let cursor = 1;
  const lb = der[cursor++]!;
  if (lb & 0x80) cursor += lb & 0x7f;
  const tbsStart = cursor;
  if (der[cursor] !== 0x30) throw new Error('tbs not a SEQUENCE');
  const tbsLb = der[cursor + 1]!;
  let tbsHeaderLen = 2;
  let tbsContentLen = 0;
  if (tbsLb & 0x80) {
    const n = tbsLb & 0x7f;
    tbsHeaderLen = 2 + n;
    for (let i = 0; i < n; i++) {
      tbsContentLen = tbsContentLen * 256 + der[cursor + 2 + i]!;
    }
  } else {
    tbsContentLen = tbsLb;
  }
  return { offset: tbsStart, length: tbsHeaderLen + tbsContentLen };
}

// Locate SubjectPublicKeyInfo inside tbsCertificate for an ECDSA cert.
// Shape: ...SEQUENCE { SEQUENCE { OID ecPublicKey, OID P-256 },
//         BIT STRING 0x00 0x04 <64 bytes xy> }
// Returns (xOffset, xyLength=64) such that der[xOffset..+64] = 0x04 <x32><y32>.
function extractEcP256SpkiXy(
  der: Uint8Array,
): { pubKeyByteOffset: number; xOffset: number; yOffset: number } {
  // Search for the ecPublicKey OID (1.2.840.10045.2.1) encoding:
  //   06 07 2A 86 48 CE 3D 02 01
  // followed by the P-256 OID (1.2.840.10045.3.1.7):
  //   06 08 2A 86 48 CE 3D 03 01 07
  const ecPubKey = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
  const p256 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
  let i = 0;
  outer: for (; i + ecPubKey.length + p256.length < der.length; i++) {
    for (let j = 0; j < ecPubKey.length; j++) if (der[i + j] !== ecPubKey[j]) continue outer;
    for (let j = 0; j < p256.length; j++) {
      if (der[i + ecPubKey.length + j] !== p256[j]) continue outer;
    }
    break;
  }
  const afterAlg = i + ecPubKey.length + p256.length;
  // Skip the outer AlgorithmIdentifier SEQUENCE header; we're already past
  // its content. The next TLV is the BIT STRING (03 <len> 00 04 <xy>).
  let bitStart = afterAlg;
  while (der[bitStart] !== 0x03) bitStart++;
  // BIT STRING: 03 <len-byte(s)> <unused-bits=0x00> <0x04 uncompressed prefix>
  const lenByte = der[bitStart + 1]!;
  let hdr = 2;
  if (lenByte & 0x80) hdr = 2 + (lenByte & 0x7f);
  const contentStart = bitStart + hdr;
  // contentStart[0] = 0x00 (unused bits), contentStart[1] = 0x04 (uncompressed)
  if (der[contentStart] !== 0x00 || der[contentStart + 1] !== 0x04) {
    throw new Error('SPKI not uncompressed P-256');
  }
  const pubKeyByteOffset = contentStart + 1; // points at the 0x04 byte
  return {
    pubKeyByteOffset,
    xOffset: pubKeyByteOffset + 1,
    yOffset: pubKeyByteOffset + 33,
  };
}

// Decode an ECDSA signatureValue BIT STRING content (which is itself an
// ASN.1 SEQUENCE { INTEGER r, INTEGER s }) into raw 32-byte big-endian r,s.
function decodeEcdsaSigSequence(seqDer: Uint8Array): { r: Uint8Array; s: Uint8Array } {
  if (seqDer[0] !== 0x30) throw new Error('ecdsa sig not SEQUENCE');
  let p = 2;
  const len1 = seqDer[1]!;
  if (len1 & 0x80) p = 2 + (len1 & 0x7f);
  function readInt(): Uint8Array {
    if (seqDer[p] !== 0x02) throw new Error('ecdsa sig field not INTEGER');
    const l = seqDer[p + 1]!;
    const start = p + 2;
    const end = start + l;
    p = end;
    // Strip leading 0x00 sign byte if present.
    let out = seqDer.slice(start, end);
    if (out.length > 32 && out[0] === 0x00) out = out.slice(1);
    // Left-pad to 32 bytes.
    if (out.length < 32) {
      const padded = new Uint8Array(32);
      padded.set(out, 32 - out.length);
      out = padded;
    }
    return out;
  }
  const r = readInt();
  const s = readInt();
  return { r, s };
}

function findOffset(haystack: Uint8Array, needle: number[]): number {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const pkgRoot = resolve(__dirname, '..');
  const outDir = resolve(pkgRoot, 'fixtures', 'integration', 'admin-ecdsa');
  mkdirSync(outDir, { recursive: true });

  const qesDir = resolve(pkgRoot, '..', '..', 'fixtures', 'qes');
  const binding = readFileSync(resolve(qesDir, 'admin-binding.qkb.json'));
  const p7s = readFileSync(resolve(qesDir, 'admin-binding.qkb.json.p7s'));

  // 1. Parse the CMS SignedData.
  const ber = p7s.slice().buffer as ArrayBuffer;
  const ci = new ContentInfo({ schema: fromBER(ber).result });
  const sd = new SignedData({ schema: ci.content });
  const certs = (sd.certificates || []).filter(
    (c): c is Certificate => c instanceof Certificate,
  );
  if (certs.length !== 1) {
    throw new Error(`expected 1 cert (leaf-only CMS), got ${certs.length}`);
  }
  const leaf = certs[0]!;
  const leafDer = new Uint8Array(leaf.toSchema(true).toBER(false));

  const signer = sd.signerInfos[0]!;
  if (!signer.signedAttrs) throw new Error('signedAttrs missing');

  // signedAttrs DER as actually signed: the SignerInfo stores it with
  // IMPLICIT [0] tag 0xA0. What was signed is the SET OF form (tag 0x31).
  const signedAttrsRaw = new Uint8Array(signer.signedAttrs.toSchema().toBER(false));
  const signedAttrsAsSigned = new Uint8Array(signedAttrsRaw.length);
  signedAttrsAsSigned.set(signedAttrsRaw);
  if (signedAttrsAsSigned[0] === 0xa0) signedAttrsAsSigned[0] = 0x31;

  // Recompute messageDigest from binding and verify it matches what's in
  // signedAttrs (belt-and-suspenders; also gives us the offset).
  const bindingDigest = new Uint8Array(createHash('sha256').update(binding).digest());
  const mdOidBytes = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
  const mdOidPos = findOffset(signedAttrsAsSigned, mdOidBytes);
  if (mdOidPos < 0) throw new Error('messageDigest OID not found in signedAttrs');
  const mdDigestPos = mdOidPos + mdOidBytes.length + 4; // SET(0x31 0x22) OCTET(0x04 0x20)
  const mdInSA = signedAttrsAsSigned.slice(mdDigestPos, mdDigestPos + 32);
  if (!Buffer.from(mdInSA).equals(Buffer.from(bindingDigest))) {
    throw new Error(
      `messageDigest mismatch: binding=${Buffer.from(bindingDigest).toString('hex')} vs signedAttrs=${Buffer.from(mdInSA).toString('hex')}`,
    );
  }

  // 2. Leaf TBS slice + ECDSA SPKI coordinates.
  const leafTbs = extractTbs(leafDer);
  const spki = extractEcP256SpkiXy(leafDer);

  // 3. SignerInfo signatureValue → ECDSA (r, s) over sha256(signedAttrs).
  const sigOctet = signer.signature.valueBlock.valueHex;
  const sigBytes = new Uint8Array(sigOctet);
  const { r, s } = decodeEcdsaSigSequence(sigBytes);

  // 4. Binding field offsets (JCS).
  const textOf = binding.toString('utf8');
  const offsetOf = (key: string): number => {
    const needle = `"${key}":`;
    const idx = textOf.indexOf(needle);
    if (idx < 0) throw new Error(`${key} not found`);
    const valueStart = idx + needle.length;
    return textOf[valueStart] === '"' ? valueStart + 1 : valueStart;
  };
  const bindingOffsets = {
    context: offsetOf('context'),
    declaration: offsetOf('declaration'),
    pk: offsetOf('pk'),
    scheme: offsetOf('scheme'),
    timestamp: offsetOf('timestamp'),
  };
  let declEnd = bindingOffsets.declaration;
  while (textOf[declEnd] !== '"') declEnd++;
  const declarationBytesLength = declEnd - bindingOffsets.declaration;

  // 5. Emit.
  copyFileSync(
    resolve(qesDir, 'admin-binding.qkb.json'),
    resolve(outDir, 'binding.qkb.json'),
  );
  copyFileSync(
    resolve(qesDir, 'admin-binding.qkb.json.p7s'),
    resolve(outDir, 'leaf.p7s'),
  );
  writeFileSync(resolve(outDir, 'leaf.der'), leafDer);

  const fixture = {
    version: '1.0',
    source: 'real Diia QES (admin-binding.qkb.json + .p7s)',
    derPaths: {
      leaf: 'leaf.der',
      cms: 'leaf.p7s',
      binding: 'binding.qkb.json',
    },
    leaf: {
      derLength: leafDer.length,
      tbs: leafTbs,
      sigAlg: leaf.signatureAlgorithm.algorithmId,
      spki: {
        pubKeyByteOffset: spki.pubKeyByteOffset,
        xOffset: spki.xOffset,
        yOffset: spki.yOffset,
      },
      notBefore: leaf.notBefore.value.toISOString(),
      notAfter: leaf.notAfter.value.toISOString(),
    },
    binding: {
      bytesLength: binding.length,
      offsets: bindingOffsets,
      declarationBytesLength,
    },
    cms: {
      signedAttrsHex: Buffer.from(signedAttrsAsSigned).toString('hex'),
      signedAttrsLength: signedAttrsAsSigned.length,
      messageDigestOffsetInSignedAttrs: mdDigestPos,
      messageDigestHex: Buffer.from(bindingDigest).toString('hex'),
      signerSignatureAlgorithm: signer.signatureAlgorithm.algorithmId,
      leafSigR: Buffer.from(r).toString('hex'),
      leafSigS: Buffer.from(s).toString('hex'),
    },
    notes: {
      intermediate:
        'OMITTED — Diia intermediate CA not yet vendored. Constraints 3 + 4 of the main circuit will require it (flattener T10 LOTL pump or offline fetch).',
    },
  };
  writeFileSync(
    resolve(outDir, 'fixture.json'),
    JSON.stringify(fixture, null, 2) + '\n',
  );

  console.log('Admin ECDSA fixture written to', outDir);
  console.log('  leaf:      ', leafDer.length, 'B  tbs', leafTbs.offset, '..', leafTbs.offset + leafTbs.length - 1);
  console.log('  spki x/y:  ', spki.xOffset, spki.yOffset);
  console.log('  signedAttrs:', signedAttrsAsSigned.length, 'B  mdOff', mdDigestPos);
  console.log('  sig r/s:   ', Buffer.from(r).toString('hex').slice(0, 16), '…', Buffer.from(s).toString('hex').slice(0, 16), '…');
  console.log(
    '  binding offsets:',
    bindingOffsets,
    'declLen=',
    declarationBytesLength,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
