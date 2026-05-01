// Synthesize a CAdES-BES detached `.p7s` for V5 E2E testing.
//
// Wraps the REAL admin-ecdsa leaf cert (leaf.der) + a placeholder
// intermediate cert in a structurally-valid CMS SignedData container,
// with signedAttrs whose messageDigest equals sha256(content). The
// SignerInfo's signature value is placeholder bytes (64 zeros) — the
// circuit doesn't verify ECDSA signatures (that's on-chain via EIP-7212),
// and `parseP7s` only checks structural integrity. So we don't need a
// matching private key.
//
// Why synthetic: the real Diia .p7s is gitignored per project secrets
// policy (CLAUDE.md "secrets hygiene"). For CI-friendly E2E we assemble
// a CAdES that exercises the parseP7s.ts → buildWitnessV5 → circuit
// path against a structurally-faithful CMS; the only synthetic bit is
// the placeholder signature value, which the circuit never reads.

import { Buffer } from 'node:buffer';
import {
  Attribute,
  Certificate,
  ContentInfo,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  SignedData,
  SignerInfo,
  SignedAndUnsignedAttributes,
  AlgorithmIdentifier,
} from 'pkijs';
import * as asn1js from 'asn1js';

// CMS / CAdES OIDs.
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_DATA = '1.2.840.113549.1.7.1';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2';
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

function buf2ab(buf: Buffer): ArrayBuffer {
  const ab = new ArrayBuffer(buf.length);
  new Uint8Array(ab).set(buf);
  return ab;
}

/**
 * Parse a Buffer-form DER cert into a pkijs Certificate.
 */
function parseCert(der: Buffer): Certificate {
  const asn = asn1js.fromBER(buf2ab(der));
  if (asn.offset === -1) throw new Error('build-synth-cades: invalid leaf cert DER');
  return new Certificate({ schema: asn.result });
}

export interface SynthCadesInput {
  /** Bytes whose sha256 lands in signedAttrs.messageDigest (typically the JCS binding). */
  contentDigest: Buffer;
  /** Real leaf cert DER (admin-ecdsa fixture's leaf.der). */
  leafCertDer: Buffer;
  /** Optional intermediate cert DER (kept in SignedData.certificates for completeness). */
  intCertDer?: Buffer;
}

export interface SynthCadesOutput {
  /** Full CAdES-BES SignedData CMS bytes — what a real `.p7s` carries. */
  p7sBuffer: Buffer;
  /** signedAttrs DER (SET-tagged 0x31, hash-input form). Pre-computed for assertions. */
  signedAttrsDer: Buffer;
  /** Offset of the messageDigest Attribute SEQUENCE (`0x30 0x2f`) within signedAttrsDer. */
  signedAttrsMdOffset: number;
}

/**
 * Build a structurally-valid CAdES-BES SignedData wrapping the supplied
 * leaf cert + signedAttrs whose messageDigest matches `contentDigest`.
 */
export function buildSynthCades(input: SynthCadesInput): SynthCadesOutput {
  if (input.contentDigest.length !== 32) {
    throw new Error(
      `build-synth-cades: contentDigest must be 32 bytes (SHA-256), got ${input.contentDigest.length}`,
    );
  }

  const leafCert = parseCert(input.leafCertDer);
  const intCert = input.intCertDer ? parseCert(input.intCertDer) : undefined;

  // Two minimum-required signedAttrs per RFC 5652 §11.1-§11.2:
  //   - contentType: id-data
  //   - messageDigest: sha256(content)
  const contentTypeAttr = new Attribute({
    type: OID_CONTENT_TYPE,
    values: [new asn1js.ObjectIdentifier({ value: OID_DATA })],
  });
  const messageDigestAttr = new Attribute({
    type: OID_MESSAGE_DIGEST,
    values: [
      new asn1js.OctetString({ valueHex: buf2ab(input.contentDigest) }),
    ],
  });

  // SignedAttributes container. type=0 is the [0] IMPLICIT tag for
  // SignerInfo encoding; the hash-input form uses tag 0x31 (SET).
  const signedAttrs = new SignedAndUnsignedAttributes({
    type: 0,
    attributes: [contentTypeAttr, messageDigestAttr],
  });

  // SignerInfo with a 64-byte placeholder ECDSA-P256 signature value.
  // The circuit doesn't verify the signature; on-chain uses leafSig from
  // calldata (separately supplied by the witness builder, not by this
  // synthetic CMS). We use an ECDSA-style ASN.1 SEQUENCE { r, s } encoding
  // so structural checks against `1.2.840.10045.4.3.2` aren't violated.
  const placeholderSigSeq = new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 1 }),
      new asn1js.Integer({ value: 1 }),
    ],
  });
  const placeholderSigBytes = new Uint8Array(placeholderSigSeq.toBER(false));

  const signerInfo = new SignerInfo({
    version: 1,
    sid: new IssuerAndSerialNumber({
      issuer: leafCert.issuer,
      serialNumber: leafCert.serialNumber,
    }),
    digestAlgorithm: new AlgorithmIdentifier({ algorithmId: OID_SHA256 }),
    signedAttrs,
    signatureAlgorithm: new AlgorithmIdentifier({ algorithmId: OID_ECDSA_WITH_SHA256 }),
    signature: new asn1js.OctetString({
      valueHex: placeholderSigBytes.slice().buffer as ArrayBuffer,
    }),
  });

  // SignedData. Detached: encapContentInfo carries only the eContentType
  // (no eContent — content lives outside the .p7s, e.g. the binding JSON).
  const certs: Certificate[] = [leafCert];
  if (intCert) certs.push(intCert);
  const cms = new SignedData({
    version: 1,
    encapContentInfo: new EncapsulatedContentInfo({ eContentType: OID_DATA }),
    digestAlgorithms: [new AlgorithmIdentifier({ algorithmId: OID_SHA256 })],
    certificates: certs,
    signerInfos: [signerInfo],
  });

  // Wrap SignedData in ContentInfo (the outer .p7s envelope).
  const ci = new ContentInfo({
    contentType: OID_SIGNED_DATA,
    content: cms.toSchema(true),
  });
  const p7sBuffer = Buffer.from(new Uint8Array(ci.toSchema().toBER(false)));

  // Extract the SET-tagged signedAttrs DER (the hash-input form).
  const saSchema = signerInfo.signedAttrs!.toSchema();
  const saBer = new Uint8Array(saSchema.toBER(false));
  const signedAttrsDer = Buffer.alloc(saBer.length);
  signedAttrsDer.set(saBer);
  if (signedAttrsDer[0] === 0xa0) signedAttrsDer[0] = 0x31;

  // Locate the messageDigest Attribute SEQUENCE (`0x30 0x2f` leadIn) by
  // searching for the canonical 15-byte CMS sub-prefix and stepping back 2.
  const NEEDLE = Buffer.from([
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
    0x31, 0x22, 0x04, 0x20,
  ]);
  const at = signedAttrsDer.indexOf(NEEDLE);
  if (at < 2) {
    throw new Error('build-synth-cades: messageDigest prefix not found in assembled signedAttrs');
  }
  const signedAttrsMdOffset = at - 2;

  return { p7sBuffer, signedAttrsDer, signedAttrsMdOffset };
}
