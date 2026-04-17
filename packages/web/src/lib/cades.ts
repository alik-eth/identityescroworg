/**
 * CAdES-BES detached parser for `binding.qkb.json.p7s`.
 *
 * Strict by design — anything unexpected raises QkbError('cades.parse').
 * Hard requirements (orchestration §4.3 / spec §4.3):
 *   - ContentInfo.contentType == id-signedData (1.2.840.113549.1.7.2).
 *   - eContent absent (detached signature).
 *   - exactly ONE SignerInfo.
 *   - signedAttrs MUST be present and MUST contain a `messageDigest` attribute
 *     (1.2.840.113549.1.9.4) of the right length for the chosen digest.
 *   - digestAlgorithm == sha-256 (2.16.840.1.101.3.4.2.1) for Phase 1.
 *   - signatureAlgorithm == rsaEncryption (1.2.840.113549.1.1.1) — RSA-PKCS#1 v1.5.
 *   - certificates field present with at least leaf + one intermediate.
 *
 * Leaf cert is the one matching the SignerInfo's IssuerAndSerialNumber.
 * Intermediate is the cert in the SET that issued the leaf (subject DN ==
 * leaf.issuer DN). If there are more than two certs (e.g. with cross-signed
 * roots) only leaf + matching intermediate are returned; the rest are ignored
 * for circuit purposes — full chain validation lives in qesVerify.ts.
 */
import * as asn1js from 'asn1js';
import {
  Certificate,
  ContentInfo,
  IssuerAndSerialNumber,
  SignedData,
  SignerInfo,
  id_ContentType_SignedData,
} from 'pkijs';
import { QkbError } from './errors';

const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_RSA = '1.2.840.113549.1.1.1';
const OID_RSA_SHA256 = '1.2.840.113549.1.1.11';

export interface ParsedCades {
  signedAttrsDer: Uint8Array;
  signatureValue: Uint8Array;
  messageDigest: Uint8Array;
  digestAlgorithmOid: string;
  signatureAlgorithmOid: string;
  leafCertDer: Uint8Array;
  intermediateCertDer: Uint8Array;
}

export function parseCades(p7s: Uint8Array): ParsedCades {
  let contentInfo: ContentInfo;
  try {
    const ber = bytesToArrayBuffer(p7s);
    const asn = asn1js.fromBER(ber);
    if (asn.offset === -1) {
      throw new Error('asn1: invalid BER');
    }
    contentInfo = new ContentInfo({ schema: asn.result });
  } catch (cause) {
    throw new QkbError('cades.parse', { reason: 'asn1', cause: String(cause) });
  }

  if (contentInfo.contentType !== id_ContentType_SignedData) {
    throw new QkbError('cades.parse', {
      reason: 'not-signed-data',
      contentType: contentInfo.contentType,
    });
  }

  let signed: SignedData;
  try {
    signed = new SignedData({ schema: contentInfo.content });
  } catch (cause) {
    throw new QkbError('cades.parse', { reason: 'signed-data-schema', cause: String(cause) });
  }

  if (
    signed.encapContentInfo.eContent !== undefined &&
    signed.encapContentInfo.eContent.valueBlock.valueHexView.byteLength > 0
  ) {
    throw new QkbError('cades.parse', { reason: 'expected-detached' });
  }

  if (signed.signerInfos.length !== 1) {
    throw new QkbError('cades.parse', {
      reason: 'signer-count',
      got: signed.signerInfos.length,
    });
  }
  const signer = signed.signerInfos[0] as SignerInfo;

  if (!signer.signedAttrs) {
    throw new QkbError('cades.parse', { reason: 'missing-signed-attrs' });
  }

  const digestAlgorithmOid = signer.digestAlgorithm.algorithmId;
  if (digestAlgorithmOid !== OID_SHA256) {
    throw new QkbError('cades.parse', {
      reason: 'digest-alg',
      oid: digestAlgorithmOid,
    });
  }

  const signatureAlgorithmOid = signer.signatureAlgorithm.algorithmId;
  if (signatureAlgorithmOid !== OID_RSA && signatureAlgorithmOid !== OID_RSA_SHA256) {
    throw new QkbError('cades.parse', {
      reason: 'signature-alg',
      oid: signatureAlgorithmOid,
    });
  }

  const mdAttr = signer.signedAttrs.attributes.find((a) => a.type === OID_MESSAGE_DIGEST);
  if (!mdAttr) {
    throw new QkbError('cades.parse', { reason: 'missing-message-digest' });
  }
  const mdValues = mdAttr.values;
  if (mdValues.length !== 1) {
    throw new QkbError('cades.parse', { reason: 'message-digest-multi' });
  }
  const mdAsn = mdValues[0] as asn1js.OctetString;
  const messageDigest = new Uint8Array(mdAsn.valueBlock.valueHexView);
  if (messageDigest.length !== 32) {
    throw new QkbError('cades.parse', {
      reason: 'message-digest-length',
      got: messageDigest.length,
    });
  }

  const signedAttrsDer = encodeSignedAttrsForSignature(signer);
  const signatureValue = new Uint8Array(signer.signature.valueBlock.valueHexView);

  const certs = (signed.certificates ?? []).filter(
    (c): c is Certificate => c instanceof Certificate,
  );
  if (certs.length < 2) {
    throw new QkbError('cades.parse', { reason: 'cert-count', got: certs.length });
  }

  const sid = signer.sid;
  const leaf = findLeafBySid(certs, sid);
  if (!leaf) {
    throw new QkbError('cades.parse', { reason: 'leaf-not-found' });
  }
  const intermediate = findIssuer(certs, leaf);
  if (!intermediate) {
    throw new QkbError('cades.parse', { reason: 'intermediate-not-found' });
  }

  return {
    signedAttrsDer,
    signatureValue,
    messageDigest,
    digestAlgorithmOid,
    signatureAlgorithmOid,
    leafCertDer: certDer(leaf),
    intermediateCertDer: certDer(intermediate),
  };
}

function encodeSignedAttrsForSignature(signer: SignerInfo): Uint8Array {
  if (!signer.signedAttrs) {
    throw new QkbError('cades.parse', { reason: 'missing-signed-attrs' });
  }
  const set = new asn1js.Set({
    value: signer.signedAttrs.attributes.map((a) => a.toSchema()),
  });
  return new Uint8Array(set.toBER(false));
}

function findLeafBySid(
  certs: readonly Certificate[],
  sid: SignerInfo['sid'],
): Certificate | undefined {
  if (sid instanceof IssuerAndSerialNumber) {
    return certs.find(
      (c) =>
        c.serialNumber.isEqual(sid.serialNumber) &&
        rdnEqual(c.issuer, sid.issuer),
    );
  }
  return undefined;
}

function findIssuer(
  certs: readonly Certificate[],
  leaf: Certificate,
): Certificate | undefined {
  return certs.find((c) => c !== leaf && rdnEqual(c.subject, leaf.issuer));
}

function rdnEqual(a: { toSchema(): asn1js.AsnType }, b: { toSchema(): asn1js.AsnType }): boolean {
  const ad = new Uint8Array(a.toSchema().toBER(false));
  const bd = new Uint8Array(b.toSchema().toBER(false));
  if (ad.length !== bd.length) return false;
  for (let i = 0; i < ad.length; i++) if (ad[i] !== bd[i]) return false;
  return true;
}

function certDer(cert: Certificate): Uint8Array {
  return new Uint8Array(cert.toSchema().toBER(false));
}

function bytesToArrayBuffer(b: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  return ab;
}
