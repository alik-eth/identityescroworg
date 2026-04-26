/**
 * CAdES-BES detached parser for `binding.qkb.json.p7s`.
 *
 * Strict by design — anything unexpected raises QkbError('cades.parse').
 * Hard requirements (orchestration §4.3 / §2.0 / spec §4.3):
 *   - ContentInfo.contentType == id-signedData (1.2.840.113549.1.7.2).
 *   - eContent absent (detached signature).
 *   - exactly ONE SignerInfo.
 *   - signedAttrs MUST be present and MUST contain a `messageDigest` attribute
 *     (1.2.840.113549.1.9.4) of the right length for the chosen digest.
 *   - digestAlgorithm == sha-256 (2.16.840.1.101.3.4.2.1) for Phase 1.
 *   - SignerInfo.signatureAlgorithm is one of:
 *       * rsaEncryption (1.2.840.113549.1.1.1)
 *       * sha256WithRSAEncryption (1.2.840.113549.1.1.11)
 *       * ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
 *   - certificates field present with at least leaf + one intermediate.
 *
 * Leaf cert is the one matching the SignerInfo's IssuerAndSerialNumber.
 * Intermediate is the cert in the SET that issued the leaf (subject DN ==
 * leaf.issuer DN).
 *
 * `leafAlg` / `algorithmTag` are derived from the leaf cert's
 * SubjectPublicKeyInfo.algorithm, which determines which circuit variant
 * (RSA vs ECDSA) the witness builder must target. ECDSA leafs must use
 * NIST P-256 (1.2.840.10045.3.1.7); other curves are rejected.
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
import { QkbError } from '../errors/index.js';

const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_RSA = '1.2.840.113549.1.1.1';
const OID_RSA_SHA256 = '1.2.840.113549.1.1.11';
const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_P256 = '1.2.840.10045.3.1.7';

export type LeafAlg = 'rsaEncryption' | 'ecdsa-with-SHA256';
export const ALGORITHM_TAG_RSA = 0 as const;
export const ALGORITHM_TAG_ECDSA = 1 as const;
export type AlgorithmTag = typeof ALGORITHM_TAG_RSA | typeof ALGORITHM_TAG_ECDSA;

export interface ParsedCades {
  signedAttrsDer: Uint8Array;
  signatureValue: Uint8Array;
  messageDigest: Uint8Array;
  digestAlgorithmOid: string;
  signatureAlgorithmOid: string;
  leafAlg: LeafAlg;
  algorithmTag: AlgorithmTag;
  leafCertDer: Uint8Array;
  /** DER-encoded leaf cert `issuer` Name. Used to resolve the intermediate
   *  from `trusted-cas.json` by issuer-DN match when the CMS only ships the
   *  leaf (Diia-style CAdES-BES — the intermediate must come from LOTL). */
  leafIssuerDer: Uint8Array;
  /** Inline intermediate when the CMS contains one (zk-email / Adobe-style
   *  CAdES-BES); `null` when the signer shipped a leaf-only CMS and the
   *  caller must resolve the intermediate from LOTL. */
  intermediateCertDer: Uint8Array | null;
  /** When the signer emitted an *attached* (enveloping) CAdES-BES, the
   *  signed binding lives in `encapContentInfo.eContent`. Diia and many
   *  EU QES tools default to attached; the spec permits both shapes.
   *  `null` for detached CAdES where the caller supplies the binding
   *  bytes out-of-band. */
  embeddedContent: Uint8Array | null;
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

  // CAdES-BES supports both *detached* (eContent omitted) and *attached*
  // (eContent carries the signed bytes). We accept both — real QES tools
  // including Diia default to attached. Callers that want a strict-
  // detached policy can check `embeddedContent === null` themselves.
  let embeddedContent: Uint8Array | null = null;
  if (
    signed.encapContentInfo.eContent !== undefined &&
    signed.encapContentInfo.eContent.valueBlock.valueHexView.byteLength > 0
  ) {
    embeddedContent = new Uint8Array(signed.encapContentInfo.eContent.valueBlock.valueHexView);
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
  if (
    signatureAlgorithmOid !== OID_RSA &&
    signatureAlgorithmOid !== OID_RSA_SHA256 &&
    signatureAlgorithmOid !== OID_ECDSA_SHA256
  ) {
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
  if (certs.length < 1) {
    throw new QkbError('cades.parse', { reason: 'cert-count', got: certs.length });
  }

  const sid = signer.sid;
  const leaf = findLeafBySid(certs, sid);
  if (!leaf) {
    throw new QkbError('cades.parse', { reason: 'leaf-not-found' });
  }
  // Intermediate is OPTIONAL at parse time. Many real-world QES profiles
  // (Diia among them) ship a leaf-only CMS and expect the relying party to
  // resolve the intermediate from a trusted list (LOTL). qesVerify.ts does
  // that resolution against `trusted-cas.json`.
  const intermediate = findIssuer(certs, leaf) ?? null;

  const { leafAlg, algorithmTag } = classifyLeaf(leaf, signatureAlgorithmOid);

  return {
    signedAttrsDer,
    signatureValue,
    messageDigest,
    digestAlgorithmOid,
    signatureAlgorithmOid,
    leafAlg,
    algorithmTag,
    leafCertDer: certDer(leaf),
    leafIssuerDer: rdnDer(leaf.issuer),
    intermediateCertDer: intermediate ? certDer(intermediate) : null,
    embeddedContent,
  };
}

function rdnDer(rdn: { toSchema(): asn1js.AsnType }): Uint8Array {
  return new Uint8Array(rdn.toSchema().toBER(false));
}

function classifyLeaf(
  leaf: Certificate,
  sigAlgOid: string,
): { leafAlg: LeafAlg; algorithmTag: AlgorithmTag } {
  const spkiAlg = leaf.subjectPublicKeyInfo.algorithm.algorithmId;
  if (spkiAlg === OID_RSA) {
    if (sigAlgOid !== OID_RSA && sigAlgOid !== OID_RSA_SHA256) {
      throw new QkbError('cades.parse', {
        reason: 'leaf-alg-mismatch',
        spki: spkiAlg,
        sig: sigAlgOid,
      });
    }
    return { leafAlg: 'rsaEncryption', algorithmTag: ALGORITHM_TAG_RSA };
  }
  if (spkiAlg === OID_EC_PUBLIC_KEY) {
    if (sigAlgOid !== OID_ECDSA_SHA256) {
      throw new QkbError('cades.parse', {
        reason: 'leaf-alg-mismatch',
        spki: spkiAlg,
        sig: sigAlgOid,
      });
    }
    const curveParam = leaf.subjectPublicKeyInfo.algorithm.algorithmParams;
    const curveOid =
      curveParam instanceof asn1js.ObjectIdentifier
        ? curveParam.valueBlock.toString()
        : undefined;
    if (curveOid !== OID_P256) {
      throw new QkbError('cades.parse', { reason: 'ecdsa-curve', curve: curveOid });
    }
    return { leafAlg: 'ecdsa-with-SHA256', algorithmTag: ALGORITHM_TAG_ECDSA };
  }
  throw new QkbError('cades.parse', { reason: 'leaf-spki-alg', oid: spkiAlg });
}

/**
 * Standalone algorithm detection from a leaf cert DER (spec §14.1,
 * orchestration §0 S0.2). Used by consumers that have a parsed cert but
 * not a full CMS — e.g., the QIE recovery path that reconstructs a
 * binding from `R` and needs to route to the right prover variant.
 *
 * Throws QkbError('cades.parse') with a typed reason when the SPKI
 * algorithm is neither rsaEncryption nor an EC key on P-256.
 */
export function detectAlgorithmTag(leafCertDer: Uint8Array): AlgorithmTag {
  let cert: Certificate;
  try {
    const asn = asn1js.fromBER(bytesToArrayBuffer(leafCertDer));
    if (asn.offset === -1) throw new Error('asn1');
    cert = new Certificate({ schema: asn.result });
  } catch (cause) {
    throw new QkbError('cades.parse', { reason: 'cert-asn1', cause: String(cause) });
  }
  const spkiAlg = cert.subjectPublicKeyInfo.algorithm.algorithmId;
  if (spkiAlg === OID_RSA) return ALGORITHM_TAG_RSA;
  if (spkiAlg === OID_EC_PUBLIC_KEY) {
    const curveParam = cert.subjectPublicKeyInfo.algorithm.algorithmParams;
    const curveOid =
      curveParam instanceof asn1js.ObjectIdentifier
        ? curveParam.valueBlock.toString()
        : undefined;
    if (curveOid !== OID_P256) {
      throw new QkbError('cades.parse', { reason: 'ecdsa-curve', curve: curveOid });
    }
    return ALGORITHM_TAG_ECDSA;
  }
  throw new QkbError('cades.parse', { reason: 'leaf-spki-alg', oid: spkiAlg });
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
