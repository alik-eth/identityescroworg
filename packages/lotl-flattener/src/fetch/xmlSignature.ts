import { constants, X509Certificate, createHash, createSign, createVerify } from 'node:crypto';
import { DOMParser } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';

const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
const ELEMENT_NODE = 1;
const RSA_PSS_SHA256 = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';
const ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
const ECDSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
const ECDSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';

interface XmlNodeLike {
  nodeType: number;
  localName?: string | null;
  namespaceURI?: string | null;
  prefix?: string | null;
  firstChild: XmlNodeLike | null;
  nextSibling: XmlNodeLike | null;
}

export interface XmlSignatureVerifyOpts {
  /** DER X.509 certs or PEM cert/public-key strings allowed to verify this XML. */
  trustedCerts?: readonly (Uint8Array | string)[];
  /** Expected local name of the signed root element, e.g. TrustServiceStatusList. */
  expectedRootLocalName?: string;
}

export interface XmlSignatureVerifyResult {
  ok: boolean;
  authenticatedXml?: string;
  signedReferenceCount: number;
  error?: string;
}

export interface XmlSignatureCertificateInfo {
  der: Uint8Array;
  subjectDN?: string;
  issuerDN?: string;
  serialNumber?: string;
  notBefore?: number;
  notAfter?: number;
  sha256Hex: string;
  sha1Hex: string;
  sha256Base64: string;
  sha1Base64: string;
}

export function installXmlSignatureAlgorithms(sig: SignedXml): void {
  sig.SignatureAlgorithms[RSA_PSS_SHA256] = RsaPssSha256;
  sig.SignatureAlgorithms[ECDSA_SHA256] = EcdsaSha256;
  sig.SignatureAlgorithms[ECDSA_SHA384] = EcdsaSha384;
  sig.SignatureAlgorithms[ECDSA_SHA512] = EcdsaSha512;
}

export function verifyXmlSignature(
  xml: string,
  opts: XmlSignatureVerifyOpts = {},
): XmlSignatureVerifyResult {
  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  const signatures = findSignatureNodes(doc);
  if (signatures.length === 0) {
    return { ok: false, signedReferenceCount: 0, error: 'missing-signature' };
  }

  const certs = opts.trustedCerts?.length ? opts.trustedCerts.map(certToPem) : [undefined];
  let lastError = 'invalid-signature';
  for (const signature of signatures) {
    for (const cert of certs) {
      const sig = new SignedXml(
        cert
          ? { publicCert: cert, getCertFromKeyInfo: () => null }
          : { getCertFromKeyInfo: SignedXml.getCertFromKeyInfo },
      );
      installXmlSignatureAlgorithms(sig);
      try {
        sig.loadSignature(signature as never);
        if (!sig.checkSignature(xml)) {
          lastError = 'check-signature-false';
          continue;
        }
        const signedReferences = sig.getSignedReferences();
        const authenticatedXml = signedReferences[0];
        if (!authenticatedXml) {
          lastError = 'missing-signed-reference';
          continue;
        }
        if (
          opts.expectedRootLocalName &&
          rootLocalName(authenticatedXml) !== opts.expectedRootLocalName
        ) {
          lastError = 'signed-reference-root-mismatch';
          continue;
        }
        return {
          ok: true,
          authenticatedXml,
          signedReferenceCount: signedReferences.length,
        };
      } catch (cause) {
        lastError = cause instanceof Error ? cause.message : String(cause);
      }
    }
  }

  return { ok: false, signedReferenceCount: 0, error: lastError };
}

class RsaPssSha256 {
  getAlgorithmName(): string {
    return RSA_PSS_SHA256;
  }

  getSignature(signedInfo: string, privateKey: string): string {
    const signer = createSign('RSA-SHA256');
    signer.update(signedInfo);
    return signer.sign(
      {
        key: privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
      },
      'base64',
    );
  }

  verifySignature(material: string, key: string, signatureValue: string): boolean {
    const verifier = createVerify('RSA-SHA256');
    verifier.update(material);
    return verifier.verify(
      {
        key,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
      },
      signatureValue,
      'base64',
    );
  }
}

class EcdsaAlgorithm {
  constructor(
    private readonly algorithmUri: string,
    private readonly nodeAlgorithm: 'SHA256' | 'SHA384' | 'SHA512',
  ) {}

  getAlgorithmName(): string {
    return this.algorithmUri;
  }

  getSignature(signedInfo: string, privateKey: string): string {
    const signer = createSign(this.nodeAlgorithm);
    signer.update(signedInfo);
    const der = signer.sign(privateKey);
    return derToJose(der, 132).toString('base64');
  }

  verifySignature(material: string, key: string, signatureValue: string): boolean {
    const verifier = createVerify(this.nodeAlgorithm);
    verifier.update(material);
    return verifier.verify(key, joseToDer(Buffer.from(signatureValue, 'base64')));
  }
}

class EcdsaSha256 extends EcdsaAlgorithm {
  constructor() {
    super(ECDSA_SHA256, 'SHA256');
  }
}

class EcdsaSha384 extends EcdsaAlgorithm {
  constructor() {
    super(ECDSA_SHA384, 'SHA384');
  }
}

class EcdsaSha512 extends EcdsaAlgorithm {
  constructor() {
    super(ECDSA_SHA512, 'SHA512');
  }
}

function derToJose(signature: Buffer, rawLength: number): Buffer {
  if (signature[0] !== 0x30) throw new Error('invalid ECDSA DER signature');
  let offset = 2;
  if (signature[1] === 0x81) offset = 3;
  else if (signature[1] === 0x82) offset = 4;
  if (signature[offset] !== 0x02) throw new Error('invalid ECDSA DER signature');
  const rLength = signature[offset + 1];
  if (rLength === undefined) throw new Error('invalid ECDSA DER signature');
  const r = signature.subarray(offset + 2, offset + 2 + rLength);
  offset += 2 + rLength;
  if (signature[offset] !== 0x02) throw new Error('invalid ECDSA DER signature');
  const sLength = signature[offset + 1];
  if (sLength === undefined) throw new Error('invalid ECDSA DER signature');
  const s = signature.subarray(offset + 2, offset + 2 + sLength);
  return Buffer.concat([leftPadUnsigned(r, rawLength / 2), leftPadUnsigned(s, rawLength / 2)]);
}

function joseToDer(signature: Buffer): Buffer {
  const n = signature.length / 2;
  if (!Number.isInteger(n)) throw new Error('invalid ECDSA raw signature length');
  const r = derInteger(signature.subarray(0, n));
  const s = derInteger(signature.subarray(n));
  return derSequence(Buffer.concat([r, s]));
}

function leftPadUnsigned(v: Buffer, length: number): Buffer {
  let out = v;
  while (out.length > 0 && out[0] === 0) out = out.subarray(1);
  if (out.length > length) throw new Error('ECDSA integer too large');
  return Buffer.concat([Buffer.alloc(length - out.length), out]);
}

function derInteger(v: Buffer): Buffer {
  let out = v;
  while (out.length > 0 && out[0] === 0) out = out.subarray(1);
  if (out.length === 0) out = Buffer.from([0]);
  const first = out[0];
  if (first === undefined) throw new Error('invalid ECDSA integer');
  if (first & 0x80) out = Buffer.concat([Buffer.from([0]), out]);
  return Buffer.concat([Buffer.from([0x02]), derLength(out.length), out]);
}

function derSequence(content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x30]), derLength(content.length), content]);
}

function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function findSignatureNodes(doc: XmlNodeLike): XmlNodeLike[] {
  const out: XmlNodeLike[] = [];
  const visit = (node: XmlNodeLike): void => {
    if (
      node.nodeType === ELEMENT_NODE &&
      node.localName === 'Signature' &&
      (node.namespaceURI === DSIG_NS || node.prefix === 'ds')
    ) {
      out.push(node);
    }
    for (let child = node.firstChild; child; child = child.nextSibling) visit(child);
  };
  visit(doc);
  return out;
}

export function extractXmlSignatureCertificates(xml: string): XmlSignatureCertificateInfo[] {
  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  const signatures = findSignatureNodes(doc);
  const out: XmlSignatureCertificateInfo[] = [];
  for (const signature of signatures) {
    const certNodes = findElements(signature, 'X509Certificate', DSIG_NS);
    for (const node of certNodes) {
      const b64 = textContent(node).replace(/\s+/g, '');
      if (!b64) continue;
      const der = Uint8Array.from(Buffer.from(b64, 'base64'));
      out.push(certInfo(der));
    }
  }
  return out;
}

function findElements(root: XmlNodeLike, localName: string, namespace?: string): XmlNodeLike[] {
  const out: XmlNodeLike[] = [];
  const visit = (node: XmlNodeLike): void => {
    if (
      node.nodeType === ELEMENT_NODE &&
      node.localName === localName &&
      (!namespace || node.namespaceURI === namespace || node.prefix === 'ds')
    ) {
      out.push(node);
    }
    for (let child = node.firstChild; child; child = child.nextSibling) visit(child);
  };
  visit(root);
  return out;
}

function textContent(node: XmlNodeLike): string {
  const chunks: string[] = [];
  const visit = (n: XmlNodeLike): void => {
    const maybeText = n as XmlNodeLike & { data?: string; nodeValue?: string | null };
    if (typeof maybeText.data === 'string') chunks.push(maybeText.data);
    else if (typeof maybeText.nodeValue === 'string') chunks.push(maybeText.nodeValue);
    for (let child = n.firstChild; child; child = child.nextSibling) visit(child);
  };
  visit(node);
  return chunks.join('');
}

function certInfo(der: Uint8Array): XmlSignatureCertificateInfo {
  const cert = parseCert(der);
  const sha256 = digest('sha256', der);
  const sha1 = digest('sha1', der);
  return {
    der,
    ...(cert ? { subjectDN: cert.subject, issuerDN: cert.issuer } : {}),
    ...(cert ? { serialNumber: cert.serialNumber } : {}),
    ...(cert ? { notBefore: Math.floor(Date.parse(cert.validFrom) / 1000) } : {}),
    ...(cert ? { notAfter: Math.floor(Date.parse(cert.validTo) / 1000) } : {}),
    sha256Hex: sha256.toString('hex'),
    sha1Hex: sha1.toString('hex'),
    sha256Base64: sha256.toString('base64'),
    sha1Base64: sha1.toString('base64'),
  };
}

function parseCert(der: Uint8Array): X509Certificate | null {
  try {
    return new X509Certificate(Buffer.from(der));
  } catch {
    return null;
  }
}

function digest(algorithm: 'sha1' | 'sha256', bytes: Uint8Array): Buffer {
  return createHash(algorithm).update(bytes).digest();
}

function rootLocalName(xml: string): string | undefined {
  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  return doc.documentElement?.localName ?? undefined;
}

function certToPem(cert: Uint8Array | string): string {
  if (typeof cert === 'string') return cert;
  const b64 = Buffer.from(cert).toString('base64');
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}
