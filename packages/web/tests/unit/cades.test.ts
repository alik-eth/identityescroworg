import { describe, expect, it, beforeAll } from 'vitest';
import forge from 'node-forge';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { sha256 } from '@noble/hashes/sha256';
import { parseCades } from '../../src/lib/cades';

pkijs.setEngine(
  'node-webcrypto',
  new pkijs.CryptoEngine({ name: 'node', crypto: globalThis.crypto }),
);

interface Fixture {
  rootKey: forge.pki.rsa.KeyPair;
  intKey: forge.pki.rsa.KeyPair;
  leafKey: forge.pki.rsa.KeyPair;
  rootCert: forge.pki.Certificate;
  intCert: forge.pki.Certificate;
  leafCert: forge.pki.Certificate;
  binding: Uint8Array;
  validCms: Uint8Array;
}

let f: Fixture;

beforeAll(() => {
  f = makeFixture();
}, 60_000);

describe('parseCades — happy path', () => {
  it('extracts signedAttrs, signature, messageDigest, leaf + intermediate DER', () => {
    const parsed = parseCades(f.validCms);
    expect(parsed.digestAlgorithmOid).toBe('2.16.840.1.101.3.4.2.1');
    expect(['1.2.840.113549.1.1.1', '1.2.840.113549.1.1.11']).toContain(
      parsed.signatureAlgorithmOid,
    );
    expect(parsed.messageDigest.length).toBe(32);
    const expected = sha256(f.binding);
    expect(toHex(parsed.messageDigest)).toBe(toHex(expected));
    expect(parsed.signatureValue.length).toBeGreaterThan(0);
    expect(parsed.signedAttrsDer.length).toBeGreaterThan(0);
    expect(parsed.leafCertDer.length).toBeGreaterThan(0);
    expect(parsed.intermediateCertDer.length).toBeGreaterThan(0);
    expect(toHex(parsed.leafCertDer)).not.toBe(toHex(parsed.intermediateCertDer));
    expect(parsed.leafAlg).toBe('rsaEncryption');
    expect(parsed.algorithmTag).toBe(0);
  });

  it('signedAttrs parsed back round-trips to a SET (DER form re-parseable)', () => {
    const parsed = parseCades(f.validCms);
    const ab = new ArrayBuffer(parsed.signedAttrsDer.byteLength);
    new Uint8Array(ab).set(parsed.signedAttrsDer);
    const decoded = asn1js.fromBER(ab);
    expect(decoded.offset).not.toBe(-1);
    expect(decoded.result instanceof asn1js.Set).toBe(true);
  });

  it('classifies an ECDSA P-256 leaf as algorithmTag=1', async () => {
    const cms = await makeEcdsaCms();
    const parsed = parseCades(cms);
    expect(parsed.leafAlg).toBe('ecdsa-with-SHA256');
    expect(parsed.algorithmTag).toBe(1);
    expect(parsed.signatureAlgorithmOid).toBe('1.2.840.10045.4.3.2');
  });
});

describe('parseCades — error fixtures', () => {
  it('rejects garbage bytes with cades.parse', () => {
    const bad = new Uint8Array([1, 2, 3, 4]);
    expect(() => parseCades(bad)).toThrowError(
      expect.objectContaining({ code: 'cades.parse' }) as unknown as Error,
    );
  });

  it('rejects an empty buffer', () => {
    expect(() => parseCades(new Uint8Array(0))).toThrowError(
      expect.objectContaining({ code: 'cades.parse' }) as unknown as Error,
    );
  });

  it('rejects a non-SignedData ContentInfo', () => {
    const data = new asn1js.OctetString({ valueHex: new Uint8Array([0x42]).buffer });
    const ci = new asn1js.Sequence({
      value: [
        new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }),
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 0 },
          value: [data],
        }),
      ],
    });
    const der = new Uint8Array(ci.toBER(false));
    expect(() => parseCades(der)).toThrowError(
      expect.objectContaining({ code: 'cades.parse' }) as unknown as Error,
    );
  });

  it('rejects CMS with two signers', () => {
    const cms = makeCms(f, { binding: f.binding, signers: 2 });
    expect(() => parseCades(cms)).toThrowError(
      expect.objectContaining({ code: 'cades.parse' }) as unknown as Error,
    );
  });

  it('rejects CMS with no signed attributes', () => {
    const cms = makeCms(f, { binding: f.binding, omitSignedAttrs: true });
    expect(() => parseCades(cms)).toThrowError(
      expect.objectContaining({ code: 'cades.parse' }) as unknown as Error,
    );
  });

  it('rejects CMS whose digest algorithm is sha-1', () => {
    const cms = makeCms(f, { binding: f.binding, digestAlgo: 'sha1' });
    expect(() => parseCades(cms)).toThrowError(
      expect.objectContaining({ code: 'cades.parse' }) as unknown as Error,
    );
  });

  it('rejects CMS missing the messageDigest attribute', () => {
    const cms = makeCms(f, { binding: f.binding, dropMessageDigest: true });
    expect(() => parseCades(cms)).toThrowError(
      expect.objectContaining({ code: 'cades.parse' }) as unknown as Error,
    );
  });

  it('rejects CMS missing intermediate certificate', () => {
    const cms = makeCms(f, { binding: f.binding, dropIntermediate: true });
    expect(() => parseCades(cms)).toThrowError(
      expect.objectContaining({ code: 'cades.parse' }) as unknown as Error,
    );
  });
});

interface MakeCmsOpts {
  binding: Uint8Array;
  signers?: number;
  omitSignedAttrs?: boolean;
  digestAlgo?: 'sha256' | 'sha1';
  dropMessageDigest?: boolean;
  dropIntermediate?: boolean;
}

function makeCms(fx: Fixture, opts: MakeCmsOpts): Uint8Array {
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(uint8ToBinary(opts.binding));
  p7.addCertificate(fx.leafCert);
  if (!opts.dropIntermediate) p7.addCertificate(fx.intCert);
  const digestAlgo = opts.digestAlgo ?? 'sha256';
  const baseAttrs: Array<{ type: string; value?: string }> = [
    { type: forge.pki.oids.contentType!, value: forge.pki.oids.data! },
    { type: forge.pki.oids.signingTime!, value: new Date() as unknown as string },
    { type: forge.pki.oids.messageDigest! },
  ];
  const n = opts.signers ?? 1;
  for (let i = 0; i < n; i++) {
    p7.addSigner({
      key: fx.leafKey.privateKey,
      certificate: fx.leafCert,
      digestAlgorithm: forge.pki.oids[digestAlgo] as string,
      ...(opts.omitSignedAttrs ? {} : { authenticatedAttributes: baseAttrs }),
    });
  }
  p7.sign({ detached: true });

  if (opts.dropMessageDigest) {
    return mutateRemoveMessageDigest(toDer(p7));
  }
  return toDer(p7);
}

function toDer(p7: forge.pkcs7.PkcsSignedData): Uint8Array {
  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  const out = new Uint8Array(der.length);
  for (let i = 0; i < der.length; i++) out[i] = der.charCodeAt(i) & 0xff;
  return out;
}

function mutateRemoveMessageDigest(der: Uint8Array): Uint8Array {
  // Re-parse, walk to signerInfo.authenticatedAttributes, drop the
  // messageDigest attribute, re-serialize. We do this generically using
  // node-forge's ASN.1 layer so we don't have to hand-edit DER offsets.
  const asn1 = forge.asn1.fromDer(uint8ToBinary(der));
  // ContentInfo -> [0] -> SignedData
  const signedData = (asn1.value[1] as forge.asn1.Asn1).value[0] as forge.asn1.Asn1;
  // SignedData fields: version[0], digestAlgs[1], encapCI[2], certs[3, opt],
  // crls[opt], signerInfos (last SET).
  const last = signedData.value[signedData.value.length - 1] as forge.asn1.Asn1;
  const signerInfo = last.value[0] as forge.asn1.Asn1;
  const authAttrs = (signerInfo.value as forge.asn1.Asn1[]).find(
    (v) => v.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && v.type === 0,
  );
  if (!authAttrs) throw new Error('no authenticatedAttributes to mutate');
  const attrs = authAttrs.value as forge.asn1.Asn1[];
  const filtered = attrs.filter((attr) => {
    const oidNode = (attr.value as forge.asn1.Asn1[])[0] as forge.asn1.Asn1;
    const oid = forge.asn1.derToOid(oidNode.value as string);
    return oid !== forge.pki.oids.messageDigest!;
  });
  authAttrs.value = filtered;
  const reser = forge.asn1.toDer(asn1).getBytes();
  const out = new Uint8Array(reser.length);
  for (let i = 0; i < reser.length; i++) out[i] = reser.charCodeAt(i) & 0xff;
  return out;
}

function makeFixture(): Fixture {
  const rootKey = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const intKey = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const leafKey = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const rootCert = mkCert({
    subject: 'Root',
    issuer: 'Root',
    pub: rootKey.publicKey,
    signKey: rootKey.privateKey,
    isCa: true,
  });
  const intCert = mkCert({
    subject: 'Int',
    issuer: 'Root',
    pub: intKey.publicKey,
    signKey: rootKey.privateKey,
    isCa: true,
  });
  const leafCert = mkCert({
    subject: 'Leaf',
    issuer: 'Int',
    pub: leafKey.publicKey,
    signKey: intKey.privateKey,
    isCa: false,
  });
  const binding = new TextEncoder().encode(JSON.stringify({ v: 'QKB/1.0', ts: 1 }));
  const validCms = (() => {
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(uint8ToBinary(binding));
    p7.addCertificate(leafCert);
    p7.addCertificate(intCert);
    const attrs: Array<{ type: string; value?: string }> = [
      { type: forge.pki.oids.contentType!, value: forge.pki.oids.data! },
      { type: forge.pki.oids.signingTime!, value: new Date() as unknown as string },
      { type: forge.pki.oids.messageDigest! },
    ];
    p7.addSigner({
      key: leafKey.privateKey,
      certificate: leafCert,
      digestAlgorithm: forge.pki.oids.sha256!,
      authenticatedAttributes: attrs,
    });
    p7.sign({ detached: true });
    return toDer(p7);
  })();
  return { rootKey, intKey, leafKey, rootCert, intCert, leafCert, binding, validCms };
}

async function makeEcdsaCms(): Promise<Uint8Array> {
  const ca = await mkPkijsCert({ subject: 'EC-Root', issuerCert: null, isCa: true });
  const leaf = await mkPkijsCert({
    subject: 'EC-Leaf',
    issuerCert: ca,
    isCa: false,
  });
  const binding = new TextEncoder().encode('hello-ecdsa');
  const md = sha256(binding);
  const signedAttrs = new pkijs.SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      new pkijs.Attribute({
        type: '1.2.840.113549.1.9.3',
        values: [new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' })],
      }),
      new pkijs.Attribute({
        type: '1.2.840.113549.1.9.4',
        values: [new asn1js.OctetString({ valueHex: md.buffer.slice(0) as ArrayBuffer })],
      }),
    ],
  });
  const signerInfo = new pkijs.SignerInfo({
    version: 1,
    sid: new pkijs.IssuerAndSerialNumber({
      issuer: leaf.cert.issuer,
      serialNumber: leaf.cert.serialNumber,
    }),
    signedAttrs,
  });
  const signed = new pkijs.SignedData({
    version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: '1.2.840.113549.1.7.1',
    }),
    signerInfos: [signerInfo],
    certificates: [leaf.cert, ca.cert],
  });
  await signed.sign(leaf.privateKey, 0, 'SHA-256');
  const ci = new pkijs.ContentInfo({
    contentType: pkijs.id_ContentType_SignedData,
    content: signed.toSchema(true),
  });
  return new Uint8Array(ci.toSchema().toBER(false));
}

interface PkijsCertResult {
  cert: pkijs.Certificate;
  privateKey: CryptoKey;
}

async function mkPkijsCert(opts: {
  subject: string;
  issuerCert: PkijsCertResult | null;
  isCa: boolean;
}): Promise<PkijsCertResult> {
  const subtle = globalThis.crypto.subtle;
  const algo = { name: 'ECDSA', namedCurve: 'P-256' } as const;
  const kp = await subtle.generateKey(algo, true, ['sign', 'verify']);
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({
    value: Math.floor(Math.random() * 1_000_000_000),
  });
  const issuerName = opts.issuerCert ? opts.issuerCert.cert.subject : undefined;
  setName(cert.subject, opts.subject);
  if (issuerName) {
    cert.issuer = issuerName;
  } else {
    setName(cert.issuer, opts.subject);
  }
  cert.notBefore.value = new Date(Date.now() - 60_000);
  cert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  await cert.subjectPublicKeyInfo.importKey(kp.publicKey);
  const signWith = opts.issuerCert ? opts.issuerCert.privateKey : kp.privateKey;
  await cert.sign(signWith, 'SHA-256');
  return { cert, privateKey: kp.privateKey };
}

function setName(target: pkijs.RelativeDistinguishedNames, cn: string): void {
  target.typesAndValues = [
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.Utf8String({ value: cn }),
    }),
  ];
}

function mkCert(opts: {
  subject: string;
  issuer: string;
  pub: forge.pki.rsa.PublicKey;
  signKey: forge.pki.rsa.PrivateKey;
  isCa: boolean;
}): forge.pki.Certificate {
  const cert = forge.pki.createCertificate();
  cert.publicKey = opts.pub;
  cert.serialNumber = String(Math.floor(Math.random() * 1e9));
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  cert.setSubject([{ name: 'commonName', value: opts.subject }]);
  cert.setIssuer([{ name: 'commonName', value: opts.issuer }]);
  cert.setExtensions([
    { name: 'basicConstraints', cA: opts.isCa },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyCertSign: opts.isCa,
    },
  ]);
  cert.sign(opts.signKey, forge.md.sha256.create());
  return cert;
}

function uint8ToBinary(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return s;
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
