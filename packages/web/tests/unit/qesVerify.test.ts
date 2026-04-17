import { describe, expect, it, beforeAll } from 'vitest';
import forge from 'node-forge';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { sha256 } from '@noble/hashes/sha256';
import * as secp from '@noble/secp256k1';
import { parseCades, type ParsedCades } from '../../src/lib/cades';
import { verifyQes, type TrustedCasFile } from '../../src/lib/qesVerify';
import {
  buildBinding,
  canonicalizeBinding,
  type Binding,
  type Locale,
} from '../../src/lib/binding';

pkijs.setEngine(
  'node-webcrypto',
  new pkijs.CryptoEngine({ name: 'node', crypto: globalThis.crypto }),
);

interface RsaCmsFixture {
  parsed: ParsedCades;
  binding: Binding;
  bindingBytes: Uint8Array;
  pk: Uint8Array;
  trustedCas: TrustedCasFile;
}

let rsaFx: RsaCmsFixture;
let ecdsaFx: RsaCmsFixture;
let unknownCaTrust: TrustedCasFile;

beforeAll(async () => {
  rsaFx = makeRsaFixture({ locale: 'en' });
  ecdsaFx = await makeEcdsaFixture({ locale: 'en' });
  unknownCaTrust = { version: 1, cas: [] };
}, 60_000);

describe('verifyQes — RSA happy path', () => {
  it('passes a well-formed RSA QES', async () => {
    const r = await verifyQes({
      parsed: rsaFx.parsed,
      binding: rsaFx.binding,
      bindingBytes: rsaFx.bindingBytes,
      expectedPk: rsaFx.pk,
      trustedCas: rsaFx.trustedCas,
    });
    expect(r.ok).toBe(true);
    expect(r.algorithmTag).toBe(0);
    expect(r.caMerkleIndex).toBe(0);
  });
});

describe('verifyQes — ECDSA happy path', () => {
  it('passes a well-formed ECDSA QES', async () => {
    const r = await verifyQes({
      parsed: ecdsaFx.parsed,
      binding: ecdsaFx.binding,
      bindingBytes: ecdsaFx.bindingBytes,
      expectedPk: ecdsaFx.pk,
      trustedCas: ecdsaFx.trustedCas,
    });
    expect(r.ok).toBe(true);
    expect(r.algorithmTag).toBe(1);
    expect(r.caMerkleIndex).toBe(0);
  });
});

describe('verifyQes — failure modes', () => {
  it('digestMismatch: tampered messageDigest', async () => {
    const tampered: ParsedCades = {
      ...rsaFx.parsed,
      messageDigest: new Uint8Array(32),
    };
    await expect(
      verifyQes({
        parsed: tampered,
        binding: rsaFx.binding,
        bindingBytes: rsaFx.bindingBytes,
        expectedPk: rsaFx.pk,
        trustedCas: rsaFx.trustedCas,
      }),
    ).rejects.toMatchObject({ code: 'qes.digestMismatch' });
  });

  it('digestMismatch: pk in B differs from SPA-held pubkey', async () => {
    const otherPk = secp.getPublicKey(secp.utils.randomPrivateKey(), false);
    await expect(
      verifyQes({
        parsed: rsaFx.parsed,
        binding: rsaFx.binding,
        bindingBytes: rsaFx.bindingBytes,
        expectedPk: otherPk,
        trustedCas: rsaFx.trustedCas,
      }),
    ).rejects.toMatchObject({ code: 'qes.digestMismatch' });
  });

  it('digestMismatch: declaration text not whitelisted', async () => {
    const evilBinding: Binding = { ...rsaFx.binding, declaration: 'NOT THE REAL DECLARATION' };
    await expect(
      verifyQes({
        parsed: rsaFx.parsed,
        binding: evilBinding,
        bindingBytes: canonicalizeBinding(evilBinding),
        expectedPk: rsaFx.pk,
        trustedCas: rsaFx.trustedCas,
      }),
    ).rejects.toMatchObject({ code: 'qes.digestMismatch' });
  });

  it('certExpired: timestamp before notBefore', async () => {
    const past: Binding = { ...rsaFx.binding, timestamp: 1 };
    await expect(
      verifyQes({
        parsed: rsaFx.parsed,
        binding: past,
        bindingBytes: rsaFx.bindingBytes,
        expectedPk: rsaFx.pk,
        trustedCas: rsaFx.trustedCas,
      }),
    ).rejects.toMatchObject({ code: 'qes.certExpired' });
  });

  it('certExpired: timestamp after notAfter', async () => {
    const future: Binding = { ...rsaFx.binding, timestamp: 4_000_000_000 };
    await expect(
      verifyQes({
        parsed: rsaFx.parsed,
        binding: future,
        bindingBytes: rsaFx.bindingBytes,
        expectedPk: rsaFx.pk,
        trustedCas: rsaFx.trustedCas,
      }),
    ).rejects.toMatchObject({ code: 'qes.certExpired' });
  });

  it('sigInvalid: tampered signatureValue', async () => {
    const sig = rsaFx.parsed.signatureValue.slice();
    sig[0] = (sig[0] ?? 0) ^ 0xff;
    const tampered: ParsedCades = { ...rsaFx.parsed, signatureValue: sig };
    await expect(
      verifyQes({
        parsed: tampered,
        binding: rsaFx.binding,
        bindingBytes: rsaFx.bindingBytes,
        expectedPk: rsaFx.pk,
        trustedCas: rsaFx.trustedCas,
      }),
    ).rejects.toMatchObject({ code: 'qes.sigInvalid' });
  });

  it('unknownCA: intermediate not in trusted-cas.json', async () => {
    await expect(
      verifyQes({
        parsed: rsaFx.parsed,
        binding: rsaFx.binding,
        bindingBytes: rsaFx.bindingBytes,
        expectedPk: rsaFx.pk,
        trustedCas: unknownCaTrust,
      }),
    ).rejects.toMatchObject({ code: 'qes.unknownCA' });
  });

  it('sigInvalid: chain link fails (intermediate did not sign leaf)', async () => {
    const otherInt = makeRsaFixture({ locale: 'en' });
    const otherIntDer = otherInt.parsed.intermediateCertDer!;
    const swapped: ParsedCades = {
      ...rsaFx.parsed,
      intermediateCertDer: otherIntDer,
    };
    const swappedTrust: TrustedCasFile = {
      version: 1,
      cas: [
        { merkleIndex: 0, certDerB64: bytesToB64(otherIntDer) },
      ],
    };
    await expect(
      verifyQes({
        parsed: swapped,
        binding: rsaFx.binding,
        bindingBytes: rsaFx.bindingBytes,
        expectedPk: rsaFx.pk,
        trustedCas: swappedTrust,
      }),
    ).rejects.toMatchObject({ code: 'qes.sigInvalid' });
  });

  it('leaf-only CMS: PASSES when intermediate is in trusted-cas (LOTL resolution)', async () => {
    // Diia-style: CMS shipped only the leaf. Strip the intermediate from the
    // parsed shape but keep it in the trusted list. qesVerify must resolve
    // the issuer DN against trusted-cas and proceed.
    const fx = makeRsaFixture({ locale: 'en' });
    const intDer = fx.parsed.intermediateCertDer!;
    const leafOnly: ParsedCades = { ...fx.parsed, intermediateCertDer: null };
    const r = await verifyQes({
      parsed: leafOnly,
      binding: fx.binding,
      bindingBytes: fx.bindingBytes,
      expectedPk: fx.pk,
      trustedCas: {
        version: 1,
        cas: [{ merkleIndex: 7, certDerB64: bytesToB64(intDer) }],
      },
    });
    expect(r.ok).toBe(true);
    expect(r.caMerkleIndex).toBe(7);
  });

  it('leaf-only CMS: throws qes.unknownCA(intermediate-not-in-lotl) when issuer absent', async () => {
    const fx = makeRsaFixture({ locale: 'en' });
    const leafOnly: ParsedCades = { ...fx.parsed, intermediateCertDer: null };
    const otherFx = makeRsaFixture({ locale: 'en', cnSuffix: '-Unrelated' });
    const otherIntDer = otherFx.parsed.intermediateCertDer!;
    await expect(
      verifyQes({
        parsed: leafOnly,
        binding: fx.binding,
        bindingBytes: fx.bindingBytes,
        expectedPk: fx.pk,
        trustedCas: {
          version: 1,
          cas: [{ merkleIndex: 0, certDerB64: bytesToB64(otherIntDer) }],
        },
      }),
    ).rejects.toMatchObject({
      code: 'qes.unknownCA',
      details: { reason: 'intermediate-not-in-lotl' },
    });
  });
});

function makeRsaFixture(opts: { locale: Locale; cnSuffix?: string }): RsaCmsFixture {
  const suf = opts.cnSuffix ?? '';
  const rootKey = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const intKey = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const leafKey = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const intCert = mkCert({
    subject: `Int${suf}`,
    issuer: `Root${suf}`,
    pub: intKey.publicKey,
    signKey: rootKey.privateKey,
    isCa: true,
  });
  const leafCert = mkCert({
    subject: `Leaf${suf}`,
    issuer: `Int${suf}`,
    pub: leafKey.publicKey,
    signKey: intKey.privateKey,
    isCa: false,
  });
  const sk = secp.utils.randomPrivateKey();
  const pk = secp.getPublicKey(sk, false);
  const nowSec = Math.floor(Date.now() / 1000);
  const binding = buildBinding({
    pk,
    timestamp: nowSec,
    nonce: secp.utils.randomPrivateKey(),
    locale: opts.locale,
  });
  const bindingBytes = canonicalizeBinding(binding);
  const cms = (() => {
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(uint8ToBinary(bindingBytes));
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
  const parsed = parseCades(cms);
  const trustedCas: TrustedCasFile = {
    version: 1,
    cas: [{ merkleIndex: 0, certDerB64: bytesToB64(parsed.intermediateCertDer!) }],
  };
  return { parsed, binding, bindingBytes, pk, trustedCas };
}

async function makeEcdsaFixture(opts: { locale: Locale }): Promise<RsaCmsFixture> {
  const ca = await mkPkijsCert({ subject: 'EC-Root', issuerCert: null });
  const leaf = await mkPkijsCert({ subject: 'EC-Leaf', issuerCert: ca });
  const sk = secp.utils.randomPrivateKey();
  const pk = secp.getPublicKey(sk, false);
  const nowSec = Math.floor(Date.now() / 1000);
  const binding = buildBinding({
    pk,
    timestamp: nowSec,
    nonce: secp.utils.randomPrivateKey(),
    locale: opts.locale,
  });
  const bindingBytes = canonicalizeBinding(binding);
  const md = sha256(bindingBytes);
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
  const cms = new Uint8Array(ci.toSchema().toBER(false));
  const parsed = parseCades(cms);
  const trustedCas: TrustedCasFile = {
    version: 1,
    cas: [{ merkleIndex: 0, certDerB64: bytesToB64(parsed.intermediateCertDer!) }],
  };
  return { parsed, binding, bindingBytes, pk, trustedCas };
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
    { name: 'keyUsage', digitalSignature: true, keyCertSign: opts.isCa },
  ]);
  cert.sign(opts.signKey, forge.md.sha256.create());
  return cert;
}

interface PkijsCertResult {
  cert: pkijs.Certificate;
  privateKey: CryptoKey;
}

async function mkPkijsCert(opts: {
  subject: string;
  issuerCert: PkijsCertResult | null;
}): Promise<PkijsCertResult> {
  const subtle = globalThis.crypto.subtle;
  const algo = { name: 'ECDSA', namedCurve: 'P-256' } as const;
  const kp = await subtle.generateKey(algo, true, ['sign', 'verify']);
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({
    value: Math.floor(Math.random() * 1_000_000_000),
  });
  setName(cert.subject, opts.subject);
  if (opts.issuerCert) cert.issuer = opts.issuerCert.cert.subject;
  else setName(cert.issuer, opts.subject);
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

function toDer(p7: forge.pkcs7.PkcsSignedData): Uint8Array {
  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  const out = new Uint8Array(der.length);
  for (let i = 0; i < der.length; i++) out[i] = der.charCodeAt(i) & 0xff;
  return out;
}

function uint8ToBinary(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return s;
}

function bytesToB64(b: Uint8Array): string {
  return btoa(uint8ToBinary(b));
}
