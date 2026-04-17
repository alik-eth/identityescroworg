/**
 * Sprint 0 S0.2 — algorithmTag detection from a leaf cert's SPKI OID.
 *
 * Verifies both positive paths (RSA → 0, ECDSA P-256 → 1) and the typed
 * error responses for unsupported key types (Ed25519, ECDSA-non-P256).
 */
import { describe, expect, it } from 'vitest';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import forge from 'node-forge';
import {
  ALGORITHM_TAG_ECDSA,
  ALGORITHM_TAG_RSA,
  detectAlgorithmTag,
} from '../../src/lib/cades';

pkijs.setEngine(
  'node-webcrypto',
  new pkijs.CryptoEngine({ name: 'node', crypto: globalThis.crypto }),
);

describe('detectAlgorithmTag', () => {
  it('returns 0 (RSA) for an rsaEncryption leaf', () => {
    const { leaf } = makeRsaLeaf();
    const der = forgeCertToDer(leaf);
    expect(detectAlgorithmTag(der)).toBe(ALGORITHM_TAG_RSA);
  });

  it('returns 1 (ECDSA) for an ECDSA P-256 leaf', async () => {
    const der = await makeEcdsaP256LeafDer();
    expect(detectAlgorithmTag(der)).toBe(ALGORITHM_TAG_ECDSA);
  });

  it('throws cades.parse { reason: "leaf-spki-alg" } for an unknown SPKI algorithm (Ed25519)', async () => {
    const der = await makeEd25519LeafDer();
    try {
      detectAlgorithmTag(der);
      expect.fail('should have thrown');
    } catch (e) {
      const err = e as { code: string; details: { reason: string; oid?: string } };
      expect(err.code).toBe('cades.parse');
      expect(err.details.reason).toBe('leaf-spki-alg');
      expect(err.details.oid).toBe('1.3.101.112');
    }
  });

  it('throws cades.parse { reason: "ecdsa-curve" } for an ECDSA P-384 leaf', async () => {
    const der = await makeEcdsaP384LeafDer();
    try {
      detectAlgorithmTag(der);
      expect.fail('should have thrown');
    } catch (e) {
      const err = e as { code: string; details: { reason: string; curve?: string } };
      expect(err.code).toBe('cades.parse');
      expect(err.details.reason).toBe('ecdsa-curve');
    }
  });

  it('throws cades.parse { reason: "cert-asn1" } for garbage bytes', () => {
    const garbage = new Uint8Array([1, 2, 3, 4, 5]);
    try {
      detectAlgorithmTag(garbage);
      expect.fail('should have thrown');
    } catch (e) {
      const err = e as { code: string; details: { reason: string } };
      expect(err.code).toBe('cades.parse');
      expect(err.details.reason).toBe('cert-asn1');
    }
  });
});

// --- helpers -----------------------------------------------------------------

function makeRsaLeaf(): { leaf: forge.pki.Certificate } {
  const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = kp.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  const attrs: forge.pki.CertificateField[] = [{ name: 'commonName', value: 'RSA Test' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(kp.privateKey);
  return { leaf: cert };
}

function forgeCertToDer(cert: forge.pki.Certificate): Uint8Array {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const out = new Uint8Array(der.length);
  for (let i = 0; i < der.length; i++) out[i] = der.charCodeAt(i) & 0xff;
  return out;
}

async function makeEcdsaP256LeafDer(): Promise<Uint8Array> {
  const kp = (await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  return mintSelfSignedEcCert(kp, 'P-256');
}

async function makeEcdsaP384LeafDer(): Promise<Uint8Array> {
  const kp = (await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  return mintSelfSignedEcCert(kp, 'P-384');
}

async function mintSelfSignedEcCert(
  kp: CryptoKeyPair,
  curve: 'P-256' | 'P-384',
): Promise<Uint8Array> {
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 1 });
  setName(cert.subject, `EC Test ${curve}`);
  setName(cert.issuer, `EC Test ${curve}`);
  cert.notBefore.value = new Date(Date.now() - 60_000);
  cert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  await cert.subjectPublicKeyInfo.importKey(kp.publicKey);
  await cert.sign(kp.privateKey, curve === 'P-256' ? 'SHA-256' : 'SHA-384');
  return new Uint8Array(cert.toSchema(true).toBER(false));
}

async function makeEd25519LeafDer(): Promise<Uint8Array> {
  // Hand-build a minimal X.509 whose SPKI algorithm is Ed25519 (1.3.101.112).
  // We don't need a real Ed25519 signature here — detectAlgorithmTag only
  // inspects the SPKI algorithm OID, so a syntactically valid (but
  // unverified) cert suffices. We sign the outer with a throwaway ECDSA key
  // so pkijs's Certificate schema parser doesn't reject the shape.
  const signKp = (await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  // Dummy Ed25519 public key (32 random bytes).
  const edPk = new Uint8Array(32);
  globalThis.crypto.getRandomValues(edPk);

  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 1 });
  setName(cert.subject, 'Ed25519 Test');
  setName(cert.issuer, 'Ed25519 Test');
  cert.notBefore.value = new Date(Date.now() - 60_000);
  cert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  // Build SubjectPublicKeyInfo manually with algorithm = id-Ed25519.
  cert.subjectPublicKeyInfo = new pkijs.PublicKeyInfo({
    algorithm: new pkijs.AlgorithmIdentifier({ algorithmId: '1.3.101.112' }),
    subjectPublicKey: new asn1js.BitString({ valueHex: edPk.buffer.slice(0) as ArrayBuffer }),
  });
  await cert.sign(signKp.privateKey, 'SHA-256');
  return new Uint8Array(cert.toSchema(true).toBER(false));
}

function setName(target: pkijs.RelativeDistinguishedNames, cn: string): void {
  target.typesAndValues = [
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.Utf8String({ value: cn }),
    }),
  ];
}
