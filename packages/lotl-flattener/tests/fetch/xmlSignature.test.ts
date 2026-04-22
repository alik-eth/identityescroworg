import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { SignedXml } from 'xml-crypto';
import {
  extractXmlSignatureCertificates,
  installXmlSignatureAlgorithms,
  verifyXmlSignature,
} from '../../src/fetch/xmlSignature.js';

const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const RSA_PSS_SHA256 = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';
const ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
const ECDSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';
const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

const rsaKeypair = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const ecKeypair = generateKeyPairSync('ec', {
  namedCurve: 'secp521r1',
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

function signedTlXml(signatureAlgorithm = RSA_SHA256, keypair = rsaKeypair): string {
  const xml = `<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="tl">
    <SchemeInformation><SchemeTerritory>EE</SchemeTerritory></SchemeInformation>
  </TrustServiceStatusList>`;
  const sig = new SignedXml({
    privateKey: keypair.privateKey,
    publicCert: keypair.publicKey,
    signatureAlgorithm,
    canonicalizationAlgorithm: EXC_C14N,
  });
  installXmlSignatureAlgorithms(sig);
  sig.addReference({
    xpath: "//*[local-name(.)='TrustServiceStatusList']",
    transforms: [ENVELOPED, EXC_C14N],
    digestAlgorithm: SHA256,
  });
  sig.computeSignature(xml);
  return sig.getSignedXml();
}

describe('verifyXmlSignature', () => {
  test('returns authenticated signed XML when the trusted cert verifies', () => {
    const result = verifyXmlSignature(signedTlXml(), {
      trustedCerts: [rsaKeypair.publicKey],
      expectedRootLocalName: 'TrustServiceStatusList',
    });
    expect(result.ok).toBe(true);
    expect(result.signedReferenceCount).toBe(1);
    expect(result.authenticatedXml).toContain('TrustServiceStatusList');
    expect(result.authenticatedXml).not.toContain('SignatureValue');
  });

  test('rejects tampered signed XML', () => {
    const tampered = signedTlXml().replace('EE', 'PL');
    const result = verifyXmlSignature(tampered, {
      trustedCerts: [rsaKeypair.publicKey],
      expectedRootLocalName: 'TrustServiceStatusList',
    });
    expect(result.ok).toBe(false);
  });

  test('supports ETSI RSA-PSS sha256-rsa-MGF1 signatures', () => {
    const result = verifyXmlSignature(signedTlXml(RSA_PSS_SHA256), {
      trustedCerts: [rsaKeypair.publicKey],
      expectedRootLocalName: 'TrustServiceStatusList',
    });
    expect(result.ok).toBe(true);
    expect(result.signedReferenceCount).toBe(1);
  });

  test.each([ECDSA_SHA256, ECDSA_SHA512])('supports ETSI %s signatures', (algorithm) => {
    const result = verifyXmlSignature(signedTlXml(algorithm, ecKeypair), {
      trustedCerts: [ecKeypair.publicKey],
      expectedRootLocalName: 'TrustServiceStatusList',
    });
    expect(result.ok).toBe(true);
    expect(result.signedReferenceCount).toBe(1);
  });

  test('rejects unsigned XML', () => {
    const result = verifyXmlSignature('<TrustServiceStatusList/>', {
      trustedCerts: [rsaKeypair.publicKey],
      expectedRootLocalName: 'TrustServiceStatusList',
    });
    expect(result).toMatchObject({ ok: false, error: 'missing-signature' });
  });

  test('extracts embedded X509 certificate fingerprints from Signature KeyInfo', () => {
    const derB64 = 'MAoCAQECAgECAwE=';
    const xml = `<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:KeyInfo>
          <ds:X509Data>
            <ds:X509Certificate>${derB64}</ds:X509Certificate>
          </ds:X509Data>
        </ds:KeyInfo>
      </ds:Signature>
    </TrustServiceStatusList>`;
    const [info] = extractXmlSignatureCertificates(xml);
    expect(info?.sha256Hex).toBe(
      'ed723107507e47cded7261dec86cb628dd7e6ad6bdebcb2298590b58fbdfb739',
    );
    expect(info?.sha1Base64).toBe('o0URamYZWcTAKUap5U3ktKnZiOc=');
  });
});
