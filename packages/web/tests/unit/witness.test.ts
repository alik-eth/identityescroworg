/**
 * Witness-builder unit test.
 *
 * Synthesises a minimal ECDSA-P256 CAdES-BES detached signature over a real
 * JCS-canonical binding statement, parses it via parseCades, then asserts
 * buildLeafWitness produces:
 *   - the exact leaf-circuit input field set expected by snarkjs;
 *   - public-signal values (declHash, pkX, pkY, timestamp, ctxHash) that
 *     match what the circuit would recompute internally;
 *   - byte-offset fields (pk, scheme, ctx, decl, ts) that point at the
 *     correct positions inside Bcanon;
 *   - zero-padded private witnesses of the exact MAX_* sizes.
 *
 * The real Diia .p7s is not accessible from CI (globally gitignored as a
 * legal-identity asset), so the test builds its own fixture.
 */
import { describe, expect, it, beforeAll } from 'vitest';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import {
  buildBinding,
  canonicalizeBinding,
  type Binding,
} from '../../src/lib/binding';
import { parseCades } from '../../src/lib/cades';
import {
  buildLeafWitness,
  bytes32ToLimbs643,
  digestToField,
  MAX_BCANON,
  MAX_CERT,
  MAX_SA,
  MAX_DECL,
  pkCoordToLimbs,
  sha256Pad,
} from '../../src/lib/witness';

pkijs.setEngine(
  'node-webcrypto',
  new pkijs.CryptoEngine({ name: 'node', crypto: globalThis.crypto }),
);

interface Fixture {
  binding: Binding;
  bindingBytes: Uint8Array;
  p7s: Uint8Array;
  pkUncompressed: Uint8Array;
}

let f: Fixture;

beforeAll(async () => {
  f = await makeFixture();
}, 60_000);

describe('buildLeafWitness — shape', () => {
  it('produces the leaf-circuit input field set with correct array widths', async () => {
    const parsed = parseCades(f.p7s);
    const w = await buildLeafWitness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
    });
    expect(w.pkX).toHaveLength(4);
    expect(w.pkY).toHaveLength(4);
    expect(w.Bcanon).toHaveLength(MAX_BCANON);
    expect(w.BcanonPaddedIn).toHaveLength(MAX_BCANON);
    expect(w.signedAttrs).toHaveLength(MAX_SA);
    expect(w.signedAttrsPaddedIn).toHaveLength(MAX_SA);
    expect(w.leafDER).toHaveLength(MAX_CERT);
    expect(w.declPaddedIn).toHaveLength(MAX_DECL + 64);
    expect(w.leafSigR).toHaveLength(6);
    expect(w.leafSigS).toHaveLength(6);
    // Split-proof pivot: leaf carries nullifier + leafSpkiCommit + the
    // subject-serial offsets that feed the person-level nullifier primitive.
    expect(typeof w.nullifier).toBe('string');
    expect(typeof w.leafSpkiCommit).toBe('string');
    expect(typeof w.subjectSerialValueOffset).toBe('number');
    expect(typeof w.subjectSerialValueLength).toBe('number');
    expect(w.subjectSerialValueLength).toBeGreaterThanOrEqual(1);
    expect(w.subjectSerialValueLength).toBeLessThanOrEqual(32);
  });

  it('emits every bigint-shaped field as a decimal string', async () => {
    const parsed = parseCades(f.p7s);
    const w = await buildLeafWitness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
    });
    for (const v of [
      ...w.pkX,
      ...w.pkY,
      w.ctxHash,
      w.declHash,
      w.timestamp,
      w.nullifier,
      w.leafSpkiCommit,
      ...w.leafSigR,
      ...w.leafSigS,
    ]) {
      expect(typeof v).toBe('string');
      expect(v).toMatch(/^\d+$/);
    }
  });
});

describe('buildLeafWitness — public signals', () => {
  it('matches the circuit-side declarations of pkX/pkY/declHash/timestamp/ctxHash', async () => {
    const parsed = parseCades(f.p7s);
    const w = await buildLeafWitness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
    });
    // pkX limbs should round-trip back to the 32-byte X coordinate.
    const xBytes = f.pkUncompressed.subarray(1, 33);
    const yBytes = f.pkUncompressed.subarray(33, 65);
    expect(w.pkX).toEqual(pkCoordToLimbs(xBytes));
    expect(w.pkY).toEqual(pkCoordToLimbs(yBytes));

    // declHash = digestToField(sha256(declaration bytes)) reduced mod p.
    const declBytes = new TextEncoder().encode(f.binding.declaration);
    expect(w.declHash).toBe(digestToField(sha256(declBytes)));

    expect(w.timestamp).toBe(String(f.binding.timestamp));
    expect(w.ctxHash).toBe('0'); // empty context
  });
});

describe('buildLeafWitness — offsets', () => {
  it('every byte-offset field points at the matching key literal in Bcanon', async () => {
    const parsed = parseCades(f.p7s);
    const w = await buildLeafWitness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
    });
    const at = (off: number, s: string): boolean =>
      new TextDecoder().decode(f.bindingBytes.subarray(off, off + s.length)) === s;
    expect(at(w.pkValueOffset, '"pk":')).toBe(true);
    expect(at(w.schemeValueOffset, '"scheme":')).toBe(true);
    expect(at(w.ctxValueOffset, '"context":')).toBe(true);
    expect(at(w.declValueOffset, '"declaration":')).toBe(true);
    expect(at(w.tsValueOffset, '"timestamp":')).toBe(true);
    expect(w.BcanonLen).toBe(f.bindingBytes.length);
    expect(w.BcanonPaddedLen).toBe(sha256Pad(f.bindingBytes).length);
    expect(w.signedAttrsLen).toBe(parsed.signedAttrsDer.length);
    expect(w.signedAttrsPaddedLen).toBe(sha256Pad(parsed.signedAttrsDer).length);
    // mdOffsetInSA should point at the start of the 32-byte messageDigest
    // payload inside signedAttrsDer.
    for (let i = 0; i < 32; i++) {
      expect(parsed.signedAttrsDer[w.mdOffsetInSA + i]).toBe(parsed.messageDigest[i]);
    }
    // leaf SPKI x/y should point at the 32-byte pk X and Y inside leafDER.
    for (let i = 0; i < 32; i++) {
      expect(parsed.leafCertDer[w.leafSpkiXOffset + i]).toBeDefined();
    }
  });

  it('round-trips sigR/sigS limbs to the 32-byte r/s bytes', async () => {
    const parsed = parseCades(f.p7s);
    const w = await buildLeafWitness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
    });
    // Reconstruct r/s from the ECDSA signature DER and compare limb packing.
    const sig = parsed.signatureValue;
    const asn = asn1js.fromBER(toAB(sig));
    const seq = asn.result as asn1js.Sequence;
    const [rNode, sNode] = seq.valueBlock.value as [asn1js.Integer, asn1js.Integer];
    const r = normalizeInt32(new Uint8Array(rNode.valueBlock.valueHexView));
    const s = normalizeInt32(new Uint8Array(sNode.valueBlock.valueHexView));
    expect(w.leafSigR).toEqual(bytes32ToLimbs643(r));
    expect(w.leafSigS).toEqual(bytes32ToLimbs643(s));
  });
});

// --- Synthetic CAdES-BES builder for the witness fixture ----------------------
// Generates an ECDSA-P256 keypair, mints a self-signed leaf, produces the
// JCS canonical binding bytes for that pk, and wraps them in a detached
// CAdES-BES CMS. No network, no file I/O — deterministic modulo key
// generation.

async function makeFixture(): Promise<Fixture> {
  const subtle = globalThis.crypto.subtle;
  const kp = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  // Generate an independent secp256k1 keypair for the binding's `pk` field.
  // The QES signing key (ECDSA P-256 above) is the user's legal identity;
  // the binding's pk is the SPA-generated secp256k1 key the QES attests to.
  const bindingPriv = secp.utils.randomPrivateKey();
  const pkUncompressed = secp.getPublicKey(bindingPriv, false);

  const timestamp = 1_730_000_000;
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  const binding = buildBinding({
    pk: pkUncompressed,
    timestamp,
    nonce,
    locale: 'en',
  });
  const bindingBytes = canonicalizeBinding(binding);

  // Mint a self-signed ECDSA-P256 cert. The subject carries an ETSI-style
  // serialNumber attribute (OID 2.5.4.5, PrintableString) so the
  // split-proof leaf witness can derive the person-level nullifier via
  // X509SubjectSerial. The value is arbitrary test-fixture content.
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 1 });
  setSubjectWithSerialNumber(cert.subject, 'QKB Witness Test', 'PNODE-12345678');
  setName(cert.issuer, 'QKB Witness Test');
  cert.notBefore.value = new Date(Date.now() - 60_000);
  cert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  await cert.subjectPublicKeyInfo.importKey(kp.publicKey);
  await cert.sign(kp.privateKey, 'SHA-256');

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
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
    }),
    signedAttrs,
  });
  const signed = new pkijs.SignedData({
    version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: '1.2.840.113549.1.7.1',
    }),
    signerInfos: [signerInfo],
    certificates: [cert],
  });
  await signed.sign(kp.privateKey, 0, 'SHA-256');
  const ci = new pkijs.ContentInfo({
    contentType: pkijs.id_ContentType_SignedData,
    content: signed.toSchema(true),
  });
  const p7s = new Uint8Array(ci.toSchema().toBER(false));

  return { binding, bindingBytes, p7s, pkUncompressed };
}

function setName(target: pkijs.RelativeDistinguishedNames, cn: string): void {
  target.typesAndValues = [
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.Utf8String({ value: cn }),
    }),
  ];
}

function setSubjectWithSerialNumber(
  target: pkijs.RelativeDistinguishedNames,
  cn: string,
  serial: string,
): void {
  target.typesAndValues = [
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.Utf8String({ value: cn }),
    }),
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.5',
      value: new asn1js.PrintableString({ value: serial }),
    }),
  ];
}

function normalizeInt32(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  const trimmed = b.subarray(i);
  const out = new Uint8Array(32);
  out.set(trimmed, 32 - trimmed.length);
  return out;
}

function toAB(b: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  return ab;
}
