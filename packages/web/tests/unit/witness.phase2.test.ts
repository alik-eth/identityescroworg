/**
 * Phase-2 witness builder tests — validates the 14-signal layout + nullifier
 * (Poseidon(Poseidon(subjectSerialLimbs, issuerCertHash), ctxHash)) against
 * the canonical ordering frozen in orchestration §2 (circuits-eng commit
 * f4e8948) and spec §14.3/§14.4.
 *
 * Uses the same synthetic CAdES-P256 harness as `witness.test.ts`; we also
 * mint a synthetic intermediate CA cert so we have something to Poseidon-
 * hash for the `issuer_cert_hash` nullifier input.
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
  ALGORITHM_TAG_ECDSA_STR,
  buildPhase2Witness,
  computeNullifier,
  extractSubjectSerialBytes,
  publicSignalsFromPhase2Witness,
  subjectSerialToLimbs,
} from '../../src/lib/witness';
import { canonicalizeCertHash } from '../../src/lib/merkleLookup';

pkijs.setEngine(
  'node-webcrypto',
  new pkijs.CryptoEngine({ name: 'node', crypto: globalThis.crypto }),
);

interface Fixture {
  binding: Binding;
  bindingBytes: Uint8Array;
  p7s: Uint8Array;
  intDer: Uint8Array;
  leafSerialBytes: Uint8Array;
}

let f: Fixture;

beforeAll(async () => {
  f = await makeFixture();
}, 60_000);

describe('phase2 witness — shape', () => {
  it('emits LeafWitnessInput fields + rTL + algorithmTag + nullifier + private inputs', async () => {
    const parsed = parseCades(f.p7s);
    const w = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      intermediateCertDer: f.intDer,
      trustedListRoot: 0n,
    });
    // Phase-1 superset — all existing witness fields are still present.
    expect(w.pkX).toHaveLength(4);
    expect(w.pkY).toHaveLength(4);
    expect(w.Bcanon).toHaveLength(1024);
    // Phase-2 additions.
    expect(typeof w.rTL).toBe('string');
    expect(typeof w.nullifier).toBe('string');
    expect(w.algorithmTag).toBe(ALGORITHM_TAG_ECDSA_STR);
    expect(w.subjectSerialLimbs).toHaveLength(4);
    expect(w.issuerCertHash).toMatch(/^\d+$/);
  });

  it('rejects missing intermediate cert', async () => {
    const parsed = parseCades(f.p7s);
    await expect(
      buildPhase2Witness({
        parsed,
        binding: f.binding,
        bindingBytes: f.bindingBytes,
        intermediateCertDer: new Uint8Array(),
        trustedListRoot: 0n,
      }),
    ).rejects.toThrow(/witness\.offsetNotFound/);
  });

  it('accepts trustedListRoot as bigint, decimal string, or 0x-hex', async () => {
    const parsed = parseCades(f.p7s);
    const w1 = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      intermediateCertDer: f.intDer,
      trustedListRoot: 0x1234n,
    });
    const w2 = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      intermediateCertDer: f.intDer,
      trustedListRoot: '4660',
    });
    const w3 = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      intermediateCertDer: f.intDer,
      trustedListRoot: '0x1234',
    });
    expect(w1.rTL).toBe('4660');
    expect(w2.rTL).toBe('4660');
    expect(w3.rTL).toBe('4660');
  });
});

describe('phase2 witness — 14-signal public layout (frozen)', () => {
  it('publicSignalsFromPhase2Witness emits 14 signals in orchestration §2 order', async () => {
    const parsed = parseCades(f.p7s);
    const w = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      intermediateCertDer: f.intDer,
      trustedListRoot: 0n,
    });
    const ps = publicSignalsFromPhase2Witness(w);
    expect(ps.signals).toHaveLength(14);
    // [0..3] pkX
    expect(ps.signals.slice(0, 4)).toEqual(w.pkX);
    // [4..7] pkY
    expect(ps.signals.slice(4, 8)).toEqual(w.pkY);
    // [8] ctxHash
    expect(ps.signals[8]).toBe(w.ctxHash);
    // [9] rTL
    expect(ps.signals[9]).toBe(w.rTL);
    // [10] declHash
    expect(ps.signals[10]).toBe(w.declHash);
    // [11] timestamp
    expect(ps.signals[11]).toBe(w.timestamp);
    // [12] algorithmTag — verifier dispatches on this
    expect(ps.signals[12]).toBe(w.algorithmTag);
    // [13] nullifier
    expect(ps.signals[13]).toBe(w.nullifier);
  });

  it('algorithmTag is "1" for ECDSA-P256 leaf', async () => {
    const parsed = parseCades(f.p7s);
    expect(parsed.algorithmTag).toBe(1);
    const w = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      intermediateCertDer: f.intDer,
      trustedListRoot: 0n,
    });
    expect(w.algorithmTag).toBe('1');
  });

  it('every signal is a decimal-string field element', async () => {
    const parsed = parseCades(f.p7s);
    const w = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      intermediateCertDer: f.intDer,
      trustedListRoot: 0n,
    });
    const ps = publicSignalsFromPhase2Witness(w);
    for (const s of ps.signals) {
      expect(typeof s).toBe('string');
      expect(s).toMatch(/^\d+$/);
    }
  });
});

describe('nullifier primitive (spec §14.4)', () => {
  it('subject serial is packed as 4 × 64-bit LE limbs (least-significant first) zero-padded to 32', () => {
    // Serial = 0x0102..20 (32 bytes ascending). Consistency with
    // pkCoordToLimbs: limb[0] = bytes 24..31 (low 64 bits BE), limb[3] =
    // bytes 0..7 (high 64 bits BE).
    const serial = new Uint8Array(32);
    for (let i = 0; i < 32; i++) serial[i] = i + 1;
    const limbs = subjectSerialToLimbs(serial);
    expect(limbs).toHaveLength(4);
    expect(limbs[0]).toBe(BigInt('0x191a1b1c1d1e1f20').toString());
    expect(limbs[3]).toBe(BigInt('0x0102030405060708').toString());
  });

  it('short serial is left-padded with zeros before limb packing (LE limb order)', () => {
    // Serial = 0x01 (1 byte) → padded to 32 bytes 0x00..0001 → limbs[0]=1, rest 0
    const limbs = subjectSerialToLimbs(new Uint8Array([0x01]));
    expect(limbs).toEqual(['1', '0', '0', '0']);
  });

  it('rejects serial > 32 bytes', () => {
    expect(() => subjectSerialToLimbs(new Uint8Array(33))).toThrow(/witness\.fieldTooLong/);
  });

  it('extractSubjectSerialBytes recovers the fixture serial from the leaf cert DER', async () => {
    const parsed = parseCades(f.p7s);
    const got = extractSubjectSerialBytes(parsed.leafCertDer);
    expect(got).toEqual(f.leafSerialBytes);
  });

  it('nullifier == Poseidon(Poseidon(serialLimbs, issuerHash), ctxHash) (reference implementation)', async () => {
    const parsed = parseCades(f.p7s);
    const w = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      intermediateCertDer: f.intDer,
      trustedListRoot: 0n,
    });
    // Re-compute from primitives and compare.
    const serialLimbs = w.subjectSerialLimbs.map((s) => BigInt(s));
    const issuerHash = await canonicalizeCertHash(f.intDer);
    const ctxHash = BigInt(w.ctxHash);
    const expected = await computeNullifier(serialLimbs, issuerHash, ctxHash);
    expect(w.nullifier).toBe(expected.toString());
  });

  it('same (pk, serial, issuer, ctx) → same nullifier (uniqueness-per-context)', async () => {
    const parsed = parseCades(f.p7s);
    const w1 = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      intermediateCertDer: f.intDer,
      trustedListRoot: 0n,
    });
    const w2 = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      intermediateCertDer: f.intDer,
      trustedListRoot: 0n,
    });
    expect(w2.nullifier).toBe(w1.nullifier);
  });

  it('different ctxHash → different nullifier (unlinkability across contexts)', async () => {
    const serialLimbs = [1n, 2n, 3n, 4n];
    const issuerHash = 0xabcdefn;
    const a = await computeNullifier(serialLimbs, issuerHash, 0n);
    const b = await computeNullifier(serialLimbs, issuerHash, 1n);
    expect(a).not.toBe(b);
  });

  it('different issuer → different nullifier (issuer-bound stability)', async () => {
    const serialLimbs = [1n, 2n, 3n, 4n];
    const a = await computeNullifier(serialLimbs, 0xabcdn, 42n);
    const b = await computeNullifier(serialLimbs, 0xbcden, 42n);
    expect(a).not.toBe(b);
  });
});

// --- Synthetic CAdES + CA fixture ------------------------------------------
//
// Builds: (1) a root CA, (2) an intermediate CA signed by root,
// (3) a leaf ECDSA-P256 cert signed by intermediate, (4) a detached CAdES-BES
// over the real JCS-canonical binding bytes. We record the intermediate DER
// explicitly so the nullifier's `issuer_cert_hash` input has a concrete
// target.

async function makeFixture(): Promise<Fixture> {
  const subtle = globalThis.crypto.subtle;
  const leafKp = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const intKp = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  // Intermediate CA (self-signed for the harness; the leaf's issuer).
  const intCert = new pkijs.Certificate();
  intCert.version = 2;
  intCert.serialNumber = new asn1js.Integer({ value: 0x100 });
  setName(intCert.subject, 'QKB Phase2 Test Intermediate');
  setName(intCert.issuer, 'QKB Phase2 Test Intermediate');
  intCert.notBefore.value = new Date(Date.now() - 60_000);
  intCert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  await intCert.subjectPublicKeyInfo.importKey(intKp.publicKey);
  await intCert.sign(intKp.privateKey, 'SHA-256');
  const intDer = new Uint8Array(intCert.toSchema(true).toBER(false));

  // Leaf: pick a distinctive serial so extractSubjectSerialBytes has a
  // non-trivial value to recover. DER INTEGER will encode this as 0x42..EE.
  const leafSerialBytes = new Uint8Array([0x42, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
  const leaf = new pkijs.Certificate();
  leaf.version = 2;
  leaf.serialNumber = new asn1js.Integer({
    valueHex: leafSerialBytes.buffer.slice(0) as ArrayBuffer,
  });
  setName(leaf.subject, 'QKB Phase2 Test Leaf');
  setName(leaf.issuer, 'QKB Phase2 Test Intermediate');
  leaf.notBefore.value = new Date(Date.now() - 60_000);
  leaf.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  await leaf.subjectPublicKeyInfo.importKey(leafKp.publicKey);
  await leaf.sign(intKp.privateKey, 'SHA-256');

  // Binding.
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
      issuer: leaf.issuer,
      serialNumber: leaf.serialNumber,
    }),
    signedAttrs,
  });
  const signed = new pkijs.SignedData({
    version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: '1.2.840.113549.1.7.1',
    }),
    signerInfos: [signerInfo],
    certificates: [leaf, intCert],
  });
  await signed.sign(leafKp.privateKey, 0, 'SHA-256');
  const ci = new pkijs.ContentInfo({
    contentType: pkijs.id_ContentType_SignedData,
    content: signed.toSchema(true),
  });
  const p7s = new Uint8Array(ci.toSchema().toBER(false));

  return { binding, bindingBytes, p7s, intDer, leafSerialBytes };
}

function setName(target: pkijs.RelativeDistinguishedNames, cn: string): void {
  target.typesAndValues = [
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.Utf8String({ value: cn }),
    }),
  ];
}
