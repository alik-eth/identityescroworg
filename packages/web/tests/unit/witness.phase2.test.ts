/**
 * Phase-2 split-proof witness builder tests.
 *
 * Validates the `{leaf, chain, shared}` bundle emitted by buildPhase2Witness
 * against the orchestration-§2 frozen layouts:
 *
 *   Leaf  (13 public signals): pkX[4], pkY[4], ctxHash, declHash, timestamp,
 *                              nullifier, leafSpkiCommit.
 *   Chain ( 3 public signals): rTL, algorithmTag, leafSpkiCommit.
 *
 * Plus the §14.4 person-level nullifier primitive (2026-04-18 amendment):
 *
 *   secret    = Poseidon(subjectSerialLimbs[0..3], subjectSerialLen)
 *   nullifier = Poseidon(secret, ctxHash)
 *
 * Uses a synthetic CAdES-P256 fixture where the leaf cert carries an
 * ETSI-EN-319-412-1-compliant subject serialNumber (OID 2.5.4.5) and a
 * self-signed intermediate so the chain witness has every slot populated.
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
  MAX_BCANON,
  MAX_CERT,
  MAX_SA,
  MERKLE_DEPTH,
  buildPhase2Witness,
  chainPublicSignals,
  computeNullifier,
  extractSubjectSerial,
  leafPublicSignals,
  subjectSerialToLimbs,
} from '../../src/lib/witness';

pkijs.setEngine(
  'node-webcrypto',
  new pkijs.CryptoEngine({ name: 'node', crypto: globalThis.crypto }),
);

// ETSI EN 319 412-1 §5.1.3 semantics identifier: natural person, Germany,
// Steuer-ID test value. 14 ASCII bytes.
const FIXTURE_SUBJECT_SERIAL = 'PNODE-12345678';

interface Fixture {
  binding: Binding;
  bindingBytes: Uint8Array;
  p7s: Uint8Array;
  intDer: Uint8Array;
  leafSubjectSerialAscii: string;
}

let f: Fixture;

beforeAll(async () => {
  f = await makeFixture();
}, 60_000);

// -------------------------------------------------------------------------
// Bundle shape — {leaf, chain, shared}
// -------------------------------------------------------------------------

describe('buildPhase2Witness — split bundle', () => {
  it('emits leaf + chain witnesses with matching leafSpkiCommit', async () => {
    const parsed = parseCades(f.p7s);
    const w = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
    });
    expect(w.leaf).toBeDefined();
    expect(w.chain).toBeDefined();
    expect(w.shared).toBeDefined();

    // leafSpkiCommit must be identical across leaf + chain + shared —
    // this is the single glue-signal the on-chain verifier asserts on.
    expect(w.leaf.leafSpkiCommit).toBe(w.chain.leafSpkiCommit);
    expect(w.shared.leafSpkiCommit).toBe(w.leaf.leafSpkiCommit);

    // Shared derivations are the same values the circuit-level witnesses
    // already carry; re-exposing them just saves the submit layer a
    // rummage through the witness object.
    expect(w.shared.pkX).toEqual(w.leaf.pkX);
    expect(w.shared.pkY).toEqual(w.leaf.pkY);
    expect(w.shared.ctxHash).toBe(w.leaf.ctxHash);
    expect(w.shared.declHash).toBe(w.leaf.declHash);
    expect(w.shared.timestamp).toBe(w.leaf.timestamp);
    expect(w.shared.nullifier).toBe(w.leaf.nullifier);
    expect(w.shared.rTL).toBe(w.chain.rTL);
    expect(w.shared.algorithmTag).toBe(w.chain.algorithmTag);

    // leafDER must be identical on both sides — the chain circuit's
    // leafSpkiCommit equality constraint re-reads leafDER at the same
    // offsets, so any drift would break the proof.
    expect(w.leaf.leafDER).toEqual(w.chain.leafDER);
    expect(w.leaf.leafSpkiXOffset).toBe(w.chain.leafSpkiXOffset);
    expect(w.leaf.leafSpkiYOffset).toBe(w.chain.leafSpkiYOffset);
  });

  it('leaf witness: array widths match the leaf circuit signal shapes', async () => {
    const parsed = parseCades(f.p7s);
    const { leaf } = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
    });
    expect(leaf.pkX).toHaveLength(4);
    expect(leaf.pkY).toHaveLength(4);
    expect(leaf.Bcanon).toHaveLength(MAX_BCANON);
    expect(leaf.BcanonPaddedIn).toHaveLength(MAX_BCANON);
    expect(leaf.signedAttrs).toHaveLength(MAX_SA);
    expect(leaf.signedAttrsPaddedIn).toHaveLength(MAX_SA);
    expect(leaf.leafDER).toHaveLength(MAX_CERT);
    expect(leaf.leafSigR).toHaveLength(6);
    expect(leaf.leafSigS).toHaveLength(6);
    expect(leaf.subjectSerialValueLength).toBe(FIXTURE_SUBJECT_SERIAL.length);
    expect(leaf.subjectSerialValueOffset).toBeGreaterThan(0);
  });

  it('chain witness: array widths match the chain circuit signal shapes', async () => {
    const parsed = parseCades(f.p7s);
    const { chain } = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
    });
    expect(chain.leafDER).toHaveLength(MAX_CERT);
    expect(chain.leafTbsPaddedIn).toHaveLength(MAX_CERT);
    expect(chain.intDER).toHaveLength(MAX_CERT);
    expect(chain.intSigR).toHaveLength(6);
    expect(chain.intSigS).toHaveLength(6);
    expect(chain.merklePath).toHaveLength(MERKLE_DEPTH);
    expect(chain.merkleIndices).toHaveLength(MERKLE_DEPTH);
    expect(chain.intDerLen).toBe(f.intDer.length);
    expect(chain.intSpkiXOffset).toBeGreaterThan(0);
    expect(chain.intSpkiYOffset).toBe(chain.intSpkiXOffset + 32);
  });

  it('accepts trustedListRoot as bigint, decimal string, or 0x-hex', async () => {
    const parsed = parseCades(f.p7s);
    const w1 = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0x1234n,
    });
    const w2 = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: '4660',
    });
    const w3 = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: '0x1234',
    });
    expect(w1.chain.rTL).toBe('4660');
    expect(w2.chain.rTL).toBe('4660');
    expect(w3.chain.rTL).toBe('4660');
    expect(w1.shared.rTL).toBe('4660');
  });

  it('defaults merkle path + indices to all-zero when no override supplied', async () => {
    const parsed = parseCades(f.p7s);
    const { chain } = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
    });
    expect(chain.merklePath.every((v) => v === '0')).toBe(true);
    expect(chain.merkleIndices.every((v) => v === 0)).toBe(true);
  });

  it('threads caller-supplied merkle path + indices into the chain witness', async () => {
    const parsed = parseCades(f.p7s);
    const path = Array.from({ length: MERKLE_DEPTH }, (_, i) => BigInt(i + 1));
    const indices = Array.from({ length: MERKLE_DEPTH }, (_, i) => (i % 2) as 0 | 1);
    const { chain } = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
      merklePath: path,
      merkleIndices: indices,
    });
    expect(chain.merklePath).toEqual(path.map((v) => v.toString()));
    expect(chain.merkleIndices).toEqual(indices);
  });

  it('falls back to the CMS-bundled intermediate when no override is passed', async () => {
    const parsed = parseCades(f.p7s);
    expect(parsed.intermediateCertDer).not.toBeNull();
    const { chain } = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
    });
    // First intDerLen bytes should equal the raw intermediate DER.
    const intBytes = chain.intDER.slice(0, chain.intDerLen);
    expect(intBytes).toEqual(Array.from(parsed.intermediateCertDer!));
  });
});

// -------------------------------------------------------------------------
// Public-signal packers (leaf[13], chain[3])
// -------------------------------------------------------------------------

describe('public-signal packers', () => {
  it('leafPublicSignals emits 13 signals in orchestration §2.1 order', async () => {
    const parsed = parseCades(f.p7s);
    const { leaf } = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
    });
    const ps = leafPublicSignals(leaf);
    expect(ps.signals).toHaveLength(13);
    expect(ps.signals.slice(0, 4)).toEqual(leaf.pkX);
    expect(ps.signals.slice(4, 8)).toEqual(leaf.pkY);
    expect(ps.signals[8]).toBe(leaf.ctxHash);
    expect(ps.signals[9]).toBe(leaf.declHash);
    expect(ps.signals[10]).toBe(leaf.timestamp);
    expect(ps.signals[11]).toBe(leaf.nullifier);
    expect(ps.signals[12]).toBe(leaf.leafSpkiCommit);
  });

  it('chainPublicSignals emits 3 signals in orchestration §2.2 order', async () => {
    const parsed = parseCades(f.p7s);
    const { chain } = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: '0xdeadbeef',
    });
    const ps = chainPublicSignals(chain);
    expect(ps.signals).toHaveLength(3);
    expect(ps.signals[0]).toBe(chain.rTL);
    expect(ps.signals[1]).toBe(chain.algorithmTag);
    expect(ps.signals[2]).toBe(chain.leafSpkiCommit);
  });

  it('algorithmTag is "1" for ECDSA-P256 leaf', async () => {
    const parsed = parseCades(f.p7s);
    expect(parsed.algorithmTag).toBe(1);
    const { shared, chain } = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
    });
    expect(shared.algorithmTag).toBe(ALGORITHM_TAG_ECDSA_STR);
    expect(chain.algorithmTag).toBe('1');
  });

  it('every leaf public signal is a decimal-string field element', async () => {
    const parsed = parseCades(f.p7s);
    const { leaf } = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
    });
    const ps = leafPublicSignals(leaf);
    for (const s of ps.signals) {
      expect(typeof s).toBe('string');
      expect(s).toMatch(/^\d+$/);
    }
  });
});

// -------------------------------------------------------------------------
// Person-level nullifier primitive (§14.4)
// -------------------------------------------------------------------------

describe('nullifier primitive (§14.4 amended)', () => {
  it('subjectSerialToLimbs packs content bytes LSB-first — matches X509SubjectSerial.circom', () => {
    // ETSI-format 14-byte identifier "PNODE-12345678".
    // bytes[0..8] = 50 4E 4F 44 45 2D 31 32 → limb[0] = LE = 0x32312D45444F4E50
    //                                        = 3616721751277260368
    // bytes[8..14] = 33 34 35 36 37 38, bytes[14..16] = 00 00
    //                                  → limb[1] = LE = 0x0000383736353433
    //                                  = 61809783813171
    const ascii = new TextEncoder().encode('PNODE-12345678');
    const limbs = subjectSerialToLimbs(ascii);
    expect(limbs).toEqual([
      '3616721751277260368',
      '61809783813171',
      '0',
      '0',
    ]);
  });

  it('1-byte serial → limb[0] = that byte, rest zero', () => {
    const limbs = subjectSerialToLimbs(new Uint8Array([0xab]));
    expect(limbs).toEqual(['171', '0', '0', '0']);
  });

  it('rejects serial outside [1, 32] byte range', () => {
    expect(() => subjectSerialToLimbs(new Uint8Array(0))).toThrow(/witness\.fieldTooLong/);
    expect(() => subjectSerialToLimbs(new Uint8Array(33))).toThrow(/witness\.fieldTooLong/);
  });

  it('extractSubjectSerial recovers the fixture serialNumber + absolute offset', async () => {
    const parsed = parseCades(f.p7s);
    const got = extractSubjectSerial(parsed.leafCertDer);
    expect(new TextDecoder('ascii').decode(got.content)).toBe(FIXTURE_SUBJECT_SERIAL);
    // Verify the offset points at content[0] inside the DER.
    expect(parsed.leafCertDer[got.contentOffset]).toBe(
      FIXTURE_SUBJECT_SERIAL.charCodeAt(0),
    );
    expect(
      parsed.leafCertDer.slice(got.contentOffset, got.contentOffset + got.content.length),
    ).toEqual(got.content);
  });

  it('nullifier == Poseidon(Poseidon(serialLimbs, serialLen), ctxHash) — reference', async () => {
    const parsed = parseCades(f.p7s);
    const { leaf } = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
    });
    const serialBytes = new TextEncoder().encode(FIXTURE_SUBJECT_SERIAL);
    const serialLimbs = subjectSerialToLimbs(serialBytes).map((s) => BigInt(s));
    const serialLen = BigInt(leaf.subjectSerialValueLength);
    const ctxHash = BigInt(leaf.ctxHash);
    const expected = await computeNullifier(serialLimbs, serialLen, ctxHash);
    expect(leaf.nullifier).toBe(expected.toString());
  });

  it('same inputs → same nullifier (uniqueness-per-context)', async () => {
    const parsed = parseCades(f.p7s);
    const w1 = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
    });
    const w2 = await buildPhase2Witness({
      parsed,
      binding: f.binding,
      bindingBytes: f.bindingBytes,
      trustedListRoot: 0n,
    });
    expect(w2.leaf.nullifier).toBe(w1.leaf.nullifier);
  });

  it('different ctxHash → different nullifier (unlinkability across contexts)', async () => {
    const limbs = [1n, 2n, 3n, 4n];
    const a = await computeNullifier(limbs, 10n, 0n);
    const b = await computeNullifier(limbs, 10n, 1n);
    expect(a).not.toBe(b);
  });

  it('different serialLen → different nullifier (padding-collision resistance)', async () => {
    // Same limbs, different declared length → different secret (and nullifier).
    const limbs = [7n, 0n, 0n, 0n];
    const a = await computeNullifier(limbs, 8n, 42n);
    const b = await computeNullifier(limbs, 14n, 42n);
    expect(a).not.toBe(b);
  });

  it('different subject serial → different nullifier (cross-user unlinkability)', async () => {
    const a = await computeNullifier([1n, 0n, 0n, 0n], 10n, 42n);
    const b = await computeNullifier([2n, 0n, 0n, 0n], 10n, 42n);
    expect(a).not.toBe(b);
  });
});

// --- Synthetic CAdES + CA fixture ------------------------------------------
//
// Leaf carries the ETSI-compliant subject.serialNumber attribute (OID 2.5.4.5,
// PrintableString "PNODE-12345678") and an intermediate-signed cert chain
// so the chain witness has intDER + outer-cert signature slots populated.
// Merkle proof is caller-supplied; not exercised here.

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

  const intCert = new pkijs.Certificate();
  intCert.version = 2;
  intCert.serialNumber = new asn1js.Integer({ value: 0x100 });
  setCommonName(intCert.subject, 'QKB Phase2 Test Intermediate');
  setCommonName(intCert.issuer, 'QKB Phase2 Test Intermediate');
  intCert.notBefore.value = new Date(Date.now() - 60_000);
  intCert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  await intCert.subjectPublicKeyInfo.importKey(intKp.publicKey);
  await intCert.sign(intKp.privateKey, 'SHA-256');
  const intDer = new Uint8Array(intCert.toSchema(true).toBER(false));

  const leaf = new pkijs.Certificate();
  leaf.version = 2;
  leaf.serialNumber = new asn1js.Integer({ value: 0x42 });
  setSubjectWithSerialNumber(leaf.subject, 'QKB Phase2 Test Leaf', FIXTURE_SUBJECT_SERIAL);
  setCommonName(leaf.issuer, 'QKB Phase2 Test Intermediate');
  leaf.notBefore.value = new Date(Date.now() - 60_000);
  leaf.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60_000);
  await leaf.subjectPublicKeyInfo.importKey(leafKp.publicKey);
  await leaf.sign(intKp.privateKey, 'SHA-256');

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

  return {
    binding,
    bindingBytes,
    p7s,
    intDer,
    leafSubjectSerialAscii: FIXTURE_SUBJECT_SERIAL,
  };
}

function setCommonName(target: pkijs.RelativeDistinguishedNames, cn: string): void {
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
