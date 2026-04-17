/**
 * Off-circuit QES verifier — full mirror of every R_QKB constraint.
 *
 * Each check has a single failure code from the orchestration §5 taxonomy:
 *   - qes.sigInvalid       — RSA/ECDSA signature over signedAttrsDer fails.
 *   - qes.digestMismatch   — messageDigest attr ≠ SHA-256(Bcanon), OR pk in
 *                            B does not match the SPA-held pubkey.
 *   - qes.certExpired      — B.timestamp outside leaf cert validity window.
 *   - qes.unknownCA        — leaf was not signed by an intermediate listed
 *                            in trusted-cas.json.
 *   - qes.wrongAlgorithm   — leaf signature algorithm not RSA-PKCS1v15-2048
 *                            or ECDSA-P256-SHA256, or chain link uses an
 *                            unsupported algorithm.
 *
 * The exact same checks run inside the Groth16 circuit; this layer guarantees
 * we never pass a known-bad witness to the prover and lets us surface clean
 * UI-grade errors.
 */
import * as asn1js from 'asn1js';
import {
  Certificate,
  CryptoEngine,
  getCrypto,
  setEngine,
} from 'pkijs';
import { sha256 } from '@noble/hashes/sha256';
import declarationDigests from '../../../../fixtures/declarations/digests.json';
import {
  type AlgorithmTag,
  ALGORITHM_TAG_ECDSA,
  ALGORITHM_TAG_RSA,
  type ParsedCades,
} from './cades';
import { canonicalizeBinding, type Binding } from './binding';
import { QkbError } from './errors';

export interface TrustedCa {
  merkleIndex: number;
  certDerB64: string;
  issuerDN?: string;
  validFrom?: number;
  validTo?: number;
  poseidonHash?: string;
}

export interface TrustedCasFile {
  version: number;
  lotlSnapshot?: string;
  treeDepth?: number;
  cas: TrustedCa[];
}

export interface VerifyInput {
  parsed: ParsedCades;
  binding: Binding;
  bindingBytes: Uint8Array;
  expectedPk: Uint8Array;
  trustedCas: TrustedCasFile;
}

export interface VerifyOk {
  ok: true;
  algorithmTag: AlgorithmTag;
  caMerkleIndex: number;
}

export async function verifyQes(input: VerifyInput): Promise<VerifyOk> {
  const { parsed, binding, bindingBytes, expectedPk, trustedCas } = input;
  ensureCryptoEngine();

  if (!bytesEqual(parsed.messageDigest, sha256(bindingBytes))) {
    throw new QkbError('qes.digestMismatch', { reason: 'messageDigest' });
  }

  const expectedPkHex = `0x${hex(expectedPk)}`;
  if (binding.pk.toLowerCase() !== expectedPkHex.toLowerCase()) {
    throw new QkbError('qes.digestMismatch', { reason: 'pk-mismatch' });
  }

  const declHashHex = hex(sha256(new TextEncoder().encode(binding.declaration)));
  const allowed = new Set(
    Object.values(declarationDigests.declarations).map((d) =>
      d.sha256.replace(/^0x/, '').toLowerCase(),
    ),
  );
  if (!allowed.has(declHashHex)) {
    throw new QkbError('qes.digestMismatch', { reason: 'declaration' });
  }

  const leafCert = parseCert(parsed.leafCertDer);
  const intCert = parseCert(parsed.intermediateCertDer);

  const ts = binding.timestamp * 1000;
  const notBefore = leafCert.notBefore.value.getTime();
  const notAfter = leafCert.notAfter.value.getTime();
  if (ts < notBefore || ts > notAfter) {
    throw new QkbError('qes.certExpired', {
      timestamp: binding.timestamp,
      notBefore: Math.floor(notBefore / 1000),
      notAfter: Math.floor(notAfter / 1000),
    });
  }

  await verifySignerSignature(parsed, leafCert);

  const intMatch = await verifyChain(leafCert, intCert);
  if (!intMatch) {
    throw new QkbError('qes.sigInvalid', { reason: 'chain' });
  }

  const caMerkleIndex = lookupTrustedCa(parsed.intermediateCertDer, trustedCas);

  return { ok: true, algorithmTag: parsed.algorithmTag, caMerkleIndex };
}

async function verifySignerSignature(
  parsed: ParsedCades,
  leaf: Certificate,
): Promise<void> {
  const subtle = getSubtle();
  const spki = leaf.subjectPublicKeyInfo;
  const spkiDer = new Uint8Array(spki.toSchema().toBER(false));

  if (parsed.algorithmTag === ALGORITHM_TAG_RSA) {
    let key: CryptoKey;
    try {
      key = await subtle.importKey(
        'spki',
        toAB(spkiDer),
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify'],
      );
    } catch (cause) {
      throw new QkbError('qes.wrongAlgorithm', { cause: String(cause) });
    }
    let ok = false;
    try {
      ok = await subtle.verify(
        'RSASSA-PKCS1-v1_5',
        key,
        toAB(parsed.signatureValue),
        toAB(parsed.signedAttrsDer),
      );
    } catch (cause) {
      throw new QkbError('qes.sigInvalid', { cause: String(cause) });
    }
    if (!ok) throw new QkbError('qes.sigInvalid', { reason: 'rsa-verify' });
    return;
  }

  if (parsed.algorithmTag === ALGORITHM_TAG_ECDSA) {
    let key: CryptoKey;
    try {
      key = await subtle.importKey(
        'spki',
        toAB(spkiDer),
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );
    } catch (cause) {
      throw new QkbError('qes.wrongAlgorithm', { cause: String(cause) });
    }
    const rawSig = ecdsaDerToRaw(parsed.signatureValue);
    let ok = false;
    try {
      ok = await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        toAB(rawSig),
        toAB(parsed.signedAttrsDer),
      );
    } catch (cause) {
      throw new QkbError('qes.sigInvalid', { cause: String(cause) });
    }
    if (!ok) throw new QkbError('qes.sigInvalid', { reason: 'ecdsa-verify' });
    return;
  }

  throw new QkbError('qes.wrongAlgorithm', { algorithmTag: parsed.algorithmTag });
}

async function verifyChain(leaf: Certificate, issuer: Certificate): Promise<boolean> {
  const subtle = getSubtle();
  const spkiDer = new Uint8Array(issuer.subjectPublicKeyInfo.toSchema().toBER(false));
  const issuerAlg = issuer.subjectPublicKeyInfo.algorithm.algorithmId;
  const tbs = new Uint8Array(leaf.encodeTBS().toBER(false));
  const sig = new Uint8Array(leaf.signatureValue.valueBlock.valueHexView);

  if (issuerAlg === '1.2.840.113549.1.1.1') {
    const key = await subtle.importKey(
      'spki',
      toAB(spkiDer),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    return subtle.verify('RSASSA-PKCS1-v1_5', key, toAB(sig), toAB(tbs));
  }
  if (issuerAlg === '1.2.840.10045.2.1') {
    const key = await subtle.importKey(
      'spki',
      toAB(spkiDer),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    return subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      toAB(ecdsaDerToRaw(sig)),
      toAB(tbs),
    );
  }
  throw new QkbError('qes.wrongAlgorithm', { reason: 'chain', oid: issuerAlg });
}

function lookupTrustedCa(intermediateDer: Uint8Array, file: TrustedCasFile): number {
  const targetHex = hex(intermediateDer);
  for (const ca of file.cas) {
    const der = b64ToBytes(ca.certDerB64);
    if (hex(der) === targetHex) return ca.merkleIndex;
  }
  throw new QkbError('qes.unknownCA');
}

function parseCert(der: Uint8Array): Certificate {
  const asn = asn1js.fromBER(toAB(der));
  if (asn.offset === -1) {
    throw new QkbError('qes.sigInvalid', { reason: 'cert-parse' });
  }
  return new Certificate({ schema: asn.result });
}

function ensureCryptoEngine(): void {
  if (!getCrypto()) {
    setEngine(
      'qkb-engine',
      new CryptoEngine({ name: 'qkb', crypto: globalThis.crypto }),
    );
  }
}

function getSubtle(): SubtleCrypto {
  return globalThis.crypto.subtle;
}

function ecdsaDerToRaw(der: Uint8Array): Uint8Array {
  const asn = asn1js.fromBER(toAB(der));
  if (asn.offset === -1) {
    throw new QkbError('qes.sigInvalid', { reason: 'ecdsa-decode' });
  }
  const seq = asn.result as asn1js.Sequence;
  const [rNode, sNode] = seq.valueBlock.value as [asn1js.Integer, asn1js.Integer];
  const r = stripLead(new Uint8Array(rNode.valueBlock.valueHexView));
  const s = stripLead(new Uint8Array(sNode.valueBlock.valueHexView));
  const out = new Uint8Array(64);
  out.set(padLeft(r, 32), 0);
  out.set(padLeft(s, 32), 32);
  return out;
}

function stripLead(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
}

function padLeft(b: Uint8Array, n: number): Uint8Array {
  if (b.length === n) return b;
  if (b.length > n) throw new QkbError('qes.sigInvalid', { reason: 'ecdsa-overflow' });
  const out = new Uint8Array(n);
  out.set(b, n - b.length);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function toAB(b: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  return ab;
}

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
