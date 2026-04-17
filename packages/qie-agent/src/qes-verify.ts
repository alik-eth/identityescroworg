/**
 * Node-side CAdES-BES verifier (Q5).
 *
 * Mirrors packages/web/src/lib/qesVerify.ts byte-for-byte on:
 *   - CMS/CAdES-BES parsing (pkijs/asn1js).
 *   - Leaf + intermediate resolution (inline SET OR LOTL issuer-DN match).
 *   - RSA-PKCS#1 v1.5 / ECDSA-P256 verification of SignedAttributes.
 *   - Signed-attributes digest check (SHA-256 preimage = payload bytes).
 *
 * Exports two shapes:
 *
 *   verifyCadesNode(p7s, cert, message, { trustedCas }):
 *     Promise<{chain, sigValid, subject?}>
 *     — rich result, used as the default `notaryVerify` wiring in server.ts
 *       (MVP refinement §0.4/§0.5).
 *
 *   qesVerifyNode(p7s, cert, message, opts?):
 *     Promise<boolean>
 *     — thin boolean wrapper returning (chain === "trusted" && sigValid).
 *       Used as the default `qesVerify` (C-path countersig & deposit QES).
 *       When no trusted-cas is supplied, returns `false` (safe default —
 *       we never declare a chain trusted without a LOTL anchor).
 */
import { readFileSync } from "node:fs";
import * as asn1js from "asn1js";
import {
  Certificate,
  ContentInfo,
  CryptoEngine,
  IssuerAndSerialNumber,
  SignedData,
  SignerInfo,
  getCrypto,
  id_ContentType_SignedData,
  setEngine,
} from "pkijs";
import type { NotaryVerifyResult } from "./context.js";

const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_CN = "2.5.4.3";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_RSA = "1.2.840.113549.1.1.1";
const OID_RSA_SHA256 = "1.2.840.113549.1.1.11";
const OID_EC = "1.2.840.10045.2.1";
const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const OID_P256 = "1.2.840.10045.3.1.7";

export interface TrustedCa {
  merkleIndex: number;
  certDerB64: string;
}

export interface TrustedCasFile {
  version: number;
  lotlSnapshot?: string;
  treeDepth?: number;
  cas: TrustedCa[];
}

export interface VerifyOpts {
  /** LOTL snapshot file contents. When absent, chain is always "untrusted". */
  trustedCas?: TrustedCasFile;
}

let _engineReady = false;
function ensureEngine(): void {
  if (_engineReady) return;
  if (!getCrypto()) {
    setEngine(
      "qie-engine",
      new CryptoEngine({ name: "qie", crypto: globalThis.crypto }),
    );
  }
  _engineReady = true;
}

/**
 * Load a trusted-cas.json pumped from the flattener package.
 * Used by production server wiring to initialise the default
 * `qesVerify` / `notaryVerify` hooks.
 */
export function loadTrustedCasFromPath(path: string): TrustedCasFile {
  const raw = JSON.parse(readFileSync(path, "utf8")) as TrustedCasFile;
  if (!raw || !Array.isArray(raw.cas)) {
    throw new Error(`malformed trusted-cas at ${path}`);
  }
  return raw;
}

/**
 * Core verifier. Parses `p7s` (detached or attached CAdES-BES), re-computes
 * the signed-attributes preimage from `message`, verifies the signature
 * with the leaf cert's SPKI, and attempts to pin the intermediate through
 * `trustedCas` (inline first, then by issuer-DN match against LOTL).
 *
 * Never throws for expected validation failures — all such outcomes are
 * encoded in the result so the router can pick the right HTTP mapping.
 * Only throws for programmer errors (bad input types).
 */
export async function verifyCadesNode(
  p7s: Uint8Array,
  cert: Uint8Array,
  message: Uint8Array,
  opts: VerifyOpts = {},
): Promise<NotaryVerifyResult> {
  ensureEngine();

  let signed: SignedData;
  let signer: SignerInfo;
  try {
    const asn = asn1js.fromBER(toAB(p7s));
    if (asn.offset === -1) return { chain: "untrusted", sigValid: false };
    const ci = new ContentInfo({ schema: asn.result });
    if (ci.contentType !== id_ContentType_SignedData) {
      return { chain: "untrusted", sigValid: false };
    }
    signed = new SignedData({ schema: ci.content });
    if (signed.signerInfos.length !== 1) return { chain: "untrusted", sigValid: false };
    signer = signed.signerInfos[0] as SignerInfo;
    if (!signer.signedAttrs) return { chain: "untrusted", sigValid: false };
  } catch {
    return { chain: "untrusted", sigValid: false };
  }

  if (signer.digestAlgorithm.algorithmId !== OID_SHA256) {
    return { chain: "untrusted", sigValid: false };
  }
  const sigAlgOid = signer.signatureAlgorithm.algorithmId;
  if (
    sigAlgOid !== OID_RSA &&
    sigAlgOid !== OID_RSA_SHA256 &&
    sigAlgOid !== OID_ECDSA_SHA256
  ) {
    return { chain: "untrusted", sigValid: false };
  }

  // Resolve the signer cert. The caller's `cert` parameter MUST match the
  // CMS SignerInfo.sid — we enforce this by finding the cert by sid in the
  // CMS and comparing its DER encoding to `cert`.
  const certs = (signed.certificates ?? []).filter(
    (c): c is Certificate => c instanceof Certificate,
  );
  let leaf: Certificate | undefined;
  try {
    leaf = findLeafBySid(certs, signer.sid);
  } catch {
    return { chain: "untrusted", sigValid: false };
  }
  if (!leaf) {
    // No CMS cert matched the signer id — try parsing the caller-provided
    // cert and using it directly (matches Phase 1 legacy callers that
    // shipped the cert out-of-band).
    const parsed = tryParseCert(cert);
    if (!parsed) return { chain: "untrusted", sigValid: false };
    leaf = parsed;
  } else {
    const leafDer = certDer(leaf);
    if (cert.length > 0 && !bytesEqual(leafDer, cert)) {
      return { chain: "untrusted", sigValid: false };
    }
  }

  // messageDigest attr MUST equal SHA-256(message).
  const mdAttr = signer.signedAttrs.attributes.find((a) => a.type === OID_MESSAGE_DIGEST);
  if (!mdAttr || mdAttr.values.length !== 1) {
    return { chain: "untrusted", sigValid: false };
  }
  const mdBytes = new Uint8Array((mdAttr.values[0] as asn1js.OctetString).valueBlock.valueHexView);
  const expected = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", toAB(message)),
  );
  const digestOk = bytesEqual(mdBytes, expected);

  // Verify the signature over the re-encoded SET OF Attribute.
  const signedAttrsDer = reencodeSignedAttrs(signer);
  const sigValue = new Uint8Array(signer.signature.valueBlock.valueHexView);
  const sigOk = await verifySigOverAttrs(leaf, sigAlgOid, signedAttrsDer, sigValue);

  // Resolve the intermediate and determine chain trust.
  let chain: "trusted" | "untrusted" = "untrusted";
  if (opts.trustedCas) {
    // Prefer inline intermediate when present.
    const inlineInt = findIssuer(certs, leaf);
    if (inlineInt) {
      const intDer = certDer(inlineInt);
      if (indexInTrustedCas(intDer, opts.trustedCas) !== -1) {
        chain = "trusted";
      } else {
        // inline didn't match — try DN-based lookup as a fallback.
        if (resolveIntermediateFromLotl(leaf, opts.trustedCas)) chain = "trusted";
      }
    } else {
      if (resolveIntermediateFromLotl(leaf, opts.trustedCas)) chain = "trusted";
    }
  }

  const result: NotaryVerifyResult = {
    chain,
    sigValid: sigOk && digestOk,
  };
  const cn = readCn(leaf.subject);
  if (cn) result.subject = cn;
  return result;
}

/**
 * Boolean wrapper used as the default `qesVerify` hook. Declared `async` so
 * that it's a drop-in replacement for the old stub signature.
 */
export async function qesVerifyNode(
  p7s: Uint8Array,
  cert: Uint8Array,
  message: Uint8Array,
  opts: VerifyOpts = {},
): Promise<boolean> {
  const r = await verifyCadesNode(p7s, cert, message, opts);
  return r.chain === "trusted" && r.sigValid;
}

/**
 * Factory for production wiring — returns callables closed over a LOTL
 * snapshot loaded from disk. Use in `src/index.ts`/bin to build the
 * `qesVerify` + `notaryVerify` hooks at server boot.
 */
export function makeCadesVerifiers(trustedCasPath: string): {
  qesVerify: (p7s: Uint8Array, cert: Uint8Array, message: Uint8Array) => Promise<boolean>;
  notaryVerify: (sig: Uint8Array, cert: Uint8Array, payload: Uint8Array) => Promise<NotaryVerifyResult>;
} {
  const trustedCas = loadTrustedCasFromPath(trustedCasPath);
  return {
    qesVerify: (p7s, cert, message) => qesVerifyNode(p7s, cert, message, { trustedCas }),
    notaryVerify: (sig, cert, payload) => verifyCadesNode(sig, cert, payload, { trustedCas }),
  };
}

// ---------------------------------------------------------------------------
// helpers

async function verifySigOverAttrs(
  leaf: Certificate,
  sigAlgOid: string,
  signedAttrsDer: Uint8Array,
  sigValue: Uint8Array,
): Promise<boolean> {
  const subtle = globalThis.crypto.subtle;
  const spki = new Uint8Array(leaf.subjectPublicKeyInfo.toSchema().toBER(false));
  const spkiAlg = leaf.subjectPublicKeyInfo.algorithm.algorithmId;

  try {
    if (spkiAlg === OID_RSA) {
      if (sigAlgOid !== OID_RSA && sigAlgOid !== OID_RSA_SHA256) return false;
      const key = await subtle.importKey(
        "spki",
        toAB(spki),
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
      return await subtle.verify(
        "RSASSA-PKCS1-v1_5",
        key,
        toAB(sigValue),
        toAB(signedAttrsDer),
      );
    }
    if (spkiAlg === OID_EC) {
      if (sigAlgOid !== OID_ECDSA_SHA256) return false;
      const curveParam = leaf.subjectPublicKeyInfo.algorithm.algorithmParams;
      const curveOid =
        curveParam instanceof asn1js.ObjectIdentifier
          ? curveParam.valueBlock.toString()
          : undefined;
      if (curveOid !== OID_P256) return false;
      const key = await subtle.importKey(
        "spki",
        toAB(spki),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      const raw = ecdsaDerToRaw(sigValue, 32);
      if (!raw) return false;
      return await subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        toAB(raw),
        toAB(signedAttrsDer),
      );
    }
  } catch {
    return false;
  }
  return false;
}

function reencodeSignedAttrs(signer: SignerInfo): Uint8Array {
  // RFC 5652 §5.4: signature is over SET OF Attribute (not [0] IMPLICIT).
  const set = new asn1js.Set({
    value: signer.signedAttrs!.attributes.map((a) => a.toSchema()),
  });
  return new Uint8Array(set.toBER(false));
}

function findLeafBySid(
  certs: readonly Certificate[],
  sid: SignerInfo["sid"],
): Certificate | undefined {
  if (sid instanceof IssuerAndSerialNumber) {
    return certs.find(
      (c) => c.serialNumber.isEqual(sid.serialNumber) && rdnEqual(c.issuer, sid.issuer),
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

function resolveIntermediateFromLotl(
  leaf: Certificate,
  file: TrustedCasFile,
): { der: Uint8Array; merkleIndex: number } | null {
  const wantDer = new Uint8Array(leaf.issuer.toSchema().toBER(false));
  for (const ca of file.cas) {
    let der: Uint8Array;
    try {
      der = b64ToBytes(ca.certDerB64);
    } catch {
      continue;
    }
    const parsed = tryParseCert(der);
    if (!parsed) continue;
    const subjDer = new Uint8Array(parsed.subject.toSchema().toBER(false));
    if (bytesEqual(subjDer, wantDer)) {
      return { der, merkleIndex: ca.merkleIndex };
    }
  }
  return null;
}

function indexInTrustedCas(target: Uint8Array, file: TrustedCasFile): number {
  for (const ca of file.cas) {
    try {
      if (bytesEqual(b64ToBytes(ca.certDerB64), target)) return ca.merkleIndex;
    } catch {
      continue;
    }
  }
  return -1;
}

function tryParseCert(der: Uint8Array): Certificate | null {
  try {
    const asn = asn1js.fromBER(toAB(der));
    if (asn.offset === -1) return null;
    return new Certificate({ schema: asn.result });
  } catch {
    return null;
  }
}

function readCn(rdn: { typesAndValues: ReadonlyArray<{ type: string; value: { valueBlock?: { value?: unknown } } }> }): string | undefined {
  for (const tv of rdn.typesAndValues) {
    if (tv.type === OID_CN) {
      const v = tv.value.valueBlock?.value;
      if (typeof v === "string") return v;
    }
  }
  return undefined;
}

function rdnEqual(a: { toSchema(): asn1js.AsnType }, b: { toSchema(): asn1js.AsnType }): boolean {
  const ad = new Uint8Array(a.toSchema().toBER(false));
  const bd = new Uint8Array(b.toSchema().toBER(false));
  return bytesEqual(ad, bd);
}

function certDer(cert: Certificate): Uint8Array {
  return new Uint8Array(cert.toSchema().toBER(false));
}

function ecdsaDerToRaw(der: Uint8Array, half: number): Uint8Array | null {
  const asn = asn1js.fromBER(toAB(der));
  if (asn.offset === -1) return null;
  const seq = asn.result as asn1js.Sequence;
  const [rNode, sNode] = seq.valueBlock.value as [asn1js.Integer, asn1js.Integer];
  const r = stripLead(new Uint8Array(rNode.valueBlock.valueHexView));
  const s = stripLead(new Uint8Array(sNode.valueBlock.valueHexView));
  if (r.length > half || s.length > half) return null;
  const out = new Uint8Array(half * 2);
  out.set(padLeft(r, half), 0);
  out.set(padLeft(s, half), half);
  return out;
}

function stripLead(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
}

function padLeft(b: Uint8Array, n: number): Uint8Array {
  if (b.length === n) return b;
  const out = new Uint8Array(n);
  out.set(b, n - b.length);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function toAB(b: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  return ab;
}

function b64ToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}
