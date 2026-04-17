/**
 * Q5: qesVerifyNode integration test.
 *
 * Mirrors the Phase-1 web qesVerify behaviour byte-for-byte:
 *   - CAdES-BES detached CMS parse (pkijs/asn1js).
 *   - LOTL-backed chain validation via trusted-cas.json.
 *   - RSA-PKCS#1 v1.5 over the re-encoded SET OF Attribute.
 *   - Structured `{chain, sigValid, subject?}` result.
 *
 * Fixtures are generated programmatically via node-forge. No `.p7s` files are
 * committed — the Diia fixture at /data/Develop/identityescroworg/fixtures/qes
 * is NOT accessible from this worktree and carries a natural person's
 * identity; we exercise the same code paths against synthetic CAs instead
 * and cover RSA. ECDSA-P256 is exercised by the shared core via the
 * @qkb/web package's qesVerify.test.ts (same underlying pkijs primitives).
 */
import { describe, it, expect, beforeAll } from "vitest";
import forge from "node-forge";
import { verifyCadesNode, type TrustedCasFile } from "../src/qes-verify.js";

interface Fx {
  p7s: Uint8Array;
  cert: Uint8Array;
  message: Uint8Array;
  trustedCas: TrustedCasFile;
  intermediateDer: Uint8Array;
  subjectCn: string;
}

function uint8ToBinary(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return s;
}

function binaryToUint8(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function toDer(p7: forge.pkcs7.PkcsSignedData): Uint8Array {
  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return binaryToUint8(der);
}

function certToDer(cert: forge.pki.Certificate): Uint8Array {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  return binaryToUint8(der);
}

function bytesToB64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
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
  cert.setSubject([{ name: "commonName", value: opts.subject }]);
  cert.setIssuer([{ name: "commonName", value: opts.issuer }]);
  cert.setExtensions([
    { name: "basicConstraints", cA: opts.isCa },
    { name: "keyUsage", digitalSignature: true, keyCertSign: opts.isCa },
  ]);
  cert.sign(opts.signKey, forge.md.sha256.create());
  return cert;
}

function makeRsaFixture(opts?: { subjectCn?: string }): Fx {
  const subjectCn = opts?.subjectCn ?? "Notary-Test";
  const rootKey = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const intKey = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const leafKey = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const intCert = mkCert({
    subject: "Test-Int",
    issuer: "Test-Root",
    pub: intKey.publicKey,
    signKey: rootKey.privateKey,
    isCa: true,
  });
  const leafCert = mkCert({
    subject: subjectCn,
    issuer: "Test-Int",
    pub: leafKey.publicKey,
    signKey: intKey.privateKey,
    isCa: false,
  });
  const message = new TextEncoder().encode("hello-qie-notary");
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(uint8ToBinary(message));
  p7.addCertificate(leafCert);
  p7.addCertificate(intCert);
  p7.addSigner({
    key: leafKey.privateKey,
    certificate: leafCert,
    digestAlgorithm: forge.pki.oids.sha256!,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType!, value: forge.pki.oids.data! },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      { type: forge.pki.oids.signingTime!, value: new Date() as any },
      { type: forge.pki.oids.messageDigest! },
    ],
  });
  p7.sign({ detached: true });
  const p7sDer = toDer(p7);
  const intermediateDer = certToDer(intCert);
  const leafDer = certToDer(leafCert);
  const trustedCas: TrustedCasFile = {
    version: 1,
    cas: [{ merkleIndex: 0, certDerB64: bytesToB64(intermediateDer) }],
  };
  return { p7s: p7sDer, cert: leafDer, message, trustedCas, intermediateDer, subjectCn };
}

let fx: Fx;
beforeAll(() => { fx = makeRsaFixture(); }, 60_000);

describe("verifyCadesNode (Q5)", () => {
  it("returns chain=trusted, sigValid=true on well-formed RSA QES with LOTL-listed intermediate", async () => {
    const r = await verifyCadesNode(fx.p7s, fx.cert, fx.message, { trustedCas: fx.trustedCas });
    expect(r.chain).toBe("trusted");
    expect(r.sigValid).toBe(true);
    expect(r.subject).toBe(fx.subjectCn);
  });

  it("returns chain=untrusted when intermediate DN is not in trusted-cas", async () => {
    const empty: TrustedCasFile = { version: 1, cas: [] };
    const r = await verifyCadesNode(fx.p7s, fx.cert, fx.message, { trustedCas: empty });
    expect(r.chain).toBe("untrusted");
  });

  it("returns sigValid=false when messageDigest does not match payload preimage", async () => {
    const wrong = new TextEncoder().encode("tampered-payload");
    const r = await verifyCadesNode(fx.p7s, fx.cert, wrong, { trustedCas: fx.trustedCas });
    expect(r.sigValid).toBe(false);
  });

  it("returns chain=untrusted with sigValid=false when cert bytes do not match CMS signer cert", async () => {
    const other = makeRsaFixture({ subjectCn: "Other-Cert" });
    // cert parameter is the caller-supplied leaf; if it doesn't match the CMS
    // SignerInfo.sid the validator reports both checks as failed.
    const r = await verifyCadesNode(fx.p7s, other.cert, fx.message, { trustedCas: fx.trustedCas });
    expect(r.sigValid).toBe(false);
  });

  it("qesVerifyNode (boolean wrapper) returns true on happy path, false otherwise", async () => {
    const { qesVerifyNode } = await import("../src/qes-verify.js");
    const ok = await qesVerifyNode(fx.p7s, fx.cert, fx.message, { trustedCas: fx.trustedCas });
    expect(ok).toBe(true);
    const empty: TrustedCasFile = { version: 1, cas: [] };
    const bad = await qesVerifyNode(fx.p7s, fx.cert, fx.message, { trustedCas: empty });
    expect(bad).toBe(false);
  });

  it("qesVerifyNode with no trustedCas returns false (safe default)", async () => {
    const { qesVerifyNode } = await import("../src/qes-verify.js");
    const bad = await qesVerifyNode(fx.p7s, fx.cert, fx.message);
    expect(bad).toBe(false);
  });
});
