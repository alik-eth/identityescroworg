/**
 * Subprocess test for scripts/verify-real-qes.mjs.
 *
 * Generates a SYNTHETIC CAdES-BES detached over a synthetic binding using
 * pkijs + WebCrypto (RSA-2048 / SHA-256 leaf), writes the pair to a temp
 * dir, then runs the verifier as a child process and asserts PASS in its
 * JSON output. The real Diia .p7s never enters the test suite.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { sha256 } from '@noble/hashes/sha256';

pkijs.setEngine(
  'node-webcrypto',
  new pkijs.CryptoEngine({ name: 'node', crypto: globalThis.crypto }),
);

let tmp: string;
let bindingPath: string;
let p7sPath: string;
const repoRoot = resolve(__dirname, '../../../..');
const scriptPath = resolve(repoRoot, 'packages/web/scripts/verify-real-qes.mjs');

beforeAll(async () => {
  tmp = mkdtempSync(join(tmpdir(), 'qkb-verify-'));
  bindingPath = join(tmp, 'binding.qkb.json');
  p7sPath = join(tmp, 'binding.qkb.json.p7s');
  const bindingBytes = new TextEncoder().encode(
    JSON.stringify({ v: 'QKB/1.0', test: 'synthetic' }),
  );
  writeFileSync(bindingPath, bindingBytes);

  const subtle = globalThis.crypto.subtle;
  const kp = (await subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 12345 });
  setName(cert.subject, 'Synthetic QES Test');
  setName(cert.issuer, 'Synthetic QES Test');
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
    sid: new pkijs.IssuerAndSerialNumber({ issuer: cert.issuer, serialNumber: cert.serialNumber }),
    signedAttrs,
  });
  const signed = new pkijs.SignedData({
    version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: '1.2.840.113549.1.7.1' }),
    signerInfos: [signerInfo],
    certificates: [cert],
  });
  await signed.sign(kp.privateKey, 0, 'SHA-256');
  const ci = new pkijs.ContentInfo({
    contentType: pkijs.id_ContentType_SignedData,
    content: signed.toSchema(true),
  });
  writeFileSync(p7sPath, new Uint8Array(ci.toSchema().toBER(false)));
}, 60_000);

afterAll(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

describe('verify-real-qes script', () => {
  it('returns PASS on a synthetic RSA-2048 detached CAdES-BES over the binding', () => {
    const r = spawnSync(
      'node',
      ['--import', 'tsx', scriptPath, bindingPath, p7sPath],
      { encoding: 'utf8', cwd: repoRoot },
    );
    if (r.status !== 0) {
      throw new Error(`script exited ${r.status}\nstderr:\n${r.stderr}\nstdout:\n${r.stdout}`);
    }
    const out = JSON.parse(r.stdout) as { outcome: string; scheme: string; keyBits: number };
    expect(out.outcome).toBe('PASS');
    expect(out.scheme).toBe('RSA-PKCS1v1_5/SHA-256');
    expect(out.keyBits).toBe(2048);
  }, 30_000);

  it('returns FAIL (exit 1) when the binding is mutated', () => {
    const tamperedBinding = join(tmp, 'binding.tampered.json');
    writeFileSync(tamperedBinding, new TextEncoder().encode('{"v":"different"}'));
    const r = spawnSync(
      'node',
      ['--import', 'tsx', scriptPath, tamperedBinding, p7sPath],
      { encoding: 'utf8', cwd: repoRoot },
    );
    expect(r.status).not.toBe(0);
    expect(r.stderr + r.stdout).toMatch(/messageDigest|FATAL/);
  }, 30_000);
});

function setName(target: pkijs.RelativeDistinguishedNames, cn: string): void {
  target.typesAndValues = [
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.Utf8String({ value: cn }),
    }),
  ];
}
