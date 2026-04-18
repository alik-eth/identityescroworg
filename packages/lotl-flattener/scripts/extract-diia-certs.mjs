// One-shot utility: extracts all certificates from a CAdES/CMS detached
// signature, writes each as DER to fixtures/diia/certs/<subject-hash>.der,
// and prints subject/issuer/validity metadata to stdout.
//
// Run from the package directory:
//   node scripts/extract-diia-certs.mjs fixtures/diia/<name>.p7s

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname, basename } from 'node:path';
import { createHash } from 'node:crypto';
import * as asn1js from 'asn1js';
import { ContentInfo, SignedData, Certificate } from 'pkijs';

const renderName = (name) =>
  name.typesAndValues
    .map((tv) => `${tv.type}=${String(tv.value.valueBlock.value)}`)
    .join(',');

async function main() {
  const p7sPath = process.argv[2];
  if (!p7sPath) {
    console.error('usage: node extract-diia-certs.mjs <path.p7s>');
    process.exit(1);
  }
  const abs = resolve(p7sPath);
  const outDir = resolve(dirname(abs), 'certs');
  await mkdir(outDir, { recursive: true });

  const buf = await readFile(abs);
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  const asn = asn1js.fromBER(ab);
  if (asn.offset === -1) throw new Error('cannot parse .p7s ASN.1');
  const ci = new ContentInfo({ schema: asn.result });
  const sd = new SignedData({ schema: ci.content });
  const certs = sd.certificates ?? [];
  console.error(`[info] SignedData carries ${certs.length} certificates`);

  const signerCerts = new Set();
  for (const si of sd.signerInfos ?? []) {
    const iasn = si.sid?.issuer;
    const serial = si.sid?.serialNumber;
    if (!iasn || !serial) continue;
    for (const c of certs) {
      if (!(c instanceof Certificate)) continue;
      if (renderName(c.issuer) === renderName(iasn) &&
          bufEq(c.serialNumber.valueBlock.valueHexView, serial.valueBlock.valueHexView)) {
        signerCerts.add(c);
      }
    }
  }

  const result = [];
  for (const c of certs) {
    if (!(c instanceof Certificate)) continue;
    const der = new Uint8Array(c.toSchema(true).toBER(false));
    const sha = createHash('sha256').update(der).digest('hex').slice(0, 16);
    const subject = renderName(c.subject);
    const issuer = renderName(c.issuer);
    const isLeaf = signerCerts.has(c);
    const isSelfSigned = subject === issuer;
    const kind = isLeaf ? 'leaf' : isSelfSigned ? 'root' : 'intermediate';
    const filename = `${kind}-${sha}.der`;
    await writeFile(resolve(outDir, filename), der);
    result.push({
      file: filename,
      kind,
      subject,
      issuer,
      validFrom: c.notBefore.value.toISOString(),
      validTo: c.notAfter.value.toISOString(),
      sigAlgoOid: c.signatureAlgorithm.algorithmId,
      spkiOid: c.subjectPublicKeyInfo.algorithm.algorithmId,
    });
  }
  console.log(JSON.stringify(result, null, 2));
}

function bufEq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
