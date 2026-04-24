#!/usr/bin/env node
// Extracts the leaf certificate DER from a Diia CAdES-BES .p7s.
// Emits base64 of the DER to stdout. Used to pin a real Diia leaf fixture
// for DobExtractorDiiaUA tests.
//
// Usage:
//   node packages/circuits/scripts/extract-diia-leaf.mjs <path-to-p7s>
//
// Sourced inline (rather than reusing packages/web/src/lib/cades.ts) to keep
// circuits-package scripts self-contained per orchestration boundaries.
import { readFileSync } from 'node:fs';
import * as asn1js from 'asn1js';
import { Certificate, ContentInfo, SignedData, SignerInfo } from 'pkijs';

const p7sPath = process.argv[2];
if (!p7sPath) {
  console.error('usage: extract-diia-leaf.mjs <p7s>');
  process.exit(2);
}

const buf = readFileSync(p7sPath);
const ab = new ArrayBuffer(buf.byteLength);
new Uint8Array(ab).set(buf);

const asn = asn1js.fromBER(ab);
if (asn.offset === -1) {
  console.error('failed to parse p7s as BER/DER');
  process.exit(1);
}

const contentInfo = new ContentInfo({ schema: asn.result });
const signedData = new SignedData({ schema: contentInfo.content });

if (!signedData.certificates || signedData.certificates.length === 0) {
  console.error('no certificates in SignedData');
  process.exit(1);
}

const signerInfo = signedData.signerInfos[0];
const issuerSerial = signerInfo.sid; // IssuerAndSerialNumber

let leaf = null;
for (const certAny of signedData.certificates) {
  const cert = /** @type {any} */ (certAny);
  if (!(cert instanceof Certificate)) continue;
  const sameSerial = cert.serialNumber.valueBlock.valueHexView
    && issuerSerial.serialNumber.valueBlock.valueHexView
    && Buffer.from(cert.serialNumber.valueBlock.valueHexView).equals(
      Buffer.from(issuerSerial.serialNumber.valueBlock.valueHexView),
    );
  if (sameSerial) {
    leaf = cert;
    break;
  }
}

if (!leaf) {
  console.error('could not match leaf by IssuerAndSerialNumber');
  process.exit(1);
}

const leafDer = new Uint8Array(leaf.toSchema(true).toBER(false));
process.stdout.write(Buffer.from(leafDer).toString('base64') + '\n');
