// Prints extension data (AIA CA issuer URLs, CRL DPs) from a DER cert.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import * as asn1js from 'asn1js';
import { Certificate, AuthorityKeyIdentifier } from 'pkijs';

const path = resolve(process.argv[2]);
const buf = await readFile(path);
const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
const asn = asn1js.fromBER(ab);
const c = new Certificate({ schema: asn.result });

console.log('subject :', c.subject.typesAndValues.map(tv => `${tv.type}=${tv.value.valueBlock.value}`).join(', '));
console.log('issuer  :', c.issuer.typesAndValues.map(tv => `${tv.type}=${tv.value.valueBlock.value}`).join(', '));
console.log('serial  :', Buffer.from(c.serialNumber.valueBlock.valueHexView).toString('hex'));
console.log();
for (const ext of c.extensions ?? []) {
  console.log('ext oid :', ext.extnID, ext.critical ? '(critical)' : '');
  if (ext.extnID === '1.3.6.1.5.5.7.1.1') {
    // Authority Info Access
    const seq = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView.buffer.slice(
      ext.extnValue.valueBlock.valueHexView.byteOffset,
      ext.extnValue.valueBlock.valueHexView.byteOffset + ext.extnValue.valueBlock.valueHexView.byteLength,
    )).result;
    for (const ad of seq.valueBlock.value ?? []) {
      const oid = ad.valueBlock.value[0].valueBlock.toString();
      const loc = ad.valueBlock.value[1];
      const uri = loc?.valueBlock?.value ?? loc?.valueBlock?.valueBlock?.value;
      // GeneralName [6] IMPLICIT IA5String → pkijs leaves the raw bytes
      const raw = loc?.valueBlock?.valueHex ?? loc?.valueBlock?.valueHexView;
      let uriStr = '';
      if (raw) {
        uriStr = new TextDecoder().decode(new Uint8Array(raw));
      }
      console.log('  accessMethod:', oid, '  loc:', uriStr);
    }
  }
  if (ext.extnID === '2.5.29.31') {
    const seq = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView.buffer.slice(
      ext.extnValue.valueBlock.valueHexView.byteOffset,
      ext.extnValue.valueBlock.valueHexView.byteOffset + ext.extnValue.valueBlock.valueHexView.byteLength,
    )).result;
    console.log('  CRL distribution points:');
    const walk = (node, depth = 0) => {
      if (!node?.valueBlock) return;
      if (node.valueBlock.valueHex && node.idBlock?.tagNumber === 6 && node.idBlock?.tagClass === 3) {
        console.log('   ', '  '.repeat(depth), 'URI:', new TextDecoder().decode(new Uint8Array(node.valueBlock.valueHex)));
      }
      for (const ch of node.valueBlock.value ?? []) walk(ch, depth + 1);
    };
    walk(seq);
  }
}
