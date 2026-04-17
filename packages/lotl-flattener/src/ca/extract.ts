import { Certificate } from 'pkijs';
import type { RawService } from '../filter/qesServices.js';
import type { ExtractedCA } from '../types.js';

export type { ExtractedCA };

const renderName = (name: { typesAndValues: { type: string; value: { valueBlock: { value: unknown } } }[] }): string =>
  name.typesAndValues
    .map((tv) => `${tv.type}=${String(tv.value.valueBlock.value)}`)
    .join(',');

export function extractCAs(services: RawService[]): ExtractedCA[] {
  const out: ExtractedCA[] = [];
  for (const svc of services) {
    for (const der of svc.x509CertificateList) {
      const ab = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength);
      const parsed = Certificate.fromBER(ab);
      out.push({
        certDer: der,
        issuerDN: renderName(parsed.issuer),
        validFrom: Math.floor(parsed.notBefore.value.getTime() / 1000),
        validTo: Math.floor(parsed.notAfter.value.getTime() / 1000),
      });
    }
  }
  return out;
}
