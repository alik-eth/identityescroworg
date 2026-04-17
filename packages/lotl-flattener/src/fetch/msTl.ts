import { XMLParser } from 'fast-xml-parser';

export interface RawService {
  serviceTypeIdentifier: string;
  status: string;
  statusStartingTime: number;
  x509CertificateList: Uint8Array[];
}

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  removeNSPrefix: true,
});

const asArray = <T>(v: T | T[] | undefined): T[] =>
  v === undefined ? [] : Array.isArray(v) ? v : [v];

const decodeB64 = (b64: string): Uint8Array => {
  const clean = b64.replace(/\s+/g, '');
  return Uint8Array.from(Buffer.from(clean, 'base64'));
};

const toEpochSeconds = (iso: string): number => {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? Math.floor(t / 1000) : 0;
};

export function parseMsTl(xml: string): RawService[] {
  const doc = parser.parse(xml);
  const tsl = doc?.TrustServiceStatusList;
  if (!tsl?.TrustServiceProviderList) {
    throw new Error('not a Member State trusted list: missing TrustServiceProviderList');
  }
  const tsps = asArray<Record<string, unknown>>(
    tsl.TrustServiceProviderList.TrustServiceProvider,
  );
  const out: RawService[] = [];
  for (const tsp of tsps) {
    const services = asArray<Record<string, unknown>>(
      (tsp.TSPServices as Record<string, unknown> | undefined)?.TSPService as
        | Record<string, unknown>
        | Record<string, unknown>[]
        | undefined,
    );
    for (const svc of services) {
      const info = svc.ServiceInformation as Record<string, unknown> | undefined;
      if (!info) continue;
      const digitalIds = asArray<Record<string, unknown>>(
        (info.ServiceDigitalIdentity as Record<string, unknown> | undefined)?.DigitalId as
          | Record<string, unknown>
          | Record<string, unknown>[]
          | undefined,
      );
      const certs: Uint8Array[] = [];
      for (const did of digitalIds) {
        const x509 = did.X509Certificate;
        if (typeof x509 === 'string') certs.push(decodeB64(x509));
        else if (Array.isArray(x509)) {
          for (const c of x509) if (typeof c === 'string') certs.push(decodeB64(c));
        }
      }
      out.push({
        serviceTypeIdentifier: String(info.ServiceTypeIdentifier ?? ''),
        status: String(info.ServiceStatus ?? ''),
        statusStartingTime: toEpochSeconds(String(info.StatusStartingTime ?? '')),
        x509CertificateList: certs,
      });
    }
  }
  return out;
}
