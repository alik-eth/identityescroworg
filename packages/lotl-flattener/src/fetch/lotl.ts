// Strips the ETSI TS 119 612 namespace prefix so element paths stay flat;
// production LOTL parsers do the same.
import { XMLParser } from 'fast-xml-parser';

export interface LotlPointer {
  territory: string;
  location: string;
  mimeType: string;
  x509CertificateList: Uint8Array[];
}

export interface FetchLotlOpts {
  allowInsecureTransport?: boolean | undefined;
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

const parsePointerCerts = (p: Record<string, unknown>): Uint8Array[] => {
  const identities = asArray<Record<string, unknown>>(
    (p.ServiceDigitalIdentities as Record<string, unknown> | undefined)?.ServiceDigitalIdentity as
      | Record<string, unknown>
      | Record<string, unknown>[]
      | undefined,
  );
  const out: Uint8Array[] = [];
  for (const identity of identities) {
    const digitalIds = asArray<Record<string, unknown>>(
      identity.DigitalId as Record<string, unknown> | Record<string, unknown>[] | undefined,
    );
    for (const did of digitalIds) {
      const cert = did.X509Certificate;
      if (typeof cert === 'string') out.push(decodeB64(cert));
    }
  }
  return out;
};

const parsePointerInfo = (
  p: Record<string, unknown>,
): Pick<LotlPointer, 'territory' | 'mimeType'> => {
  const otherInfo = asArray<Record<string, unknown>>(
    (p.AdditionalInformation as Record<string, unknown> | undefined)?.OtherInformation as
      | Record<string, unknown>
      | Record<string, unknown>[]
      | undefined,
  );
  const findString = (key: string): string => {
    for (const info of otherInfo) {
      const value = info[key];
      if (typeof value === 'string') return value;
    }
    return '';
  };
  return {
    territory: findString('SchemeTerritory'),
    mimeType: findString('MimeType'),
  };
};

const isTrustedListPointer = (p: LotlPointer): boolean =>
  Boolean(p.territory) &&
  p.territory !== 'EU' &&
  Boolean(p.location) &&
  (!p.mimeType || p.mimeType === 'application/vnd.etsi.tsl+xml');

export function parseLotl(xml: string): LotlPointer[] {
  const doc = parser.parse(xml);
  const tsl = doc?.TrustServiceStatusList;
  if (!tsl) throw new Error('not a LOTL: missing TrustServiceStatusList');
  const raw = tsl?.SchemeInformation?.PointersToOtherTSL?.OtherTSLPointer ?? [];
  const arr = Array.isArray(raw) ? raw : [raw];
  return arr
    .map((p: Record<string, unknown>) => {
      const info = parsePointerInfo(p);
      return {
        territory: info.territory,
        location: String(p?.TSLLocation ?? ''),
        mimeType: info.mimeType,
        x509CertificateList: parsePointerCerts(p),
      };
    })
    .filter(isTrustedListPointer);
}

const RETRYABLE_HTTP_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);

const sleep = async (ms: number): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, ms));
};

const withInsecureTransport = async <T>(enabled: boolean, fn: () => Promise<T>): Promise<T> => {
  if (!enabled) return await fn();
  const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  try {
    return await fn();
  } finally {
    if (previous === undefined) Reflect.deleteProperty(process.env, 'NODE_TLS_REJECT_UNAUTHORIZED');
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous;
  }
};

export async function fetchLotl(url: string, opts: FetchLotlOpts = {}): Promise<string> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      const resp = await withInsecureTransport(Boolean(opts.allowInsecureTransport), async () =>
        fetch(url),
      );
      if (resp.ok) return await resp.text();
      lastError = new Error(`LOTL fetch failed: ${resp.status}`);
      if (!RETRYABLE_HTTP_STATUSES.has(resp.status)) throw lastError;
    } catch (cause) {
      lastError = cause;
      if (attempt === 5) break;
    }
    await sleep(1000 * attempt);
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}
