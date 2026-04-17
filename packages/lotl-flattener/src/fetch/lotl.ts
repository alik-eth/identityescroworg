import { XMLParser } from 'fast-xml-parser';

export interface LotlPointer {
  territory: string;
  location: string;
  mimeType: string;
}

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  removeNSPrefix: true,
});

export function parseLotl(xml: string): LotlPointer[] {
  const doc = parser.parse(xml);
  const tsl = doc?.TrustServiceStatusList;
  if (!tsl) throw new Error('not a LOTL: missing TrustServiceStatusList');
  const raw = tsl?.SchemeInformation?.PointersToOtherTSL?.OtherTSLPointer ?? [];
  const arr = Array.isArray(raw) ? raw : [raw];
  return arr
    .map((p: Record<string, unknown>) => {
      const info = (p?.AdditionalInformation as Record<string, unknown> | undefined)
        ?.OtherInformation as Record<string, unknown> | undefined;
      return {
        territory: String(info?.SchemeTerritory ?? ''),
        location: String(p?.TSLLocation ?? ''),
        mimeType: String(info?.MimeType ?? ''),
      };
    })
    .filter((p: LotlPointer) => p.territory && p.location);
}

export async function fetchLotl(url: string): Promise<string> {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`LOTL fetch failed: ${resp.status}`);
  return await resp.text();
}
