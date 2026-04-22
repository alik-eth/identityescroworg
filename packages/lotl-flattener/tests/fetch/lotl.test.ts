import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { type LotlPointer, fetchLotl, parseLotl } from '../../src/fetch/lotl.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(here, '../../fixtures/lotl-mini.xml');

afterEach(() => {
  vi.restoreAllMocks();
});

describe('parseLotl', () => {
  test('extracts MS pointers from LOTL xml', async () => {
    const xml = await readFile(fixturePath, 'utf8');
    const pointers: LotlPointer[] = parseLotl(xml);
    expect(pointers).toHaveLength(2);
    expect(pointers.map((p) => p.territory).sort()).toEqual(['EE', 'PL']);
    expect(pointers[0]?.location).toBe('ms-tl-ee.xml');
    expect(pointers[0]?.x509CertificateList).toEqual([]);
  });

  test('extracts MS TL signing certificates from LOTL pointers', () => {
    const cert = Buffer.from([1, 2, 3]).toString('base64');
    const xml = `<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
      <SchemeInformation>
        <PointersToOtherTSL>
          <OtherTSLPointer>
            <TSLLocation>https://tl.example.test/ee.xml</TSLLocation>
            <ServiceDigitalIdentities>
              <ServiceDigitalIdentity>
                <DigitalId><X509Certificate>${cert}</X509Certificate></DigitalId>
              </ServiceDigitalIdentity>
            </ServiceDigitalIdentities>
            <AdditionalInformation>
              <OtherInformation><SchemeTerritory>EE</SchemeTerritory></OtherInformation>
            </AdditionalInformation>
          </OtherTSLPointer>
        </PointersToOtherTSL>
      </SchemeInformation>
    </TrustServiceStatusList>`;
    const [pointer] = parseLotl(xml);
    expect(pointer?.x509CertificateList).toHaveLength(1);
    expect([...(pointer?.x509CertificateList[0] ?? [])]).toEqual([1, 2, 3]);
  });

  test('handles live LOTL OtherInformation arrays and skips EU self pointer', () => {
    const xml = `<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
      <SchemeInformation>
        <PointersToOtherTSL>
          <OtherTSLPointer>
            <TSLLocation>https://ec.europa.eu/tools/lotl/eu-lotl.xml</TSLLocation>
            <AdditionalInformation>
              <OtherInformation><TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType></OtherInformation>
              <OtherInformation><SchemeTerritory>EU</SchemeTerritory></OtherInformation>
              <OtherInformation><MimeType>application/vnd.etsi.tsl+xml</MimeType></OtherInformation>
            </AdditionalInformation>
          </OtherTSLPointer>
          <OtherTSLPointer>
            <TSLLocation>https://tl.example.test/at.xml</TSLLocation>
            <AdditionalInformation>
              <OtherInformation><SchemeTerritory>AT</SchemeTerritory></OtherInformation>
              <OtherInformation><MimeType>application/vnd.etsi.tsl+xml</MimeType></OtherInformation>
            </AdditionalInformation>
          </OtherTSLPointer>
          <OtherTSLPointer>
            <TSLLocation>https://eur-lex.europa.eu/legal-content/example.pdf</TSLLocation>
            <AdditionalInformation>
              <OtherInformation><SchemeTerritory>OJ</SchemeTerritory></OtherInformation>
              <OtherInformation><MimeType>application/pdf</MimeType></OtherInformation>
            </AdditionalInformation>
          </OtherTSLPointer>
        </PointersToOtherTSL>
      </SchemeInformation>
    </TrustServiceStatusList>`;

    expect(parseLotl(xml)).toEqual([
      {
        territory: 'AT',
        location: 'https://tl.example.test/at.xml',
        mimeType: 'application/vnd.etsi.tsl+xml',
        x509CertificateList: [],
      },
    ]);
  });

  test('throws on malformed xml', () => {
    expect(() => parseLotl('<not-lotl/>')).toThrow(/not a LOTL/);
  });
});

describe('fetchLotl', () => {
  test('retries transient network failures', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockResolvedValueOnce(new Response('<TrustServiceStatusList/>', { status: 200 }));

    await expect(fetchLotl('https://tl.example.test/tsl.xml')).resolves.toBe(
      '<TrustServiceStatusList/>',
    );
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });
});
