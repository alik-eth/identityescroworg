import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import { type RawService, parseMsTl } from '../../src/fetch/msTl.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(here, '../../fixtures/ms-tl-ee.xml');

describe('parseMsTl', () => {
  test('returns one RawService per TSPService with decoded certs', async () => {
    const xml = await readFile(fixturePath, 'utf8');
    const services: RawService[] = parseMsTl(xml);
    expect(services).toHaveLength(2);
    const caQc = services.find((s) => s.serviceTypeIdentifier.endsWith('CA/QC'));
    const other = services.find((s) => s.serviceTypeIdentifier.endsWith('unspecified'));
    expect(caQc).toBeDefined();
    expect(other).toBeDefined();
    expect(caQc?.territory).toBe('EE');
    expect(caQc?.tspName).toBe('SK ID Solutions AS');
    expect(caQc?.serviceName).toBe('EE Certification Centre Root CA');
    expect(caQc?.status).toMatch(/granted$/);
    expect(caQc?.x509CertificateList).toHaveLength(1);
    expect(caQc?.x509CertificateList[0]).toBeInstanceOf(Uint8Array);
    expect(caQc?.x509CertificateList[0]?.length).toBeGreaterThan(0);
    expect(caQc?.qualifiers).toEqual([]);
    expect(caQc?.qualificationElements).toEqual([]);
    expect(typeof caQc?.statusStartingTime).toBe('number');
    expect(caQc?.statusStartingTime).toBeGreaterThan(1_500_000_000);
  });

  test('returns service history instances with derived ending times and qualifiers', () => {
    const cert = Buffer.from([1, 2, 3]).toString('base64');
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
        <SchemeInformation><SchemeTerritory>DE</SchemeTerritory></SchemeInformation>
        <TrustServiceProviderList>
          <TrustServiceProvider>
            <TSPInformation><TSPName><Name xml:lang="en">DE QTSP</Name></TSPName></TSPInformation>
            <TSPServices>
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                  <ServiceName><Name xml:lang="en">Current CA</Name></ServiceName>
                  <ServiceDigitalIdentity><DigitalId><X509Certificate>${cert}</X509Certificate></DigitalId></ServiceDigitalIdentity>
                  <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
                  <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
                  <ServiceInformationExtensions>
                    <Extension>
                      <Qualifications>
                        <QualificationElement>
                          <Qualifiers>
                            <Qualifier><QualifierUri>http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig</QualifierUri></Qualifier>
                          </Qualifiers>
                        </QualificationElement>
                      </Qualifications>
                    </Extension>
                  </ServiceInformationExtensions>
                </ServiceInformation>
                <ServiceHistory>
                  <ServiceHistoryInstance>
                    <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                    <ServiceDigitalIdentity><DigitalId><X509Certificate>${cert}</X509Certificate></DigitalId></ServiceDigitalIdentity>
                    <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
                    <StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime>
                  </ServiceHistoryInstance>
                </ServiceHistory>
              </TSPService>
            </TSPServices>
          </TrustServiceProvider>
        </TrustServiceProviderList>
      </TrustServiceStatusList>`;

    const services = parseMsTl(xml);
    expect(services).toHaveLength(2);
    expect(services[0]).toMatchObject({
      territory: 'DE',
      tspName: 'DE QTSP',
      status: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn',
      statusEndingTime: 1_704_067_199,
    });
    expect(services[1]).toMatchObject({
      serviceName: 'Current CA',
      qualifiers: ['http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig'],
      qualificationElements: [
        {
          qualifiers: ['http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig'],
          criteria: {
            keyUsageBits: [],
            policyIdentifiers: [],
          },
        },
      ],
    });
  });

  test('parses live QualificationElement attributes and CriteriaList fields', () => {
    const cert = Buffer.from([1, 2, 3]).toString('base64');
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
        <SchemeInformation><SchemeTerritory>IT</SchemeTerritory></SchemeInformation>
        <TrustServiceProviderList>
          <TrustServiceProvider>
            <TSPServices>
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                  <ServiceDigitalIdentity><DigitalId><X509Certificate>${cert}</X509Certificate></DigitalId></ServiceDigitalIdentity>
                  <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
                  <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
                  <ServiceInformationExtensions>
                    <Extension>
                      <Qualifications>
                        <QualificationElement>
                          <Qualifiers>
                            <Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"/>
                            <Qualifier uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson"/>
                          </Qualifiers>
                          <CriteriaList assert="atLeastOne">
                            <KeyUsage>
                              <KeyUsageBit name="nonRepudiation">true</KeyUsageBit>
                              <KeyUsageBit name="digitalSignature">false</KeyUsageBit>
                            </KeyUsage>
                            <PolicySet>
                              <PolicyIdentifier>
                                <Identifier Qualifier="OIDAsURN">urn:oid:1.2.3.4</Identifier>
                              </PolicyIdentifier>
                              <PolicyIdentifier>
                                <Identifier>urn:oid:1.2.3.5</Identifier>
                              </PolicyIdentifier>
                            </PolicySet>
                          </CriteriaList>
                        </QualificationElement>
                      </Qualifications>
                    </Extension>
                  </ServiceInformationExtensions>
                </ServiceInformation>
              </TSPService>
            </TSPServices>
          </TrustServiceProvider>
        </TrustServiceProviderList>
      </TrustServiceStatusList>`;

    const services = parseMsTl(xml);
    expect(services).toHaveLength(1);
    expect(services[0]?.qualifiers).toEqual([
      'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson',
      'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD',
    ]);
    expect(services[0]?.qualificationElements).toEqual([
      {
        qualifiers: [
          'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson',
          'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD',
        ],
        criteria: {
          assert: 'atLeastOne',
          keyUsageBits: ['nonRepudiation'],
          policyIdentifiers: ['urn:oid:1.2.3.4', 'urn:oid:1.2.3.5'],
        },
      },
    ]);
  });

  test('parses AdditionalServiceInformation URI values as qualifiers', () => {
    const cert = Buffer.from([1, 2, 3]).toString('base64');
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
        <SchemeInformation><SchemeTerritory>UA</SchemeTerritory></SchemeInformation>
        <TrustServiceProviderList>
          <TrustServiceProvider>
            <TSPServices>
              <TSPService>
                <ServiceInformation>
                  <ServiceTypeIdentifier>http://czo.gov.ua/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                  <ServiceDigitalIdentity><DigitalId><X509Certificate>${cert}</X509Certificate></DigitalId></ServiceDigitalIdentity>
                  <ServiceStatus>http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
                  <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
                  <ServiceInformationExtensions>
                    <Extension>
                      <AdditionalServiceInformation>
                        <URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</URI>
                      </AdditionalServiceInformation>
                    </Extension>
                  </ServiceInformationExtensions>
                </ServiceInformation>
              </TSPService>
            </TSPServices>
          </TrustServiceProvider>
        </TrustServiceProviderList>
      </TrustServiceStatusList>`;

    const services = parseMsTl(xml);
    expect(services).toHaveLength(1);
    expect(services[0]?.qualifiers).toEqual([
      'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures',
    ]);
  });

  test('throws on xml that is not an MS TL', () => {
    expect(() => parseMsTl('<not-tsl/>')).toThrow(/not a Member State/);
  });
});
