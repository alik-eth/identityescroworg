import { describe, expect, test } from 'vitest';
import type { RawService } from '../../src/fetch/msTl.js';
import { filterQes } from '../../src/filter/qesServices.js';

const SVC_CA_QC = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';
const UA_SVC_CA_QC = 'http://czo.gov.ua/TrstSvc/Svctype/CA/QC';
const UA_SVC_MR_CA_QC = 'http://czo.gov.ua/TrstSvc/Svctype/MR-CA/QC';
const SVC_UNSPEC = 'http://uri.etsi.org/TrstSvc/Svctype/unspecified';
const STATUS_GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const UA_STATUS_GRANTED = 'http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted';
const STATUS_WITHDRAWN = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn';
const QC_FOR_ESIG = 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig';
const QC_FOR_ESEAL = 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal';
const QC_FOR_LEGAL_PERSON = 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson';
const FORE_SIGNATURES = 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures';
const FORE_SEALS = 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals';

const service = (patch: Partial<RawService>): RawService => ({
  territory: 'EE',
  serviceTypeIdentifier: SVC_CA_QC,
  status: STATUS_GRANTED,
  x509CertificateList: [new Uint8Array([1])],
  statusStartingTime: 1_700_000_000,
  qualifiers: [],
  qualificationElements: [],
  ...patch,
});

describe('filterQes', () => {
  test('keeps only CA/QC services with granted status', () => {
    const input: RawService[] = [
      service({ x509CertificateList: [new Uint8Array([1])] }),
      service({
        serviceTypeIdentifier: SVC_UNSPEC,
        x509CertificateList: [new Uint8Array([2])],
      }),
      service({
        status: STATUS_WITHDRAWN,
        x509CertificateList: [new Uint8Array([3])],
      }),
    ];
    const out = filterQes(input);
    expect(out).toHaveLength(1);
    expect(out[0]?.x509CertificateList[0]?.[0]).toBe(1);
  });

  test('drops services that have no certificates', () => {
    const out = filterQes([
      service({
        x509CertificateList: [],
      }),
    ]);
    expect(out).toHaveLength(0);
  });

  test('keeps qualified e-signature services when qualifiers are explicit', () => {
    expect(filterQes([service({ qualifiers: [QC_FOR_ESIG] })])).toHaveLength(1);
  });

  test('drops CA/QC services explicitly qualified only for seals', () => {
    expect(filterQes([service({ qualifiers: [QC_FOR_ESEAL] })])).toHaveLength(0);
  });

  test('drops CA/QC services explicitly qualified only for legal persons', () => {
    expect(filterQes([service({ qualifiers: [QC_FOR_LEGAL_PERSON] })])).toHaveLength(0);
  });

  test('keeps services without a purpose qualifier when criteria require nonRepudiation', () => {
    expect(
      filterQes([
        service({
          qualificationElements: [
            {
              qualifiers: ['http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD'],
              criteria: {
                assert: 'atLeastOne',
                keyUsageBits: ['nonRepudiation'],
                policyIdentifiers: [],
              },
            },
          ],
        }),
      ]),
    ).toHaveLength(1);
  });

  test('drops services without a purpose qualifier when criteria do not indicate signatures', () => {
    expect(
      filterQes([
        service({
          qualificationElements: [
            {
              qualifiers: ['http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD'],
              criteria: {
                assert: 'atLeastOne',
                keyUsageBits: ['digitalSignature'],
                policyIdentifiers: [],
              },
            },
          ],
        }),
      ]),
    ).toHaveLength(0);
  });

  test('keeps Ukrainian cross-border CA/QC services qualified for foreign signatures', () => {
    expect(
      filterQes([
        service({
          serviceTypeIdentifier: UA_SVC_CA_QC,
          status: UA_STATUS_GRANTED,
          qualifiers: [FORE_SIGNATURES],
        }),
        service({
          serviceTypeIdentifier: UA_SVC_MR_CA_QC,
          status: UA_STATUS_GRANTED,
          qualifiers: [FORE_SIGNATURES],
        }),
      ]),
    ).toHaveLength(2);
  });

  test('drops Ukrainian services qualified only for foreign seals', () => {
    expect(
      filterQes([
        service({
          serviceTypeIdentifier: UA_SVC_CA_QC,
          status: UA_STATUS_GRANTED,
          qualifiers: [FORE_SEALS],
        }),
      ]),
    ).toHaveLength(0);
  });
});
