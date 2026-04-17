import { describe, expect, test } from 'vitest';
import { filterQes } from '../../src/filter/qesServices.js';
import type { RawService } from '../../src/fetch/msTl.js';

const SVC_CA_QC = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';
const SVC_UNSPEC = 'http://uri.etsi.org/TrstSvc/Svctype/unspecified';
const STATUS_GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const STATUS_WITHDRAWN = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn';

describe('filterQes', () => {
  test('keeps only CA/QC services with granted status', () => {
    const input: RawService[] = [
      {
        serviceTypeIdentifier: SVC_CA_QC,
        status: STATUS_GRANTED,
        x509CertificateList: [new Uint8Array([1])],
        statusStartingTime: 1_700_000_000,
      },
      {
        serviceTypeIdentifier: SVC_UNSPEC,
        status: STATUS_GRANTED,
        x509CertificateList: [new Uint8Array([2])],
        statusStartingTime: 1_700_000_000,
      },
      {
        serviceTypeIdentifier: SVC_CA_QC,
        status: STATUS_WITHDRAWN,
        x509CertificateList: [new Uint8Array([3])],
        statusStartingTime: 1_700_000_000,
      },
    ];
    const out = filterQes(input);
    expect(out).toHaveLength(1);
    expect(out[0]!.x509CertificateList[0]![0]).toBe(1);
  });

  test('drops services that have no certificates', () => {
    const out = filterQes([
      {
        serviceTypeIdentifier: SVC_CA_QC,
        status: STATUS_GRANTED,
        x509CertificateList: [],
        statusStartingTime: 1_700_000_000,
      },
    ]);
    expect(out).toHaveLength(0);
  });
});
