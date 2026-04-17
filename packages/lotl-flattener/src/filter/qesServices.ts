import type { RawService } from '../fetch/msTl.js';

export type { RawService };

const SVC_CA_QC = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';
const STATUS_GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';

export function filterQes(services: RawService[]): RawService[] {
  return services.filter(
    (s) =>
      s.serviceTypeIdentifier === SVC_CA_QC &&
      s.status === STATUS_GRANTED &&
      s.x509CertificateList.length > 0,
  );
}
