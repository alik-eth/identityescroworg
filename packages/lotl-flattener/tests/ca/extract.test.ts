import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import { extractCAs } from '../../src/ca/extract.js';
import type { RawService } from '../../src/fetch/msTl.js';

const here = dirname(fileURLToPath(import.meta.url));
const derPath = resolve(here, '../../fixtures/certs/test-ca.der');

const STATUS_GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const SVC_CA_QC = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';

describe('extractCAs', () => {
  test('parses DER fields from a real cert', async () => {
    const der = new Uint8Array(await readFile(derPath));
    const services: RawService[] = [
      {
        serviceTypeIdentifier: SVC_CA_QC,
        status: STATUS_GRANTED,
        statusStartingTime: 1_700_000_000,
        x509CertificateList: [der],
      },
    ];
    const out = extractCAs(services);
    expect(out).toHaveLength(1);
    const ca = out[0]!;
    expect(ca.certDer).toBe(der);
    expect(ca.issuerDN).toContain('QKB Test CA');
    expect(ca.issuerDN).toContain('QKB');
    expect(ca.issuerDN).toContain('EE');
    expect(ca.validFrom).toBeGreaterThan(1_700_000_000);
    expect(ca.validTo).toBeGreaterThan(ca.validFrom);
  });

  test('throws on malformed DER', () => {
    const services: RawService[] = [
      {
        serviceTypeIdentifier: SVC_CA_QC,
        status: STATUS_GRANTED,
        statusStartingTime: 1_700_000_000,
        x509CertificateList: [new Uint8Array([0x00, 0x01, 0x02])],
      },
    ];
    expect(() => extractCAs(services)).toThrow();
  });
});
