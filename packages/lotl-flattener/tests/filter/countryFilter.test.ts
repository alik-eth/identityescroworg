import { describe, expect, it } from 'vitest';
import { filterServicesByCountry } from '../../src/filter/countryFilter.js';

describe('filterServicesByCountry', () => {
  const svcs = [
    { territory: 'EE', x509CertificateList: [new Uint8Array([1])] },
    { territory: 'DE', x509CertificateList: [new Uint8Array([2])] },
    { territory: 'ee', x509CertificateList: [new Uint8Array([3])] },
  ];

  it('returns only matching ISO country code (case-insensitive)', () => {
    const filtered = filterServicesByCountry(svcs as never, 'EE');
    expect(filtered).toHaveLength(2);
  });

  it('normalizes the needle case-insensitively', () => {
    const filtered = filterServicesByCountry(svcs as never, 'ee');
    expect(filtered).toHaveLength(2);
  });

  it('rejects unknown country string', () => {
    expect(() => filterServicesByCountry(svcs as never, 'XX')).toThrowError(
      /no trusted services/,
    );
  });
});
