import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  DOB_SOURCE_TAGS,
  dobSourceTagToField,
  extractDobFromDiiaUA,
  normalizeDobToIso,
  normalizeDobToYmd,
  runDobExtractors,
  standardRfc3739DobExtractor,
  uaSubjectDirectoryDobExtractor,
} from '../../src/lib/dob';

// Real Diia admin leaf cert DER, base64.
// Source: packages/circuits/fixtures/dob/ua/diia-admin.der.txt
// sha256 = 42e7ddae42ed5c102ccab25dd95a5411d5eaa5c2752bfab84cf5b5a0fd07c806
const DIIA_ADMIN_DER_B64 =
  'MIIFCDCCBK+gAwIBAgIUZmkkPSsEMx0EAAAAFOuZAPdBtAQwCgYIKoZIzj0EAwIwgdgxIDAeBgNVBAoMF1N0YXRlIGVudGVycHJpc2UgIkRJSUEiMTAwLgYDVQQLDCdEZXBhcnRtZW50IG9mIEVsZWN0cm9uaWMgVHJ1c3QgU2VydmljZXMxMjAwBgNVBAMMKSJESUlBIi4gUXVhbGlmaWVkIFRydXN0IFNlcnZpY2VzIFByb3ZpZGVyMRkwFwYDVQQFExBVQS00MzM5NTAzMy0yMzExMQswCQYDVQQGEwJVQTENMAsGA1UEBwwES3lpdjEXMBUGA1UEYQwOTlRSVUEtNDMzOTUwMzMwHhcNMjUxMDE4MTExNjQwWhcNMjYxMDE4MTExNjM5WjBwMR0wGwYDVQQDDBRWb3Zrb3RydWIgT2xla3NhbmRyIDESMBAGA1UEBAwJVm92a290cnViMRMwEQYDVQQqDApPbGVrc2FuZHIgMRkwFwYDVQQFExBUSU5VQS0zNjI3NTA2NTc1MQswCQYDVQQGEwJVQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIPbFi+dM5SCwtT2OM6QlYG9lyYmWDcY08flIxzOeMGlJRRJ1TRUjMjJPUKUwouupA14ifE4TUd/2wwBHBh2YxmjggK8MIICuDAdBgNVHQ4EFgQUZwifI7BTmPBaUkq/k2BP+CHMmDEwHwYDVR0jBBgwFoAUZmkkPSsEMx0ekqtvP0rbSCMbP8QwDgYDVR0PAQH/BAQDAgZAMEYGA1UdIAQ/MD0wOwYJKoYkAgEBAQIEMC4wLAYIKwYBBQUHAgEWIGh0dHBzOi8vY2EuZGlpYS5nb3YudWEvcmVnbGFtZW50MAkGA1UdEwQCMAAwVAYIKwYBBQUHAQMESDBGMAgGBgQAjkYBATATBgYEAI5GAQYwCQYHBACORgEGATAOBgYEAI5GAQcwBBMCVUEwFQYIKwYBBQUHCwIwCQYHBACL7EkBATAeBgNVHREEFzAVoBMGCisGAQQBgjcUAgOgBQwDMjI0ME4GA1UdHwRHMEUwQ6BBoD+GPWh0dHA6Ly9jYS5kaWlhLmdvdi51YS9kb3dubG9hZC9jcmxzL0NBLTY2NjkyNDNELUZ1bGwtUzMxNi5jcmwwTwYDVR0uBEgwRjBEoEKgQIY+aHR0cDovL2NhLmRpaWEuZ292LnVhL2Rvd25sb2FkL2NybHMvQ0EtNjY2OTI0M0QtRGVsdGEtUzMxNi5jcmwwgYcGCCsGAQUFBwEBBHsweTAwBggrBgEFBQcwAYYkaHR0cDovL2NhLmRpaWEuZ292LnVhL3NlcnZpY2VzL29jc3AvMEUGCCsGAQUFBzAChjlodHRwOi8vY2EuZGlpYS5nb3YudWEvdXBsb2Fkcy9jZXJ0aWZpY2F0ZXMvZGlpYV9lY2RzYS5wN2IwRQYIKwYBBQUHAQsEOTA3MDUGCCsGAQUFBzADhilodHRwOi8vY2EuZGlpYS5nb3YudWEvc2VydmljZXMvdHNwL2VjZHNhLzArBgNVHQkEJDAiMCAGDCqGJAIBAQELAQQLATEQEw4xOTk5MDQyNi0wMjk3MDAKBggqhkjOPQQDAgNHADBEAiBMj910i+UGkHEqbNELPeWpaTca3iDfAp8JqcFf9AHMegIgYs+Fopo/CVeiDJZO1zRXlvlTvX3fcIGuIoOXL5oRLfo=';

describe('normalizeDobToIso', () => {
  it('normalizes YYYYMMDD suffix formats', () => {
    expect(normalizeDobToIso('19990426-02970')).toBe('1999-04-26');
  });

  it('normalizes plain YYYYMMDD values', () => {
    expect(normalizeDobToIso('19990426')).toBe('1999-04-26');
  });

  it('rejects impossible calendar dates (Feb 31)', () => {
    expect(() => normalizeDobToIso('19990231')).toThrowError(/calendar/);
  });

  it('rejects Feb 29 on a non-leap year', () => {
    expect(() => normalizeDobToIso('19990229')).toThrowError(/calendar/);
  });

  it('accepts Feb 29 on a leap year', () => {
    expect(normalizeDobToIso('20000229')).toBe('2000-02-29');
  });

  it('rejects Feb 29 on a centenary non-leap year (1900)', () => {
    expect(() => normalizeDobToIso('19000229')).toThrowError(/calendar/);
  });

  it('rejects April 31', () => {
    expect(() => normalizeDobToIso('19990431')).toThrowError(/calendar/);
  });
});

describe('normalizeDobToYmd', () => {
  it('produces YYYYMMDD as an integer', () => {
    expect(normalizeDobToYmd('19990426-02970')).toBe(19990426);
  });
});

describe('dobSourceTagToField', () => {
  it('maps known source tags to stable field elements', () => {
    expect(dobSourceTagToField('ua_subject_directory_v1')).toBe(DOB_SOURCE_TAGS.ua_subject_directory_v1);
  });
});

describe('standardRfc3739DobExtractor', () => {
  it('extracts DOB from the standard dateOfBirth OID', () => {
    const extractor = standardRfc3739DobExtractor();
    const out = extractor.extract({
      subjectAttributes: [
        { oid: '1.3.6.1.5.5.7.9.1', value: '19990426' },
      ],
    });
    expect(out?.dob).toBe('1999-04-26');
    expect(out?.dobYmd).toBe(19990426);
    expect(out?.sourceTag).toBe('standard_rfc3739_date_of_birth');
  });
});

describe('uaSubjectDirectoryDobExtractor', () => {
  it('extracts DOB from the observed UA subjectDirectoryAttributes OID', () => {
    const extractor = uaSubjectDirectoryDobExtractor();
    const out = extractor.extract({
      subjectDirectoryAttributes: [
        { oid: '1.2.804.2.1.1.1.11.1.4.11', value: '19990426-02970' },
      ],
    });
    expect(out?.dob).toBe('1999-04-26');
    expect(out?.dobYmd).toBe(19990426);
    expect(out?.sourceTag).toBe('ua_subject_directory_v1');
    expect(out?.evidence).toBe('subjectDirectoryAttributes');
  });
});

describe('runDobExtractors', () => {
  it('returns the first matching extraction result when the issuer is UA-anchored', () => {
    const out = runDobExtractors(
      {
        country: 'UA',
        subjectDirectoryAttributes: [
          { oid: '1.2.804.2.1.1.1.11.1.4.11', value: '19990426-02970' },
        ],
      },
      [standardRfc3739DobExtractor(), uaSubjectDirectoryDobExtractor()],
    );
    expect(out?.profile).toBe('ua-subject-directory-v1');
  });

  it('refuses to classify a cert as national-UA when the OID appears without a UA issuer', () => {
    const out = runDobExtractors(
      {
        issuerDN: 'CN=Some Non-UA CA, C=US',
        subjectDirectoryAttributes: [
          { oid: '1.2.804.2.1.1.1.11.1.4.11', value: '19990426-02970' },
        ],
      },
      [uaSubjectDirectoryDobExtractor()],
    );
    expect(out).toBeNull();
  });

  it('accepts a UA cert via issuer DN C=UA even without the country helper field', () => {
    const out = runDobExtractors(
      {
        issuerDN: 'CN=DIIA QTSP, O=State enterprise DIIA, C=UA',
        subjectDirectoryAttributes: [
          { oid: '1.2.804.2.1.1.1.11.1.4.11', value: '19990426-02970' },
        ],
      },
      [uaSubjectDirectoryDobExtractor()],
    );
    expect(out?.profile).toBe('ua-subject-directory-v1');
  });
});

describe('extractDobFromDiiaUA', () => {
  it('fixture sha256 matches the circuits pin', () => {
    const b64 = DIIA_ADMIN_DER_B64;
    const der = Buffer.from(b64, 'base64');
    const sha = createHash('sha256')
      .update(`${b64}\n`)
      .digest('hex');
    expect(sha).toBe(
      '42e7ddae42ed5c102ccab25dd95a5411d5eaa5c2752bfab84cf5b5a0fd07c806',
    );
    expect(der.byteLength).toBeGreaterThan(1000);
  });

  it('parses real Diia fixture YMD + source tag', () => {
    const der = Uint8Array.from(Buffer.from(DIIA_ADMIN_DER_B64, 'base64'));
    const result = extractDobFromDiiaUA(der);
    expect(result.supported).toBe(true);
    expect(result.sourceTag).toBe(1);
    expect(result.ymd).toBe(19990426);
  });

  it('returns supported=false for random bytes with no OID 2.5.29.9', () => {
    const der = new Uint8Array(200).fill(0x42);
    const result = extractDobFromDiiaUA(der);
    expect(result.supported).toBe(false);
    expect(result.ymd).toBe(0);
    expect(result.sourceTag).toBe(0);
  });

  it('returns supported=false when inner UA attr OID is absent', () => {
    const der = new Uint8Array(120);
    der.set([0x06, 0x03, 0x55, 0x1d, 0x09], 20);
    const result = extractDobFromDiiaUA(der);
    expect(result.supported).toBe(false);
    expect(result.ymd).toBe(0);
    expect(result.sourceTag).toBe(0);
  });

  it('returns supported=false when value tag is not PrintableString', () => {
    const inner = [0x06, 0x0c, 0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x0b, 0x01, 0x04, 0x0b, 0x01];
    const der = new Uint8Array([
      0x06, 0x03, 0x55, 0x1d, 0x09,
      ...inner,
      0x18, 0x0e,
      0x31, 0x39, 0x39, 0x39, 0x30, 0x34, 0x32, 0x36,
      0x2d, 0x30, 0x32, 0x39, 0x37, 0x30,
    ]);
    const result = extractDobFromDiiaUA(der);
    expect(result.supported).toBe(false);
    expect(result.ymd).toBe(0);
    expect(result.sourceTag).toBe(0);
  });
});
