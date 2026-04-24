import { describe, expect, it } from 'vitest';
import {
  DOB_SOURCE_TAGS,
  dobSourceTagToField,
  normalizeDobToIso,
  normalizeDobToYmd,
  runDobExtractors,
  standardRfc3739DobExtractor,
  uaSubjectDirectoryDobExtractor,
} from '../../src/lib/dob';

describe('normalizeDobToIso', () => {
  it('normalizes YYYYMMDD suffix formats', () => {
    expect(normalizeDobToIso('19990426-02970')).toBe('1999-04-26');
  });

  it('normalizes plain YYYYMMDD values', () => {
    expect(normalizeDobToIso('19990426')).toBe('1999-04-26');
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
  it('returns the first matching extraction result', () => {
    const out = runDobExtractors(
      {
        subjectDirectoryAttributes: [
          { oid: '1.2.804.2.1.1.1.11.1.4.11', value: '19990426-02970' },
        ],
      },
      [standardRfc3739DobExtractor(), uaSubjectDirectoryDobExtractor()],
    );
    expect(out?.profile).toBe('ua-subject-directory-v1');
  });
});
