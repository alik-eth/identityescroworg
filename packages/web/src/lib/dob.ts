/**
 * Draft DOB extraction interfaces for future age-capable QKB profiles.
 *
 * These types intentionally do not parse ASN.1 themselves. They define the
 * module boundary between certificate/profile decoders and the rest of the
 * witness / policy pipeline.
 */
import { QkbError } from './errors';

export type DobEvidence =
  | 'subject'
  | 'subjectDirectoryAttributes'
  | 'san'
  | 'qcStatements'
  | 'other';

export type DobTrustLevel = 'standard' | 'national' | 'provider';

export type DobSourceTag =
  | 'standard_rfc3739_date_of_birth'
  | 'ua_subject_directory_v1'
  | 'provider_custom'
  | 'unknown';

export interface DobAttributeValue {
  readonly oid: string;
  readonly value: string;
}

export interface CertificateDobView {
  readonly issuerDN?: string;
  readonly subjectDN?: string;
  readonly country?: string;
  readonly subjectAttributes?: readonly DobAttributeValue[];
  readonly subjectDirectoryAttributes?: readonly DobAttributeValue[];
  readonly sanOtherNames?: readonly DobAttributeValue[];
  readonly qcStatements?: readonly DobAttributeValue[];
  readonly extensionOids?: readonly string[];
}

export interface DobExtraction {
  readonly dob: `${number}-${number}-${number}`;
  readonly dobYmd: number;
  readonly rawValue: string;
  readonly sourceOid: string;
  readonly sourceTag: DobSourceTag;
  readonly profile: string;
  readonly trustLevel: DobTrustLevel;
  readonly evidence: DobEvidence;
}

export interface DobExtractor {
  readonly id: string;
  readonly sourceTag: DobSourceTag;
  readonly trustLevel: DobTrustLevel;
  supports(input: CertificateDobView): boolean;
  extract(input: CertificateDobView): DobExtraction | null;
}

export const DOB_SOURCE_TAGS: Record<DobSourceTag, bigint> = {
  standard_rfc3739_date_of_birth: 1n,
  ua_subject_directory_v1: 1001n,
  provider_custom: 2001n,
  unknown: 65535n,
};

export function dobSourceTagToField(tag: DobSourceTag): bigint {
  return DOB_SOURCE_TAGS[tag];
}

export function normalizeDobToIso(raw: string): `${number}-${number}-${number}` {
  const compact = extractDobDigits(raw);
  const year = compact.slice(0, 4);
  const month = compact.slice(4, 6);
  const day = compact.slice(6, 8);
  validateDobParts(year, month, day, raw);
  return `${year}-${month}-${day}` as `${number}-${number}-${number}`;
}

export function normalizeDobToYmd(raw: string): number {
  const iso = normalizeDobToIso(raw);
  return Number(iso.replaceAll('-', ''));
}

export function runDobExtractors(
  input: CertificateDobView,
  extractors: readonly DobExtractor[],
): DobExtraction | null {
  for (const extractor of extractors) {
    if (!extractor.supports(input)) continue;
    const out = extractor.extract(input);
    if (out !== null) return out;
  }
  return null;
}

export function standardRfc3739DobExtractor(): DobExtractor {
  return {
    id: 'standard-rfc3739',
    sourceTag: 'standard_rfc3739_date_of_birth',
    trustLevel: 'standard',
    supports(input) {
      return hasOid(input.subjectAttributes, '1.3.6.1.5.5.7.9.1');
    },
    extract(input) {
      const attr = findByOid(input.subjectAttributes, '1.3.6.1.5.5.7.9.1');
      if (!attr) return null;
      const dob = normalizeDobToIso(attr.value);
      return {
        dob,
        dobYmd: normalizeDobToYmd(attr.value),
        rawValue: attr.value,
        sourceOid: attr.oid,
        sourceTag: 'standard_rfc3739_date_of_birth',
        profile: 'standard-rfc3739',
        trustLevel: 'standard',
        evidence: 'subject',
      };
    },
  };
}

export function uaSubjectDirectoryDobExtractor(): DobExtractor {
  return {
    id: 'ua-subject-directory-v1',
    sourceTag: 'ua_subject_directory_v1',
    trustLevel: 'national',
    supports(input) {
      return hasOid(input.subjectDirectoryAttributes, '1.2.804.2.1.1.1.11.1.4.11');
    },
    extract(input) {
      const attr = findByOid(input.subjectDirectoryAttributes, '1.2.804.2.1.1.1.11.1.4.11');
      if (!attr) return null;
      const dob = normalizeDobToIso(attr.value);
      return {
        dob,
        dobYmd: normalizeDobToYmd(attr.value),
        rawValue: attr.value,
        sourceOid: attr.oid,
        sourceTag: 'ua_subject_directory_v1',
        profile: 'ua-subject-directory-v1',
        trustLevel: 'national',
        evidence: 'subjectDirectoryAttributes',
      };
    },
  };
}

function hasOid(values: readonly DobAttributeValue[] | undefined, oid: string): boolean {
  return values?.some((value) => value.oid === oid) ?? false;
}

function findByOid(
  values: readonly DobAttributeValue[] | undefined,
  oid: string,
): DobAttributeValue | undefined {
  return values?.find((value) => value.oid === oid);
}

function extractDobDigits(raw: string): string {
  const match = raw.match(/^(\d{8})(?:[^\d].*)?$/);
  if (!match) {
    throw new QkbError('binding.field', { field: 'dob', reason: 'bad-format', raw });
  }
  return match[1]!;
}

function validateDobParts(year: string, month: string, day: string, raw: string): void {
  const y = Number(year);
  const m = Number(month);
  const d = Number(day);
  if (!Number.isInteger(y) || y < 1900 || y > 2999) {
    throw new QkbError('binding.field', { field: 'dob.year', reason: 'range', raw });
  }
  if (!Number.isInteger(m) || m < 1 || m > 12) {
    throw new QkbError('binding.field', { field: 'dob.month', reason: 'range', raw });
  }
  if (!Number.isInteger(d) || d < 1 || d > 31) {
    throw new QkbError('binding.field', { field: 'dob.day', reason: 'range', raw });
  }
}
