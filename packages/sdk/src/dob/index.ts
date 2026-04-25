/**
 * Draft DOB extraction interfaces for future age-capable QKB profiles.
 *
 * These types intentionally do not parse ASN.1 themselves. They define the
 * module boundary between certificate/profile decoders and the rest of the
 * witness / policy pipeline.
 */
import { QkbError } from '../errors/index.js';

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
    // OID presence alone is NOT a trust anchor — the attribute OID
    // 1.2.804.2.1.1.1.11.1.4.11 can appear in any cert. Match both the
    // OID and a UA-country issuer marker so this extractor's
    // `trustLevel: 'national'` label is only applied to certs chained
    // through a Ukrainian trust anchor. Downstream of this the on-chain
    // verifier still gates the leaf via intermediate Merkle inclusion
    // under the UA `trustedListRoot`, but labeling arbitrary certs
    // 'national' here overstates trust in an inferred field.
    supports(input) {
      if (!hasOid(input.subjectDirectoryAttributes, '1.2.804.2.1.1.1.11.1.4.11')) {
        return false;
      }
      if (input.country === 'UA') return true;
      const issuer = input.issuerDN ?? '';
      return /(^|,|\s)C\s*=\s*UA(\s|,|$)/i.test(issuer);
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

export interface DiiaDobExtraction {
  readonly supported: boolean;
  readonly ymd: number;
  readonly sourceTag: number;
}

// Outer extension OID 2.5.29.9 (SubjectDirectoryAttributes) header: 06 03 55 1D 09.
const DIIA_OUTER_OID_2_5_29_9 = new Uint8Array([0x06, 0x03, 0x55, 0x1d, 0x09]);
// Inner UA attribute OID 1.2.804.2.1.1.1.11.1.4.11.1 — 14-byte header: 06 0C 2A 86 24 02 01 01 01 0B 01 04 0B 01.
const DIIA_INNER_UA_ATTR_OID = new Uint8Array([
  0x06, 0x0c, 0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x0b, 0x01, 0x04, 0x0b, 0x01,
]);
const PRINTABLE_STRING_TAG = 0x13;
const DIIA_DOB_SOURCE_TAG = 1;
const DIIA_DOB_NEG: DiiaDobExtraction = { supported: false, ymd: 0, sourceTag: 0 };

// Byte-exact mirror of DobExtractorDiiaUA.circom (M2.3b). The value is encoded
// as ASN.1 PrintableString (tag 0x13), NOT GeneralizedTime — Diia's observed
// content is "YYYYMMDD-NNNNN" (e.g. "19990426-02970"); first 8 ASCII digits
// are YYYYMMDD. Until M2.3b lands the circuit emits dobYmd=0; this TS is the
// canonical spec the circuit must reproduce.
export function extractDobFromDiiaUA(der: Uint8Array): DiiaDobExtraction {
  const outer = findSubsequence(der, DIIA_OUTER_OID_2_5_29_9, 0);
  if (outer < 0) return DIIA_DOB_NEG;
  const afterOuter = outer + DIIA_OUTER_OID_2_5_29_9.length;

  const inner = findSubsequence(der, DIIA_INNER_UA_ATTR_OID, afterOuter);
  if (inner < 0) return DIIA_DOB_NEG;
  const afterInner = inner + DIIA_INNER_UA_ATTR_OID.length;

  const tagIdx = findByte(der, PRINTABLE_STRING_TAG, afterInner);
  if (tagIdx < 0 || tagIdx + 1 >= der.length) return DIIA_DOB_NEG;

  const lenByte = der[tagIdx + 1]!;
  if (lenByte < 8) return DIIA_DOB_NEG;

  const startOfDigits = tagIdx + 2;
  if (startOfDigits + 8 > der.length) return DIIA_DOB_NEG;

  const digits = der.subarray(startOfDigits, startOfDigits + 8);
  for (const d of digits) {
    if (d < 0x30 || d > 0x39) return DIIA_DOB_NEG;
  }
  const ymd = Number(new TextDecoder().decode(digits));
  return { supported: true, ymd, sourceTag: DIIA_DOB_SOURCE_TAG };
}

function findSubsequence(haystack: Uint8Array, needle: Uint8Array, from: number): number {
  outer: for (let i = from; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function findByte(haystack: Uint8Array, byte: number, from: number): number {
  for (let i = from; i < haystack.length; i++) {
    if (haystack[i] === byte) return i;
  }
  return -1;
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

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  if (month === 4 || month === 6 || month === 9 || month === 11) return 30;
  return 31;
}

/** Throws QkbError('binding.field') if (y,m,d) is not a real Gregorian date.
 *  Rejects impossible days like 19990231 that a simple 1..31 check accepts. */
export function assertGregorianDate(
  year: number,
  month: number,
  day: number,
  raw: string,
  field: string,
): void {
  if (!Number.isInteger(year) || year < 1900 || year > 2999) {
    throw new QkbError('binding.field', { field: `${field}.year`, reason: 'range', raw });
  }
  if (!Number.isInteger(month) || month < 1 || month > 12) {
    throw new QkbError('binding.field', { field: `${field}.month`, reason: 'range', raw });
  }
  if (!Number.isInteger(day) || day < 1 || day > daysInMonth(year, month)) {
    throw new QkbError('binding.field', { field: `${field}.day`, reason: 'calendar', raw });
  }
}

function validateDobParts(year: string, month: string, day: string, raw: string): void {
  assertGregorianDate(Number(year), Number(month), Number(day), raw, 'dob');
}
