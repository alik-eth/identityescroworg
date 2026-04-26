// Thin re-export façade over @qkb/sdk's dob module. Keeps `./dob` a stable
// import path for routes + helpers that fan out across the codebase.
export {
  DOB_SOURCE_TAGS,
  assertGregorianDate,
  dobSourceTagToField,
  extractDobFromDiiaUA,
  normalizeDobToIso,
  normalizeDobToYmd,
  runDobExtractors,
  standardRfc3739DobExtractor,
  uaSubjectDirectoryDobExtractor,
  type CertificateDobView,
  type DiiaDobExtraction,
  type DobAttributeValue,
  type DobEvidence,
  type DobExtraction,
  type DobExtractor,
  type DobSourceTag,
  type DobTrustLevel,
} from '@qkb/sdk';
