// @qkb/sdk witness/v5 — public API surface for the V5 witness builder.
//
// Cross-read from arch-circuits f0d5a73's @qkb/circuits package (kept
// vendored locally because @qkb/circuits is Node-only — see
// `build-witness-v5.ts` header for the two browser patches).

export {
  buildWitnessV5,
  parseP7s,
  extractBindingOffsets,
  findTbsInCert,
  findSubjectSerial,
  pkCoordToLimbs,
  subjectSerialBytesToLimbs,
  MAX_BCANON,
  MAX_CERT,
  MAX_CTX,
  MAX_CTX_PADDED,
  MAX_LEAF_TBS,
  MAX_POLICY_ID,
  MAX_SA,
} from './build-witness-v5';

export type {
  BuildWitnessV5Input,
  CmsExtraction,
  V2CoreBindingOffsets,
  WitnessV5,
} from './types';

export {
  decomposeTo643Limbs,
  parseP256Spki,
  spkiCommit,
  type ParsedSpki,
} from './spki-commit-ref';
