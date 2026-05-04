// @zkqes/circuits — public package exports.
//
// Stable API surface for downstream consumers (web-eng's witness wire-in,
// contracts-eng's calldata builder, the zkqes CLI wrapper). Anything
// imported from a sub-path (e.g. `@zkqes/circuits/src/types`) is internal
// and may shift between commits — pin to the surface this file re-exports.

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
