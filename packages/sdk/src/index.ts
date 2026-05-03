// Curated public API for @qkb/sdk.
//
// Modules are extracted incrementally from packages/web/src/lib. Each
// extraction lands as its own commit and exposes its surface here.

export {
  ALL_ERROR_CODES,
  BundleError,
  QkbError,
  localizeError,
  type ErrorCode,
  type I18nLike,
} from './errors/index.js';

export {
  BINDING_V2_SCHEMA,
  BINDING_V2_SCHEME,
  BINDING_V2_VERSION,
  BN254_SCALAR_FIELD,
  NONCE_LENGTH,
  PK_UNCOMPRESSED_LENGTH,
  POLICY_ID_RE,
  POLICY_LEAF_V1_SCHEMA,
  bindingCoreHashV2,
  bindingCoreV2,
  bindingHashV2,
  buildBindingV2,
  buildPolicyLeafV1,
  canonicalizeBindingCoreV2,
  canonicalizeBindingV2,
  canonicalizePolicyLeafV1,
  policyLeafDigestV1,
  policyLeafFieldV1,
  policyLeafHashV1,
  type BindingCoreV2,
  type BindingV2,
  type BindingV2Assertions,
  type BindingV2Display,
  type BindingV2PolicyRef,
  type BuildBindingV2Input,
  type BuildPolicyLeafV1Input,
  type PolicyLeafV1,
} from './binding/index.js';

export {
  buildPolicyInclusionProof,
  buildPolicyTreeFromLeaves,
  recomputePolicyRoot,
  zeroHashes,
  type PolicyBuiltTree,
  type PolicyInclusionProof,
} from './policy/index.js';

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
} from './dob/index.js';

export {
  ALGORITHM_TAG_ECDSA,
  ALGORITHM_TAG_RSA,
  detectAlgorithmTag,
  parseCades,
  type AlgorithmTag,
  type LeafAlg,
  type ParsedCades,
} from './cert/cades.js';

export {
  loadArtifacts,
  pickVariantUrls,
  validateUrlsJson,
  variantForAlgorithmTag,
  type ArtifactCache,
  type CircuitVariant,
  type DualUrlsJson,
  type Fetcher,
  type LoadOptions,
  type LoadedArtifacts,
  type UrlsJson,
} from './artifacts/index.js';

export {
  ALGORITHM_TAG_ECDSA_STR,
  ALGORITHM_TAG_RSA_STR,
  MAX_BCANON,
  MAX_CERT,
  MAX_CTX,
  MAX_DECL,
  MAX_SA,
  MERKLE_DEPTH,
  bytes32ToLimbs643,
  digestToField,
  extractSubjectSerial,
  findJcsKeyValueOffset,
  packProof,
  pkCoordToLimbs,
  sha256Pad,
  subjectSerialToLimbs,
  zeroPadTo,
  type ChainInputs,
  type ChainWitnessInput,
  type ExtractedSubjectSerial,
  type Groth16Proof,
  type LeafWitnessInput,
  type Phase2SharedInputs,
  type Phase2Witness,
  type SolidityProof,
} from './core/index.js';

export {
  buildPhase2WitnessV4Draft,
  leafPublicSignalsV4,
  parseLeafPublicSignals,
  type BuildPhase2WitnessV4DraftInput,
  type LeafPublicSignals,
  type LeafPublicSignalsV4,
  type LeafWitnessInputV4,
  type Phase2SharedInputsV4,
  type Phase2WitnessV4,
} from './witness/index.js';

export {
  buildLeafWitness,
  buildPhase2Witness,
  computeLeafSpkiCommit,
  computeNullifier,
  type BuildPhase2WitnessInput,
  type BuildWitnessInput,
} from './witness/builder.js';

export {
  encodeRegisterFromSignals,
  encodeRegisterFromSignalsAge,
  prepareWitnessV4,
  type EncodeRegisterFromSignalsAgeInput,
  type EncodeRegisterFromSignalsInput,
  type EncodedRegister,
  type EncodedRegisterAge,
  type PrepareWitnessV4Input,
} from './facade/index.js';

export {
  BINDING_FIELD_ORDER,
  BINDING_SCHEME,
  BINDING_VERSION,
  DECLARATIONS,
  NONCE_LENGTH_V1,
  PK_UNCOMPRESSED_LENGTH_V1,
  bindingHash,
  buildBinding,
  buildTBS,
  canonicalizeBinding,
  declarationDigestHex,
  type Binding,
  type BuildBindingInput,
  type Locale,
} from './binding/v1.js';

export {
  REGISTRY_V4_ERROR_SELECTORS,
  agePublicSignalsV4,
  ageInputsV4FromPublicSignals,
  classifyV4RegistryRevert,
  classifyV4WalletRevert,
  assertAgeInputsV4Shape,
  assertLeafInputsV4AgeShape,
  assertLeafInputsV4Shape,
  assertRegisterArgsV4AgeShape,
  assertRegisterArgsV4Shape,
  buildRegisterArgsV4AgeFromSignals,
  buildRegisterArgsV4FromSignals,
  encodeLeafProofCalldata,
  encodeV4RegisterCalldata,
  leafInputsV4AgeFromPublicSignals,
  leafInputsV4FromPublicSignals,
  leafPublicSignalsV4 as buildLeafPublicSignalsV4Solidity,
  leafPublicSignalsV4Age,
  type AgeInputsV4,
  type AgePublicSignalFieldsV4,
  type AgePublicSignalsV4,
  type G16Proof,
  type LeafCalldata,
  type LeafDobInputs,
  type LeafInputsV4,
  type LeafInputsV4AgeCapable,
  type LeafPublicSignalFieldsV4,
  type LeafPublicSignalFieldsV4AgeCapable,
  type LeafPublicSignalsV4 as RegistryLeafPublicSignalsV4,
  type LeafPublicSignalsV4AgeCapable,
  type RegisterArgsV4,
  type RegisterArgsV4Age,
} from './registry/index.js';

export {
  MockProver,
  proveSplit,
  proveV5,
  type AlgorithmArtifactUrls,
  type CircuitArtifactUrls,
  type IProver,
  type MockProverOptions,
  type ProofProgress,
  type ProofSide,
  type ProofStage,
  type ProveOptions,
  type ProveResult,
  type ProveV5Options,
  type ProveV5Result,
  type SplitProgress,
  type SplitProveOptions,
  type SplitProveResult,
} from './prover/index.js';

export {
  SUPPORTED_COUNTRIES,
  getCountryConfig,
  type CeremonyUrlManifest,
  type CountryCeremonyPins,
  type CountryConfig,
  type SupportedCountry,
} from './country/index.js';

// M4: viem read helpers + deployments fixture + freshly-built ABIs.
export { isVerified, nullifierOf, trustedListRoot } from './registry/index.js';

export {
  QKB_DEPLOYMENTS,
  deploymentForChainId,
  type QkbDeployment,
  type QkbNetwork,
} from './deployments.js';

export { qkbRegistryV4Abi } from './abi/QKBRegistryV4.js';
export { qkbRegistryV5_1Abi } from './abi/QKBRegistryV5_1.js';
export { identityEscrowNftAbi } from './abi/IdentityEscrowNFT.js';

export {
  PUBLIC_SIGNALS_V5_LENGTH,
  REGISTRY_V5_ERROR_SELECTORS,
  assertRegisterArgsV5Shape,
  classifyV5RegistryRevert,
  encodeV5RegisterCalldata,
  encodeV5RotateWalletCalldata,
  publicSignalsFromArray,
  publicSignalsToArray,
  type Groth16ProofV5,
  type PublicSignalsV5,
  type RegisterArgsV5,
  type RotateWalletArgsV5,
} from './registry/registryV5.js';

export {
  PUBLIC_SIGNALS_V5_2_LENGTH,
  assertRegisterArgsV5_2Shape,
  encodeV5_2RegisterCalldata,
  encodeV5_2RotateWalletCalldata,
  publicSignalsV5_2FromArray,
  publicSignalsV5_2ToArray,
  type Groth16ProofV5_2,
  type PublicSignalsV5_2,
  type RegisterArgsV5_2,
  type RotateWalletArgsV5_2,
} from './registry/registryV5_2.js';

export {
  bytes32ToHiLo,
  hiLoToBytes32,
} from './core/bytes32ToHiLo.js';

// V5 witness builder — vendored from arch-circuits f0d5a73 with browser
// patches (see `./witness/v5/build-witness-v5.ts` header). The lower-level
// helpers (MAX_BCANON, pkCoordToLimbs etc.) live under `./core` already and
// are re-exported above; we only surface V5-specific symbols here.
export {
  buildWitnessV5,
  buildWitnessV5_2,
  computeIdentityFingerprint,
  parseP7s,
  extractBindingOffsets,
  findTbsInCert,
  findSubjectSerial,
  subjectSerialBytesToLimbs,
  decomposeTo643Limbs,
  parseP256Spki,
  spkiCommit,
  decodeEcdsaSigSequence,
  bytes32ToHex,
  MAX_CTX_PADDED,
  MAX_LEAF_TBS,
  MAX_POLICY_ID,
  type BuildWitnessV5Input,
  type BuildWitnessV5_2Input,
  type CmsExtraction,
  type V2CoreBindingOffsets,
  type WitnessV5,
  type WitnessV5_2,
  type ParsedSpki,
  type EcdsaRS,
} from './witness/v5.js';
