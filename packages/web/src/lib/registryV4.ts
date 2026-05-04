// Thin re-export façade over @zkqes/sdk's registry module.
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
  type LeafPublicSignalsV4,
  type LeafPublicSignalsV4AgeCapable,
  type RegisterArgsV4,
  type RegisterArgsV4Age,
} from '@zkqes/sdk';
// `leafPublicSignalsV4` is re-exported under the registry-domain name to
// preserve existing call sites; the SDK exports the same function as
// `buildLeafPublicSignalsV4Solidity` to disambiguate from the witness-side
// projection of the same name.
export { buildLeafPublicSignalsV4Solidity as leafPublicSignalsV4 } from '@zkqes/sdk';
