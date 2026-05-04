// Thin re-export façade over @zkqes/sdk's binding module. Web has long
// imported QKB/2.0 schema helpers from `./bindingV2`; routing those imports
// through the SDK keeps the consumer surface stable while collapsing the
// duplicate implementation into one source of truth.
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
} from '@zkqes/sdk';
