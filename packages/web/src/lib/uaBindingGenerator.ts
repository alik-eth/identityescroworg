/**
 * UA QKB/2.0 binding generator.
 *
 * Wraps `buildBindingV2` with the committed UA default policy leaf and the
 * pinned UA declaration text, producing a schema-valid QKB/2.0 binding ready
 * for Diia CAdES signing.
 *
 * The `policy.leafHash` here MUST match what the V4 leaf circuit derives from
 * the JCS-canonicalized binding core — anything else produces silent
 * constraint failures downstream. The cross-check lives in the vitest that
 * drives this module.
 */
import uaPolicySeed from '../../../../fixtures/declarations/ua/policy-v1.json';
import ukDeclaration from '../../../../fixtures/declarations/uk.txt?raw';
import {
  BINDING_V2_SCHEMA,
  buildBindingV2,
  buildPolicyLeafV1,
  canonicalizeBindingV2,
  policyLeafHashV1,
  type BindingV2,
} from './bindingV2';

export interface BuildUaBindingV2Input {
  readonly pk: Uint8Array; // SEC1 uncompressed 65 bytes
  readonly timestamp: number; // unix seconds
  readonly nonce: Uint8Array; // 32 bytes
  readonly context?: Uint8Array;
}

export interface UaBindingV2Bundle {
  readonly binding: BindingV2;
  readonly bcanon: Uint8Array;
}

const UA_POLICY_LEAF = buildPolicyLeafV1({
  policyId: uaPolicySeed.policyId,
  policyVersion: uaPolicySeed.policyVersion,
  contentHash: uaPolicySeed.contentHash as `0x${string}`,
  metadataHash: uaPolicySeed.metadataHash as `0x${string}`,
});
const UA_POLICY_LEAF_HASH = policyLeafHashV1(UA_POLICY_LEAF);

export function buildUaBindingV2(input: BuildUaBindingV2Input): UaBindingV2Bundle {
  const binding = buildBindingV2({
    pk: input.pk,
    timestamp: input.timestamp,
    nonce: input.nonce,
    ...(input.context ? { context: input.context } : {}),
    policy: {
      leafHash: UA_POLICY_LEAF_HASH,
      policyId: uaPolicySeed.policyId,
      policyVersion: uaPolicySeed.policyVersion,
      bindingSchema: BINDING_V2_SCHEMA,
    },
    display: {
      lang: 'uk',
      template: 'qkb-default-ua/v1',
      text: ukDeclaration,
    },
  });
  const bcanon = canonicalizeBindingV2(binding);
  return { binding, bcanon };
}

export const UA_POLICY_LEAF_HASH_HEX = UA_POLICY_LEAF_HASH;
