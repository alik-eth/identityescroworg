/**
 * UA QKB/2.0 binding generator.
 *
 * Produces a schema-valid QKB/2.0 `BindingV2` (core + display) for UI rendering
 * and download, AND the JCS bytes (`bcanon`) that must be signed by Diia and
 * fed into the V4 circuit. Per spec (2026-04-23 QKB binding V2 + policy root),
 * `display` + `extensions` live OUTSIDE the proving surface — the signed bytes
 * are the core-only serialization. Mixing display text into the signed bytes
 * both bloats the payload past the circuit's `MAX_BCANON = 1024` cap AND lets
 * prose drift creep into a circuit-committed surface. Never do it.
 *
 * `policy.leafHash` must equal what the V4 leaf circuit derives from the JCS
 * core bytes; drift there causes silent constraint failures downstream.
 */
import uaPolicySeed from '../../../../fixtures/declarations/ua/policy-v1.json';
import ukDeclaration from '../../../../fixtures/declarations/uk.txt?raw';
import {
  BINDING_V2_SCHEMA,
  buildBindingV2,
  buildPolicyLeafV1,
  canonicalizeBindingCoreV2,
  policyLeafHashV1,
  type BindingV2,
} from './bindingV2';
import { MAX_BCANON } from './witness';
import { QkbError } from './errors';

export interface BuildUaBindingV2Input {
  readonly pk: Uint8Array; // SEC1 uncompressed 65 bytes
  readonly timestamp: number; // unix seconds
  readonly nonce: Uint8Array; // 32 bytes
  readonly context?: Uint8Array;
}

export interface UaBindingV2Bundle {
  /**
   * Full binding object — core + display. Render this in the UI and persist
   * it in session so `/ua/sign` can show the user what they're about to sign.
   * NEVER hash this, NEVER put it into `bcanonV2B64`, NEVER sign it.
   */
  readonly binding: BindingV2;
  /**
   * JCS-canonical core-only bytes. This is what Diia signs and what the
   * circuit consumes. Stable across display-text changes; always ≤ 1024 B.
   */
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
  const bcanon = canonicalizeBindingCoreV2(binding);
  if (bcanon.byteLength > MAX_BCANON) {
    throw new QkbError('binding.jcs', {
      reason: 'bcanon-exceeds-max',
      got: bcanon.byteLength,
      max: MAX_BCANON,
    });
  }
  return { binding, bcanon };
}

export const UA_POLICY_LEAF_HASH_HEX = UA_POLICY_LEAF_HASH;
