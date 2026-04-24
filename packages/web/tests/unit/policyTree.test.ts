import { describe, expect, it } from 'vitest';
import { buildPolicyLeafV1, policyLeafFieldV1, policyLeafHashV1 } from '../../src/lib/bindingV2';
import {
  buildPolicyInclusionProof,
  buildPolicyTreeFromLeaves,
  recomputePolicyRoot,
} from '../../src/lib/policyTree';

describe('policyTree', () => {
  it('policyLeafHashV1 is the hex32 encoding of the field leaf used in the tree', () => {
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 1,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });
    expect(policyLeafHashV1(leaf)).toBe(toHex32(policyLeafFieldV1(leaf)));
  });

  it('builds a deterministic Poseidon policy root', async () => {
    const leaves = sampleLeaves();
    const a = await buildPolicyTreeFromLeaves(leaves, 3);
    const b = await buildPolicyTreeFromLeaves(leaves, 3);
    expect(a.rootHex).toBe(b.rootHex);
    expect(a.leafHex).toEqual(b.leafHex);
  });

  it('inclusion proof recomputes the same root', async () => {
    const tree = await buildPolicyTreeFromLeaves(sampleLeaves(), 3);
    const proof = await buildPolicyInclusionProof(tree, 1);
    const root = await recomputePolicyRoot(proof.leaf, proof);
    expect(toHex32(root)).toBe(tree.rootHex);
  });

  it('changing a leaf changes the root', async () => {
    const a = await buildPolicyTreeFromLeaves(sampleLeaves(), 3);
    const b = await buildPolicyTreeFromLeaves(
      [
        buildPolicyLeafV1({
          policyId: 'qkb-default',
          policyVersion: 1,
          contentHash: hex32('11'),
          metadataHash: hex32('22'),
        }),
        buildPolicyLeafV1({
          policyId: 'qkb-default',
          policyVersion: 3,
          contentHash: hex32('33'),
          metadataHash: hex32('44'),
        }),
      ],
      3,
    );
    expect(a.rootHex).not.toBe(b.rootHex);
  });
});

function sampleLeaves() {
  return [
    buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 1,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    }),
    buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('33'),
      metadataHash: hex32('44'),
      jurisdiction: 'multi',
    }),
  ];
}

function hex32(byte: string): `0x${string}` {
  return (`0x${byte.repeat(32)}`) as `0x${string}`;
}

function toHex32(v: bigint): `0x${string}` {
  return `0x${v.toString(16).padStart(64, '0')}` as `0x${string}`;
}
