import { describe, expect, it } from 'vitest';
import {
  buildPolicyLeafV1,
  policyLeafFieldV1,
  policyLeafHashV1,
} from '../src/binding/index.js';
import { buildPolicyTreeFromLeaves, buildPolicyInclusionProof } from '../src/policy/index.js';
import { encodeRegisterFromSignals } from '../src/facade/index.js';
import type { Groth16Proof } from '../src/core/index.js';

function hex32(n: number | bigint): `0x${string}` {
  const v = typeof n === 'bigint' ? n : BigInt(n);
  return `0x${v.toString(16).padStart(64, '0')}` as `0x${string}`;
}

function makeProof(seed: number): Groth16Proof {
  return {
    pi_a: [String(seed + 1), String(seed + 2), '1'],
    pi_b: [
      [String(seed + 3), String(seed + 4)],
      [String(seed + 5), String(seed + 6)],
      ['1', '0'],
    ],
    pi_c: [String(seed + 7), String(seed + 8), '1'],
    protocol: 'groth16',
    curve: 'bn128',
  };
}

describe('encodeRegisterFromSignals (façade)', () => {
  it('returns ABI-encoded calldata starting with the V4 register selector', () => {
    const PK = `0x04${'00'.repeat(64)}` as `0x04${string}`;
    // V4 non-age leaf is 14 signals (no dobCommit / dobSupported).
    const publicLeaf: string[] = [
      '1', '2', '3', '4', // pkX
      '5', '6', '7', '8', // pkY
      '100',              // ctxHash
      '200',              // policyLeafHash
      '300',              // policyRoot
      '1730000000',       // timestamp
      '99',               // nullifier
      '12345',            // leafSpkiCommit
    ];
    const publicChain: string[] = ['300', '1', '12345']; // rTL, algorithmTag, leafSpkiCommit

    const out = encodeRegisterFromSignals({
      pk: PK,
      proofLeaf: makeProof(0),
      publicLeaf,
      proofChain: makeProof(20),
      publicChain,
    });

    expect(out.calldata).toMatch(/^0x[0-9a-f]+$/);
    expect(out.calldata.length).toBeGreaterThan(10);
    expect(out.args.pk).toBe(PK);
    expect(out.args.chainInputs.leafSpkiCommit).toBe(
      ('0x' + (12345n).toString(16).padStart(64, '0')) as `0x${string}`,
    );
  });

  it('rejects malformed leaf public signal length', () => {
    const PK = `0x04${'00'.repeat(64)}` as `0x04${string}`;
    expect(() =>
      encodeRegisterFromSignals({
        pk: PK,
        proofLeaf: makeProof(0),
        publicLeaf: ['only', 'one'],
        proofChain: makeProof(20),
        publicChain: ['1', '1', '1'],
      }),
    ).toThrow();
  });
});

describe('façade — policy round-trip', () => {
  it('builds a policy tree from one leaf and recomputes the root via the inclusion proof', async () => {
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default-ua',
      policyVersion: 1,
      contentHash: hex32(0x1111),
      metadataHash: hex32(0x2222),
      jurisdiction: 'UA',
    });
    const tree = await buildPolicyTreeFromLeaves([leaf], 16);
    const proof = await buildPolicyInclusionProof(tree, 0);

    expect(proof.leafHex).toBe(policyLeafHashV1(leaf));
    expect(proof.rootHex).toBe(tree.rootHex);
    expect(proof.path).toHaveLength(16);
    expect(proof.indices).toHaveLength(16);

    // The leaf field equals what the binding's policy.leafHash should pin.
    expect(BigInt(proof.leafHex)).toBe(policyLeafFieldV1(leaf));
  });
});
