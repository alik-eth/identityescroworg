import { describe, expect, it } from 'vitest';
import * as secp from '@noble/secp256k1';
import {
  BINDING_V2_SCHEMA,
  buildBindingV2,
  buildPolicyLeafV1,
  policyLeafHashV1,
} from '../../src/lib/bindingV2';
import { buildPolicyInclusionProof, buildPolicyTreeFromLeaves } from '../../src/lib/policyTree';
import { buildPhase2WitnessV4Draft, leafPublicSignalsV4 } from '../../src/lib/witnessV4';
import type { Phase2Witness } from '../../src/lib/witness';

const VALID_SK = hexToBytes(
  '0000000000000000000000000000000000000000000000000000000000000001',
);
const VALID_PK = secp.getPublicKey(VALID_SK, false);
const NONCE = new Uint8Array(32).map((_, i) => i + 1);

function makeBaseWitness(): Phase2Witness {
  return {
    leaf: {
      pkX: ['1', '2', '3', '4'],
      pkY: ['5', '6', '7', '8'],
      ctxHash: '0',
      declHash: '1234',
      timestamp: '1730000000',
      nullifier: '42',
      leafSpkiCommit: '99',
      subjectSerialValueOffset: 100,
      subjectSerialValueLength: 14,
      Bcanon: [],
      BcanonLen: 0,
      BcanonPaddedIn: [],
      BcanonPaddedLen: 0,
      pkValueOffset: 0,
      schemeValueOffset: 0,
      ctxValueOffset: 0,
      ctxHexLen: 0,
      declValueOffset: 0,
      declValueLen: 0,
      tsValueOffset: 0,
      tsDigitCount: 10,
      declPaddedIn: [],
      declPaddedLen: 0,
      signedAttrs: Array.from({ length: 1536 }, (_, i) => (i < 8 ? i + 1 : 0)),
      signedAttrsLen: 8,
      signedAttrsPaddedIn: Array.from({ length: 1536 }, (_, i) => (i < 64 ? 0xaa : 0)),
      signedAttrsPaddedLen: 64,
      mdOffsetInSA: 4,
      leafDER: Array.from({ length: 1536 }, (_, i) => (i < 16 ? 0xbb : 0)),
      leafSpkiXOffset: 200,
      leafSpkiYOffset: 232,
      leafSigR: ['0', '0', '0', '0', '0', '0'],
      leafSigS: ['0', '0', '0', '0', '0', '0'],
    },
    chain: {
      rTL: '4660',
      algorithmTag: '1',
      leafSpkiCommit: '99',
      leafDER: Array<number>(1536).fill(0),
      leafSpkiXOffset: 200,
      leafSpkiYOffset: 232,
      leafTbsPaddedIn: Array<number>(1536).fill(0),
      leafTbsPaddedLen: 64,
      intDER: Array<number>(1536).fill(0),
      intDerLen: 64,
      intSpkiXOffset: 12,
      intSpkiYOffset: 44,
      intSigR: ['0', '0', '0', '0', '0', '0'],
      intSigS: ['0', '0', '0', '0', '0', '0'],
      merklePath: Array(16).fill('0'),
      merkleIndices: Array(16).fill(0),
    },
    shared: {
      pkX: ['1', '2', '3', '4'],
      pkY: ['5', '6', '7', '8'],
      ctxHash: '0',
      declHash: '1234',
      timestamp: '1730000000',
      nullifier: '42',
      leafSpkiCommit: '99',
      rTL: '4660',
      algorithmTag: '1',
    },
  };
}

describe('buildPhase2WitnessV4Draft', () => {
  it('lifts a V3 phase-2 witness into the draft V4 leaf surface', async () => {
    const leafA = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });
    const leafB = buildPolicyLeafV1({
      policyId: 'qkb-alt',
      policyVersion: 1,
      contentHash: hex32('33'),
      metadataHash: hex32('44'),
    });
    const tree = await buildPolicyTreeFromLeaves([leafA, leafB], 16);
    const proof = await buildPolicyInclusionProof(tree, 0);
    const binding = buildBindingV2({
      pk: VALID_PK,
      timestamp: 1_780_000_000,
      nonce: NONCE,
      policy: {
        leafHash: policyLeafHashV1(leafA),
        policyId: leafA.policyId,
        policyVersion: leafA.policyVersion,
        bindingSchema: BINDING_V2_SCHEMA,
      },
      display: { lang: 'en', template: 'qkb-default/v2', text: 'Display only' },
    });

    const w = buildPhase2WitnessV4Draft({
      baseWitness: makeBaseWitness(),
      binding,
      policyProof: proof,
    });

    expect(w.leaf.policyLeafHash).toBe(BigInt(proof.leafHex).toString());
    expect(w.leaf.policyRoot).toBe(BigInt(proof.rootHex).toString());
    expect(w.shared.policyLeafHash).toBe(w.leaf.policyLeafHash);
    expect(w.shared.policyRoot).toBe(w.leaf.policyRoot);
    expect(w.leaf.nullifier).toBe('42');
    expect(w.leaf.leafSpkiCommit).toBe(w.chain.leafSpkiCommit);
    expect(w.leaf.policyMerklePath).toHaveLength(16);
    expect(w.leaf.policyMerkleIndices).toHaveLength(16);
    expect(w.leaf.bindingCoreLen).toBeGreaterThan(0);
    expect(w.leaf.assertionsValueOffset).toBeGreaterThan(0);
    expect(w.leaf.statementSchemaValueOffset).toBeGreaterThan(0);
    expect(w.leaf.nonceValueOffset).toBeGreaterThan(0);
    expect(w.leaf.nonceBytes).toHaveLength(32);
    expect(w.leaf.policyIdValueOffset).toBeGreaterThan(0);
    expect(w.leaf.policyIdLen).toBe(leafA.policyId.length);
    expect(w.leaf.policyVersionValueOffset).toBeGreaterThan(0);
    expect(w.leaf.policyVersionDigitCount).toBeGreaterThan(0);
    expect(w.leaf.policyVersion).toBe(leafA.policyVersion);
    expect(w.leaf.policyLeafHashValueOffset).toBeGreaterThan(0);
    expect(w.leaf.policyBindingSchemaValueOffset).toBeGreaterThan(0);
    expect(w.leaf.versionValueOffset).toBeGreaterThan(0);
  });

  it('leafPublicSignalsV4 emits the frozen 14-signal order', async () => {
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });
    const tree = await buildPolicyTreeFromLeaves([leaf], 16);
    const proof = await buildPolicyInclusionProof(tree, 0);
    const binding = buildBindingV2({
      pk: VALID_PK,
      timestamp: 1_780_000_000,
      nonce: NONCE,
      policy: {
        leafHash: policyLeafHashV1(leaf),
        policyId: leaf.policyId,
        policyVersion: leaf.policyVersion,
        bindingSchema: BINDING_V2_SCHEMA,
      },
    });
    const w = buildPhase2WitnessV4Draft({
      baseWitness: makeBaseWitness(),
      binding,
      policyProof: proof,
    });
    const ps = leafPublicSignalsV4(w.leaf);
    expect(ps.signals).toHaveLength(14);
    expect(ps.signals.slice(0, 4)).toEqual(w.leaf.pkX);
    expect(ps.signals.slice(4, 8)).toEqual(w.leaf.pkY);
    expect(ps.signals[8]).toBe(w.leaf.ctxHash);
    expect(ps.signals[9]).toBe(w.leaf.policyLeafHash);
    expect(ps.signals[10]).toBe(w.leaf.policyRoot);
    expect(ps.signals[11]).toBe(w.leaf.timestamp);
    expect(ps.signals[12]).toBe(w.leaf.nullifier);
    expect(ps.signals[13]).toBe(w.leaf.leafSpkiCommit);
  });

  it('rejects a binding whose policy.leafHash does not match the supplied proof leaf', async () => {
    const leafA = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });
    const leafB = buildPolicyLeafV1({
      policyId: 'qkb-alt',
      policyVersion: 1,
      contentHash: hex32('33'),
      metadataHash: hex32('44'),
    });
    const tree = await buildPolicyTreeFromLeaves([leafA, leafB], 16);
    const proof = await buildPolicyInclusionProof(tree, 1);
    const binding = buildBindingV2({
      pk: VALID_PK,
      timestamp: 1_780_000_000,
      nonce: NONCE,
      policy: {
        leafHash: policyLeafHashV1(leafA),
        policyId: leafA.policyId,
        policyVersion: leafA.policyVersion,
        bindingSchema: BINDING_V2_SCHEMA,
      },
    });

    expect(() =>
      buildPhase2WitnessV4Draft({
        baseWitness: makeBaseWitness(),
        binding,
        policyProof: proof,
      }),
    ).toThrowError(expect.objectContaining({ code: 'binding.field' }) as unknown as Error);
  });

  it('rejects non-empty context until the draft ctx hash path is implemented', async () => {
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default',
      policyVersion: 2,
      contentHash: hex32('11'),
      metadataHash: hex32('22'),
    });
    const tree = await buildPolicyTreeFromLeaves([leaf], 16);
    const proof = await buildPolicyInclusionProof(tree, 0);
    const binding = buildBindingV2({
      pk: VALID_PK,
      timestamp: 1_780_000_000,
      nonce: NONCE,
      context: new TextEncoder().encode('dao.example.org#vote-2026'),
      policy: {
        leafHash: policyLeafHashV1(leaf),
        policyId: leaf.policyId,
        policyVersion: leaf.policyVersion,
        bindingSchema: BINDING_V2_SCHEMA,
      },
    });

    expect(() =>
      buildPhase2WitnessV4Draft({
        baseWitness: makeBaseWitness(),
        binding,
        policyProof: proof,
      }),
    ).toThrowError(expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error);
  });
});

function hex32(v: string): `0x${string}` {
  return `0x${v.padStart(64, '0')}`;
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
