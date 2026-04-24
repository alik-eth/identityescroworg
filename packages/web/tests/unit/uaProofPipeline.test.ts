import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import * as secp from '@noble/secp256k1';
import {
  BINDING_V2_SCHEMA,
  buildBindingV2,
  buildPolicyLeafV1,
  policyLeafHashV1,
} from '../../src/lib/bindingV2';
import { buildPolicyInclusionProof, buildPolicyTreeFromLeaves } from '../../src/lib/policyTree';
import type { Phase2Witness } from '../../src/lib/witness';
import {
  buildUaLeafPublicSignalsV4,
  computeDobCommit,
} from '../../src/lib/uaProofPipeline';

const VALID_SK = new Uint8Array(32);
VALID_SK[31] = 1;
const VALID_PK = secp.getPublicKey(VALID_SK, false);
const NONCE = new Uint8Array(32).map((_, i) => i + 1);

function hex32(v: string): `0x${string}` {
  return `0x${v.padStart(64, '0')}`;
}

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

describe('computeDobCommit', () => {
  it('produces Poseidon(dobYmd, sourceTag) as a decimal string', async () => {
    // Golden value from the circuits-side synthetic smoke:
    //   packages/circuits/fixtures/integration/ua-v4/leaf-synthetic-qkb2.public.json
    //   public[14] = dobCommit = Poseidon(0, 1)
    const c = await computeDobCommit(0n, 1n);
    expect(c).toBe(
      '12583541437132735734108669866114103169564651237895298778035846191048104863326',
    );
  });

  it('is deterministic for the same inputs', async () => {
    const a = await computeDobCommit(19990426n, 1n);
    const b = await computeDobCommit(19990426n, 1n);
    expect(a).toBe(b);
    expect(a).not.toBe(await computeDobCommit(19990426n, 0n));
  });
});

describe('buildUaLeafPublicSignalsV4', () => {
  it('emits 16 signals in circuit order (no-DOB leaf DER)', async () => {
    const leaf = buildPolicyLeafV1({
      policyId: 'qkb-default-ua',
      policyVersion: 1,
      contentHash: hex32('aa'),
      metadataHash: hex32('bb'),
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
    // Synthetic leaf DER with NO 2.5.29.9 outer anchor — extractor returns
    // supported:false so the builder emits (dobCommit = Poseidon(0,1),
    // dobSupported = 0), matching DobExtractorDiiaUA's wiring on a cert
    // without the Diia extension.
    const leafDER = new Uint8Array(256).fill(0x42);
    const out = await buildUaLeafPublicSignalsV4({
      baseWitness: makeBaseWitness(),
      binding,
      policyProof: proof,
      leafDER,
    });
    expect(out.publicLeafV4).toHaveLength(16);
    // pkX/pkY limbs (0..7) derive from the binding's pk, not the synthetic
    // baseWitness fields — just confirm they're non-empty decimal strings.
    for (let i = 0; i < 8; i++) {
      expect(out.publicLeafV4[i]).toMatch(/^\d+$/);
      expect(BigInt(out.publicLeafV4[i]!)).toBeGreaterThanOrEqual(0n);
    }
    expect(out.publicLeafV4[8]).toBe('0'); // ctxHash (no context)
    expect(out.publicLeafV4[11]).toBe('1780000000'); // timestamp from the binding
    expect(out.publicLeafV4[12]).toBe('42'); // nullifier (lifted from baseWitness)
    expect(out.publicLeafV4[13]).toBe('99'); // leafSpkiCommit (lifted from baseWitness)
    // (14) dobCommit = Poseidon(0, 1) — matches the synthetic KAT golden.
    expect(out.publicLeafV4[14]).toBe(
      '12583541437132735734108669866114103169564651237895298778035846191048104863326',
    );
    expect(out.publicLeafV4[15]).toBe('0');
    expect(out.dobSupported).toBe(0);
  });

  it('structural pin matches circuits-side KAT leaf-synthetic-qkb2.public.json ordering', () => {
    const kat = JSON.parse(
      readFileSync(
        resolve(
          __dirname,
          '../../../../../circuits/packages/circuits/fixtures/integration/ua-v4/leaf-synthetic-qkb2.public.json',
        ),
        'utf8',
      ),
    ) as string[];
    // Ordering invariants that pin the web builder against the on-circuit
    // layout — if a reorder ever lands (e.g. someone swaps dobCommit and
    // dobSupported), this test catches it.
    expect(kat).toHaveLength(16);
    for (const s of kat) {
      expect(typeof s).toBe('string');
      expect(BigInt(s)).toBeGreaterThanOrEqual(0n);
    }
    // pkX/pkY limbs are small (< 2^64 each — four 64-bit limbs of a 256-bit value).
    for (const i of [0, 1, 2, 3, 4, 5, 6, 7]) {
      expect(BigInt(kat[i]!)).toBeLessThan(1n << 64n);
    }
    // ctxHash = 0 (empty context in the synthetic binding).
    expect(kat[8]).toBe('0');
    // timestamp is unix seconds in the late-2020s range.
    expect(BigInt(kat[11]!)).toBeGreaterThan(1_700_000_000n);
    expect(BigInt(kat[11]!)).toBeLessThan(2_000_000_000n);
    // dobSupported ∈ {0, 1}. Synthetic has no 2.5.29.9 → 0.
    expect(['0', '1']).toContain(kat[15]);
    // dobCommit (index 14) must match Poseidon(0, 1) since synthetic dobSupported=0.
    if (kat[15] === '0') {
      expect(kat[14]).toBe(
        '12583541437132735734108669866114103169564651237895298778035846191048104863326',
      );
    }
  });
});
