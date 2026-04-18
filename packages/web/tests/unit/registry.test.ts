/**
 * QKBRegistryV3 bindings — split-proof pivot (2026-04-18).
 *
 * - Error selectors cover the frozen V3 error taxonomy (NullifierUsed,
 *   RootMismatch, AlreadyBound, LeafSpkiCommitMismatch, InvalidProof,
 *   UnknownAlgorithm, BindingTooOld, BindingFromFuture, …).
 * - classifyRegistryRevert maps the subset with localized copy and lets
 *   the rest fall through to the raw wallet message.
 * - classifyWalletRevert handles nested viem-style shapes + decoded-reason
 *   strings.
 * - assertRegisterArgsShape enforces split-proof pair shape, 32-byte hex
 *   bytes32 fields, pk format, and leafSpkiCommit agreement between the
 *   leaf and chain inputs.
 * - packProof / packLeafInputs / packChainInputs / buildRegisterArgs wire a
 *   witness + prover result through to the Solidity struct calldata shape.
 */
import { describe, expect, it } from 'vitest';
import { keccak_256 } from '@noble/hashes/sha3';
import {
  assertRegisterArgsShape,
  buildRegisterArgs,
  classifyRegistryRevert,
  classifyWalletRevert,
  packChainInputs,
  packLeafInputs,
  packProof,
  REGISTRY_ERROR_SELECTORS,
  type ChainInputs,
  type LeafInputs,
  type RegisterArgs,
  type SolidityProof,
} from '../../src/lib/registry';
import type { Groth16Proof, SplitProveResult } from '../../src/lib/prover';
import type {
  ChainWitnessInput,
  LeafWitnessInput,
  Phase2Witness,
} from '../../src/lib/witness';

function expectedSelector(sig: string): string {
  const h = keccak_256(new TextEncoder().encode(sig));
  let hex = '0x';
  for (let i = 0; i < 4; i++) hex += (h[i] as number).toString(16).padStart(2, '0');
  return hex;
}

function hex32(n: number | bigint | string): `0x${string}` {
  const v = typeof n === 'bigint' ? n : typeof n === 'string' ? BigInt(n) : BigInt(n);
  return `0x${v.toString(16).padStart(64, '0')}`;
}

describe('REGISTRY_ERROR_SELECTORS', () => {
  it('covers the V3 custom error taxonomy', () => {
    expect(REGISTRY_ERROR_SELECTORS.NullifierUsed).toBe(expectedSelector('NullifierUsed()'));
    expect(REGISTRY_ERROR_SELECTORS.RootMismatch).toBe(expectedSelector('RootMismatch()'));
    expect(REGISTRY_ERROR_SELECTORS.AlreadyBound).toBe(expectedSelector('AlreadyBound()'));
    expect(REGISTRY_ERROR_SELECTORS.LeafSpkiCommitMismatch).toBe(
      expectedSelector('LeafSpkiCommitMismatch()'),
    );
    expect(REGISTRY_ERROR_SELECTORS.InvalidProof).toBe(expectedSelector('InvalidProof()'));
    expect(REGISTRY_ERROR_SELECTORS.UnknownAlgorithm).toBe(expectedSelector('UnknownAlgorithm()'));
    expect(REGISTRY_ERROR_SELECTORS.BindingTooOld).toBe(expectedSelector('BindingTooOld()'));
    expect(REGISTRY_ERROR_SELECTORS.BindingFromFuture).toBe(
      expectedSelector('BindingFromFuture()'),
    );
    expect(REGISTRY_ERROR_SELECTORS.WrongState).toBe(expectedSelector('WrongState()'));
    expect(REGISTRY_ERROR_SELECTORS.EscrowExists).toBe(expectedSelector('EscrowExists()'));
  });

  it('all selectors are 10-char 0x-hex', () => {
    for (const s of Object.values(REGISTRY_ERROR_SELECTORS)) {
      expect(s).toMatch(/^0x[0-9a-f]{8}$/);
    }
  });
});

describe('classifyRegistryRevert', () => {
  it('maps the NullifierUsed selector to registry.nullifierUsed', () => {
    const err = classifyRegistryRevert(REGISTRY_ERROR_SELECTORS.NullifierUsed);
    expect(err?.code).toBe('registry.nullifierUsed');
  });

  it('maps the RootMismatch selector to registry.rootMismatch', () => {
    const err = classifyRegistryRevert(REGISTRY_ERROR_SELECTORS.RootMismatch);
    expect(err?.code).toBe('registry.rootMismatch');
  });

  it('maps AlreadyBound + AgeExceeded + BindingTooOld', () => {
    expect(classifyRegistryRevert(REGISTRY_ERROR_SELECTORS.AlreadyBound)?.code).toBe(
      'registry.alreadyBound',
    );
    expect(classifyRegistryRevert(REGISTRY_ERROR_SELECTORS.AgeExceeded)?.code).toBe(
      'registry.ageExceeded',
    );
    expect(classifyRegistryRevert(REGISTRY_ERROR_SELECTORS.BindingTooOld)?.code).toBe(
      'registry.ageExceeded',
    );
  });

  it('accepts selector with trailing ABI-encoded args', () => {
    const pad = '0'.repeat(64);
    const err = classifyRegistryRevert(REGISTRY_ERROR_SELECTORS.NullifierUsed + pad);
    expect(err?.code).toBe('registry.nullifierUsed');
  });

  it('returns null for V3 errors without localized copy (falls through to raw)', () => {
    // LeafSpkiCommitMismatch lives in the V3 taxonomy but we don't have a
    // localized QkbError for it yet; classifier should return null so the
    // caller shows the raw wallet message.
    expect(classifyRegistryRevert(REGISTRY_ERROR_SELECTORS.LeafSpkiCommitMismatch)).toBeNull();
    expect(classifyRegistryRevert(REGISTRY_ERROR_SELECTORS.InvalidProof)).toBeNull();
  });

  it('returns null for unknown selector / malformed input', () => {
    expect(classifyRegistryRevert('0xdeadbeef')).toBeNull();
    expect(classifyRegistryRevert(undefined)).toBeNull();
    expect(classifyRegistryRevert('')).toBeNull();
    expect(classifyRegistryRevert('not-hex')).toBeNull();
  });
});

describe('classifyWalletRevert', () => {
  it('recognizes decoded error names in Error.message', () => {
    expect(classifyWalletRevert(new Error('execution reverted: NullifierUsed()'))?.code).toBe(
      'registry.nullifierUsed',
    );
    expect(classifyWalletRevert(new Error('RootMismatch'))?.code).toBe('registry.rootMismatch');
    expect(classifyWalletRevert(new Error('AlreadyBound'))?.code).toBe('registry.alreadyBound');
    expect(classifyWalletRevert(new Error('BindingTooOld'))?.code).toBe('registry.ageExceeded');
  });

  it('walks nested viem-style { cause: { data: ... } } shapes', () => {
    const err = {
      message: 'tx failed',
      cause: {
        data: REGISTRY_ERROR_SELECTORS.RootMismatch,
      },
    };
    expect(classifyWalletRevert(err)?.code).toBe('registry.rootMismatch');
  });

  it('returns null for unrelated errors', () => {
    expect(classifyWalletRevert(new Error('user rejected request'))).toBeNull();
    expect(classifyWalletRevert({})).toBeNull();
    expect(classifyWalletRevert(null)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// V3 calldata shape packers
// ---------------------------------------------------------------------------

const sampleProof: Groth16Proof = {
  pi_a: ['1', '2', '1'],
  pi_b: [
    ['3', '4'],
    ['5', '6'],
    ['1', '0'],
  ],
  pi_c: ['7', '8', '1'],
  protocol: 'groth16',
  curve: 'bn128',
};

describe('packProof', () => {
  it('projects pi_a / pi_b / pi_c down to the Solidity uint[2]*uint[2][2]*uint[2] shape', () => {
    const p = packProof(sampleProof);
    expect(p.a).toEqual(['1', '2']);
    expect(p.c).toEqual(['7', '8']);
    // snarkjs pi_b[i] = [real, imag]; Solidity uint[2][2] b = [[b0.imag, b0.real], [b1.imag, b1.real]]
    expect(p.b).toEqual([
      ['4', '3'],
      ['6', '5'],
    ]);
  });
});

describe('packLeafInputs', () => {
  const leafW: LeafWitnessInput = {
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
    signedAttrs: [],
    signedAttrsLen: 0,
    signedAttrsPaddedIn: [],
    signedAttrsPaddedLen: 0,
    mdOffsetInSA: 0,
    leafDER: [],
    leafSpkiXOffset: 0,
    leafSpkiYOffset: 0,
    leafSigR: ['0', '0', '0', '0', '0', '0'],
    leafSigS: ['0', '0', '0', '0', '0', '0'],
  };

  it('packs witness fields into the V3 LeafInputs Solidity struct shape', () => {
    const li = packLeafInputs(leafW);
    // Witness fields are decimal strings — packLeafInputs parses them as
    // decimal bigints before rendering 32-byte hex (matches what the
    // circuit emits via snarkjs publicSignals).
    expect(li.pkX).toEqual(['1', '2', '3', '4']);
    expect(li.pkY).toEqual(['5', '6', '7', '8']);
    expect(li.ctxHash).toBe(hex32(0));
    expect(li.declHash).toBe(hex32(1234));
    expect(li.timestamp).toBe('1730000000');
    expect(li.nullifier).toBe(hex32(42));
    expect(li.leafSpkiCommit).toBe(hex32(99));
  });
});

describe('packChainInputs', () => {
  const chainW: ChainWitnessInput = {
    rTL: '4660', // 0x1234
    algorithmTag: '1',
    leafSpkiCommit: '99',
    leafDER: [],
    leafSpkiXOffset: 0,
    leafSpkiYOffset: 0,
    leafTbsPaddedIn: [],
    leafTbsPaddedLen: 0,
    intDER: [],
    intDerLen: 0,
    intSpkiXOffset: 0,
    intSpkiYOffset: 0,
    intSigR: ['0', '0', '0', '0', '0', '0'],
    intSigS: ['0', '0', '0', '0', '0', '0'],
    merklePath: Array(16).fill('0'),
    merkleIndices: Array(16).fill(0),
  };

  it('packs witness fields into the V3 ChainInputs Solidity struct shape', () => {
    const ci = packChainInputs(chainW);
    expect(ci.rTL).toBe(hex32(0x1234));
    expect(ci.algorithmTag).toBe(1);
    expect(ci.leafSpkiCommit).toBe(hex32(99));
  });

  it('algorithmTag=0 routes to RSA', () => {
    const ci = packChainInputs({ ...chainW, algorithmTag: '0' });
    expect(ci.algorithmTag).toBe(0);
  });
});

describe('buildRegisterArgs', () => {
  const leafW: LeafWitnessInput = {
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
    signedAttrs: [],
    signedAttrsLen: 0,
    signedAttrsPaddedIn: [],
    signedAttrsPaddedLen: 0,
    mdOffsetInSA: 0,
    leafDER: [],
    leafSpkiXOffset: 0,
    leafSpkiYOffset: 0,
    leafSigR: ['0', '0', '0', '0', '0', '0'],
    leafSigS: ['0', '0', '0', '0', '0', '0'],
  };
  const chainW: ChainWitnessInput = {
    rTL: '4660',
    algorithmTag: '1',
    leafSpkiCommit: '99',
    leafDER: [],
    leafSpkiXOffset: 0,
    leafSpkiYOffset: 0,
    leafTbsPaddedIn: [],
    leafTbsPaddedLen: 0,
    intDER: [],
    intDerLen: 0,
    intSpkiXOffset: 0,
    intSpkiYOffset: 0,
    intSigR: ['0', '0', '0', '0', '0', '0'],
    intSigS: ['0', '0', '0', '0', '0', '0'],
    merklePath: Array(16).fill('0'),
    merkleIndices: Array(16).fill(0),
  };
  const witness: Phase2Witness = {
    leaf: leafW,
    chain: chainW,
    shared: {
      pkX: leafW.pkX,
      pkY: leafW.pkY,
      ctxHash: leafW.ctxHash,
      declHash: leafW.declHash,
      timestamp: leafW.timestamp,
      nullifier: leafW.nullifier,
      leafSpkiCommit: leafW.leafSpkiCommit,
      rTL: chainW.rTL,
      algorithmTag: chainW.algorithmTag,
    },
  };
  const proofs: SplitProveResult = {
    proofLeaf: sampleProof,
    publicLeaf: [],
    proofChain: sampleProof,
    publicChain: [],
  };

  it('returns a well-shaped V3 RegisterArgs', () => {
    const args = buildRegisterArgs(('0x04' + 'ab'.repeat(64)) as `0x04${string}`, witness, proofs);
    expect(args.pk).toMatch(/^0x04[0-9a-fA-F]{128}$/);
    expect(args.leafInputs.leafSpkiCommit).toBe(args.chainInputs.leafSpkiCommit);
    expect(args.leafInputs.pkX).toHaveLength(4);
    expect(args.chainInputs.algorithmTag).toBe(1);
    expect(() => assertRegisterArgsShape(args)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// assertRegisterArgsShape — V3 split-proof form
// ---------------------------------------------------------------------------

describe('assertRegisterArgsShape', () => {
  const validPk = ('0x04' + 'ab'.repeat(64)) as `0x04${string}`;
  const validProof: SolidityProof = {
    a: ['1', '2'],
    b: [
      ['3', '4'],
      ['5', '6'],
    ],
    c: ['7', '8'],
  };
  const sharedCommit = hex32(0x99);
  const validLeafInputs: LeafInputs = {
    pkX: ['1', '2', '3', '4'],
    pkY: ['5', '6', '7', '8'],
    ctxHash: hex32(0),
    declHash: hex32(0x1234),
    timestamp: '1730000000',
    nullifier: hex32(0x42),
    leafSpkiCommit: sharedCommit,
  };
  const validChainInputs: ChainInputs = {
    rTL: hex32(0x1234),
    algorithmTag: 1,
    leafSpkiCommit: sharedCommit,
  };
  const validArgs: RegisterArgs = {
    pk: validPk,
    proofLeaf: validProof,
    leafInputs: validLeafInputs,
    proofChain: validProof,
    chainInputs: validChainInputs,
  };

  it('accepts a well-formed split-proof args payload', () => {
    expect(() => assertRegisterArgsShape(validArgs)).not.toThrow();
  });

  it('rejects pk with wrong length', () => {
    const args: RegisterArgs = {
      ...validArgs,
      pk: ('0x04' + 'ab'.repeat(32)) as `0x04${string}`,
    };
    expect(() => assertRegisterArgsShape(args)).toThrowError(
      expect.objectContaining({ code: 'binding.pkMismatch' }) as unknown as Error,
    );
  });

  it('rejects pk missing 0x04 prefix', () => {
    const args: RegisterArgs = {
      ...validArgs,
      pk: ('0x03' + 'ab'.repeat(64)) as unknown as `0x04${string}`,
    };
    expect(() => assertRegisterArgsShape(args)).toThrowError(
      expect.objectContaining({ code: 'binding.pkMismatch' }) as unknown as Error,
    );
  });

  it('rejects malformed proof b shape', () => {
    const bad: RegisterArgs = {
      ...validArgs,
      proofChain: { ...validProof, b: [['3', '4']] as unknown as SolidityProof['b'] },
    };
    expect(() => assertRegisterArgsShape(bad)).toThrowError(
      expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error,
    );
  });

  it('rejects leaf / chain leafSpkiCommit drift', () => {
    const bad: RegisterArgs = {
      ...validArgs,
      chainInputs: { ...validChainInputs, leafSpkiCommit: hex32(0x88) },
    };
    expect(() => assertRegisterArgsShape(bad)).toThrowError(
      expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error,
    );
  });

  it('rejects algorithmTag outside {0, 1}', () => {
    const bad: RegisterArgs = {
      ...validArgs,
      chainInputs: { ...validChainInputs, algorithmTag: 5 as unknown as 0 | 1 },
    };
    expect(() => assertRegisterArgsShape(bad)).toThrowError(
      expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error,
    );
  });

  it('rejects non-32-byte hex for bytes32 fields', () => {
    const bad: RegisterArgs = {
      ...validArgs,
      leafInputs: { ...validLeafInputs, ctxHash: '0xabc' as unknown as `0x${string}` },
    };
    expect(() => assertRegisterArgsShape(bad)).toThrowError(
      expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error,
    );
  });
});
