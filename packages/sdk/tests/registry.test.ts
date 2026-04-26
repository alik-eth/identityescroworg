import { describe, expect, it } from 'vitest';
import {
  ageInputsV4FromPublicSignals,
  agePublicSignalsV4,
  assertLeafInputsV4Shape,
  assertLeafInputsV4AgeShape,
  assertRegisterArgsV4Shape,
  assertRegisterArgsV4AgeShape,
  buildRegisterArgsV4AgeFromSignals,
  buildRegisterArgsV4FromSignals,
  encodeLeafProofCalldata,
  leafInputsV4AgeFromPublicSignals,
  leafInputsV4FromPublicSignals,
  leafPublicSignalsV4Age,
  leafPublicSignalsV4,
  type AgeInputsV4,
  type LeafInputsV4AgeCapable,
  type LeafInputsV4,
  type RegisterArgsV4Age,
  type RegisterArgsV4,
} from '../src/registry/index.js';
import type { ChainInputs, Groth16Proof, SolidityProof } from '../src/core/index.js';

function hex32(n: number | bigint | string): `0x${string}` {
  const v = typeof n === 'bigint' ? n : typeof n === 'string' ? BigInt(n) : BigInt(n);
  return `0x${v.toString(16).padStart(64, '0')}`;
}

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

describe('leafPublicSignalsV4', () => {
  it('emits the frozen 14-signal draft order', () => {
    const ps = leafPublicSignalsV4({
      pkX: ['1', '2', '3', '4'],
      pkY: ['5', '6', '7', '8'],
      ctxHash: '0',
      policyLeafHash: '1234',
      policyRoot: '5678',
      timestamp: '1730000000',
      nullifier: '42',
      leafSpkiCommit: '99',
    });
    expect(ps.signals).toEqual([
      '1', '2', '3', '4',
      '5', '6', '7', '8',
      '0',
      '1234',
      '5678',
      '1730000000',
      '42',
      '99',
    ]);
  });

  it('rejects malformed limb counts', () => {
    expect(() =>
      leafPublicSignalsV4({
        pkX: ['1', '2', '3'],
        pkY: ['5', '6', '7', '8'],
        ctxHash: '0',
        policyLeafHash: '1234',
        policyRoot: '5678',
        timestamp: '1730000000',
        nullifier: '42',
        leafSpkiCommit: '99',
      }),
    ).toThrowError(expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error);
  });
});

describe('leafPublicSignalsV4Age', () => {
  it('emits the frozen 16-signal age-capable order', () => {
    const ps = leafPublicSignalsV4Age({
      pkX: ['1', '2', '3', '4'],
      pkY: ['5', '6', '7', '8'],
      ctxHash: '0',
      policyLeafHash: '1234',
      policyRoot: '5678',
      timestamp: '1730000000',
      nullifier: '42',
      leafSpkiCommit: '99',
      dobCommit: '777',
      dobSupported: 1,
    });
    expect(ps.signals).toEqual([
      '1', '2', '3', '4',
      '5', '6', '7', '8',
      '0',
      '1234',
      '5678',
      '1730000000',
      '42',
      '99',
      '777',
      '1',
    ]);
  });
});

describe('agePublicSignalsV4', () => {
  it('emits the frozen 3-signal age order', () => {
    const ps = agePublicSignalsV4({
      dobCommit: '777',
      ageCutoffDate: '20080423',
      ageQualified: 1,
    });
    expect(ps.signals).toEqual(['777', '20080423', '1']);
  });
});

describe('leafInputsV4FromPublicSignals', () => {
  const signals: readonly string[] = [
    '1', '2', '3', '4',
    '5', '6', '7', '8',
    '0',
    '1234',
    '5678',
    '1730000000',
    '42',
    '99',
  ];

  it('projects the 14-signal draft array into LeafInputsV4', () => {
    const li = leafInputsV4FromPublicSignals(signals);
    expect(li.pkX).toEqual(['1', '2', '3', '4']);
    expect(li.pkY).toEqual(['5', '6', '7', '8']);
    expect(li.ctxHash).toBe(hex32(0));
    expect(li.policyLeafHash).toBe(hex32(1234));
    expect(li.policyRoot).toBe(hex32(5678));
    expect(li.timestamp).toBe('1730000000');
    expect(li.nullifier).toBe(hex32(42));
    expect(li.leafSpkiCommit).toBe(hex32(99));
  });

  it('rejects wrong-length arrays', () => {
    expect(() => leafInputsV4FromPublicSignals(signals.slice(0, 13))).toThrowError(
      expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error,
    );
  });
});

describe('leafInputsV4AgeFromPublicSignals', () => {
  const signals: readonly string[] = [
    '1', '2', '3', '4',
    '5', '6', '7', '8',
    '0',
    '1234',
    '5678',
    '1730000000',
    '42',
    '99',
    '777',
    '1',
  ];

  it('projects the 16-signal draft array into LeafInputsV4AgeCapable', () => {
    const li = leafInputsV4AgeFromPublicSignals(signals);
    expect(li.dobCommit).toBe(hex32(777));
    expect(li.dobSupported).toBe(1);
  });
});

describe('ageInputsV4FromPublicSignals', () => {
  it('projects the 3-signal draft array into AgeInputsV4', () => {
    const ai = ageInputsV4FromPublicSignals(['777', '20080423', '1']);
    expect(ai.dobCommit).toBe(hex32(777));
    expect(ai.ageCutoffDate).toBe('20080423');
    expect(ai.ageQualified).toBe(1);
  });
});

describe('assertLeafInputsV4Shape', () => {
  const valid: LeafInputsV4 = {
    pkX: ['1', '2', '3', '4'],
    pkY: ['5', '6', '7', '8'],
    ctxHash: hex32(0),
    policyLeafHash: hex32(1234),
    policyRoot: hex32(5678),
    timestamp: '1730000000',
    nullifier: hex32(42),
    leafSpkiCommit: hex32(99),
  };

  it('accepts a well-shaped V4 leaf inputs object', () => {
    expect(() => assertLeafInputsV4Shape(valid)).not.toThrow();
  });

  it('rejects malformed policyRoot bytes32 values', () => {
    expect(() =>
      assertLeafInputsV4Shape({
        ...valid,
        policyRoot: '0x1234' as unknown as `0x${string}`,
      }),
    ).toThrowError(expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error);
  });
});

describe('assertLeafInputsV4AgeShape', () => {
  const valid: LeafInputsV4AgeCapable = {
    pkX: ['1', '2', '3', '4'],
    pkY: ['5', '6', '7', '8'],
    ctxHash: hex32(0),
    policyLeafHash: hex32(1234),
    policyRoot: hex32(5678),
    timestamp: '1730000000',
    nullifier: hex32(42),
    leafSpkiCommit: hex32(99),
    dobCommit: hex32(777),
    dobSupported: 1,
  };

  it('accepts a well-shaped age-capable V4 leaf inputs object', () => {
    expect(() => assertLeafInputsV4AgeShape(valid)).not.toThrow();
  });

  it('rejects non-binary dobSupported values', () => {
    expect(() =>
      assertLeafInputsV4AgeShape({
        ...valid,
        dobSupported: 2 as 0 | 1,
      }),
    ).toThrowError(expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error);
  });
});

describe('assertRegisterArgsV4Shape', () => {
  const validPk = ('0x04' + 'ab'.repeat(64)) as `0x04${string}`;
  const validProof: SolidityProof = {
    a: ['1', '2'],
    b: [
      ['4', '3'],
      ['6', '5'],
    ],
    c: ['7', '8'],
  };
  const sharedCommit = hex32(99);
  const validLeafInputs: LeafInputsV4 = {
    pkX: ['1', '2', '3', '4'],
    pkY: ['5', '6', '7', '8'],
    ctxHash: hex32(0),
    policyLeafHash: hex32(1234),
    policyRoot: hex32(5678),
    timestamp: '1730000000',
    nullifier: hex32(42),
    leafSpkiCommit: sharedCommit,
  };
  const validChainInputs: ChainInputs = {
    rTL: hex32(0x1234),
    algorithmTag: 1,
    leafSpkiCommit: sharedCommit,
  };
  const validArgs: RegisterArgsV4 = {
    pk: validPk,
    proofLeaf: validProof,
    leafInputs: validLeafInputs,
    proofChain: validProof,
    chainInputs: validChainInputs,
  };

  it('accepts a well-formed draft V4 args payload', () => {
    expect(() => assertRegisterArgsV4Shape(validArgs)).not.toThrow();
  });

  it('rejects leaf / chain leafSpkiCommit drift', () => {
    const bad: RegisterArgsV4 = {
      ...validArgs,
      chainInputs: { ...validChainInputs, leafSpkiCommit: hex32(88) },
    };
    expect(() => assertRegisterArgsV4Shape(bad)).toThrowError(
      expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error,
    );
  });
});

describe('assertRegisterArgsV4AgeShape', () => {
  const validPk = ('0x04' + 'ab'.repeat(64)) as `0x04${string}`;
  const validProof: SolidityProof = {
    a: ['1', '2'],
    b: [
      ['4', '3'],
      ['6', '5'],
    ],
    c: ['7', '8'],
  };
  const sharedCommit = hex32(99);
  const sharedDobCommit = hex32(777);
  const validLeafInputs: LeafInputsV4AgeCapable = {
    pkX: ['1', '2', '3', '4'],
    pkY: ['5', '6', '7', '8'],
    ctxHash: hex32(0),
    policyLeafHash: hex32(1234),
    policyRoot: hex32(5678),
    timestamp: '1730000000',
    nullifier: hex32(42),
    leafSpkiCommit: sharedCommit,
    dobCommit: sharedDobCommit,
    dobSupported: 1,
  };
  const validChainInputs: ChainInputs = {
    rTL: hex32(0x1234),
    algorithmTag: 1,
    leafSpkiCommit: sharedCommit,
  };
  const validAgeInputs: AgeInputsV4 = {
    dobCommit: sharedDobCommit,
    ageCutoffDate: '20080423',
    ageQualified: 1,
  };
  const validArgs: RegisterArgsV4Age = {
    pk: validPk,
    proofLeaf: validProof,
    leafInputs: validLeafInputs,
    proofChain: validProof,
    chainInputs: validChainInputs,
    proofAge: validProof,
    ageInputs: validAgeInputs,
    requireAgeQualification: true,
  };

  it('accepts a well-formed age-capable V4 args payload', () => {
    expect(() => assertRegisterArgsV4AgeShape(validArgs)).not.toThrow();
  });

  it('rejects age-required payloads when dob is unsupported', () => {
    expect(() =>
      assertRegisterArgsV4AgeShape({
        ...validArgs,
        leafInputs: { ...validLeafInputs, dobSupported: 0 },
      }),
    ).toThrowError(expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error);
  });
});

describe('buildRegisterArgsV4FromSignals', () => {
  const pk = ('0x04' + 'ab'.repeat(64)) as `0x04${string}`;
  const publicLeaf = [
    '1', '2', '3', '4',
    '5', '6', '7', '8',
    '0',
    '1234',
    '5678',
    '1730000000',
    '42',
    '99',
  ];
  const publicChain = ['4660', '1', '99'];

  it('assembles a valid draft V4 args object from proof + public signals', () => {
    const args = buildRegisterArgsV4FromSignals(
      pk,
      sampleProof,
      publicLeaf,
      sampleProof,
      publicChain,
    );
    expect(args.leafInputs.policyLeafHash).toBe(hex32(1234));
    expect(args.leafInputs.policyRoot).toBe(hex32(5678));
    expect(args.chainInputs.rTL).toBe(hex32(0x1234));
    expect(args.leafInputs.leafSpkiCommit).toBe(args.chainInputs.leafSpkiCommit);
    expect(() => assertRegisterArgsV4Shape(args)).not.toThrow();
  });

  it('rejects unknown algorithm tags at the public-signal boundary', () => {
    const malformedChain = ['4660', '5', '99'];
    expect(() =>
      buildRegisterArgsV4FromSignals(pk, sampleProof, publicLeaf, sampleProof, malformedChain),
    ).toThrowError(
      expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error,
    );
  });

  it('accepts algorithmTag="0" (RSA) explicitly', () => {
    const rsaChain = ['4660', '0', '99'];
    const args = buildRegisterArgsV4FromSignals(
      pk,
      sampleProof,
      publicLeaf,
      sampleProof,
      rsaChain,
    );
    expect(args.chainInputs.algorithmTag).toBe(0);
  });
});

describe('buildRegisterArgsV4AgeFromSignals', () => {
  const pk = ('0x04' + 'ab'.repeat(64)) as `0x04${string}`;
  const publicLeaf = [
    '1', '2', '3', '4',
    '5', '6', '7', '8',
    '0',
    '1234',
    '5678',
    '1730000000',
    '42',
    '99',
    '777',
    '1',
  ];
  const publicChain = ['4660', '1', '99'];
  const publicAge = ['777', '20080423', '1'];

  it('assembles a valid age-capable V4 args object from proof + public signals', () => {
    const args = buildRegisterArgsV4AgeFromSignals(
      pk,
      sampleProof,
      publicLeaf,
      sampleProof,
      publicChain,
      sampleProof,
      publicAge,
      true,
    );
    expect(args.leafInputs.dobCommit).toBe(hex32(777));
    expect(args.ageInputs.dobCommit).toBe(hex32(777));
    expect(args.ageInputs.ageQualified).toBe(1);
    expect(() => assertRegisterArgsV4AgeShape(args)).not.toThrow();
  });

  it('rejects ageCutoffDate that is not a real YYYYMMDD calendar date (Feb 31)', () => {
    const badAge = ['777', '20080231', '1'];
    expect(() =>
      buildRegisterArgsV4AgeFromSignals(
        pk, sampleProof, publicLeaf, sampleProof, publicChain, sampleProof, badAge, true,
      ),
    ).toThrowError(expect.objectContaining({ code: 'binding.field' }) as unknown as Error);
  });

  it('rejects ageCutoffDate outside [19000101, 29991231]', () => {
    const badAge = ['777', '18991231', '1'];
    expect(() =>
      buildRegisterArgsV4AgeFromSignals(
        pk, sampleProof, publicLeaf, sampleProof, publicChain, sampleProof, badAge, true,
      ),
    ).toThrowError(expect.objectContaining({ code: 'binding.field' }) as unknown as Error);
  });

  it('rejects non-numeric ageCutoffDate strings', () => {
    const badAge = ['777', 'not-a-date', '1'];
    expect(() =>
      buildRegisterArgsV4AgeFromSignals(
        pk, sampleProof, publicLeaf, sampleProof, publicChain, sampleProof, badAge, true,
      ),
    ).toThrowError(expect.objectContaining({ code: 'binding.field' }) as unknown as Error);
  });
});

describe('encodeLeafProofCalldata', () => {
  function makeDummyG16Proof() {
    return {
      a: [0n, 0n] as const,
      b: [
        [0n, 0n],
        [0n, 0n],
      ] as const,
      c: [0n, 0n] as const,
    };
  }

  it('emits 16 uints in circuit order', () => {
    const proof = makeDummyG16Proof();
    const signals = {
      pkX: [1n, 2n, 3n, 4n] as [bigint, bigint, bigint, bigint],
      pkY: [5n, 6n, 7n, 8n] as [bigint, bigint, bigint, bigint],
      ctxHash: 9n,
      policyLeafHash: 10n,
      policyRoot: 11n,
      timestamp: 12n,
      nullifier: 13n,
      leafSpkiCommit: 14n,
      dobCommit: 15n,
      dobSupported: 1n,
    };
    const calldata = encodeLeafProofCalldata(proof, signals);
    expect(calldata.inputs).toHaveLength(16);
    expect(calldata.inputs[14]).toBe(15n);
    expect(calldata.inputs[15]).toBe(1n);
  });
});
