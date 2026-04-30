// V5 register-call boundary tests. The two index-order tests are
// load-bearing — they're the regression guard against orchestration §0.1
// (PublicSignals layout) and §0.2 (calldata struct order) drift.
import { describe, expect, it } from 'vitest';
import { decodeFunctionData } from 'viem';
import { qkbRegistryV5Abi } from '../abi/QKBRegistryV5.js';
import {
  PUBLIC_SIGNALS_V5_LENGTH,
  REGISTRY_V5_ERROR_SELECTORS,
  assertRegisterArgsV5Shape,
  classifyV5RegistryRevert,
  encodeV5RegisterCalldata,
  publicSignalsFromArray,
  publicSignalsToArray,
  type PublicSignalsV5,
  type RegisterArgsV5,
} from './registryV5.js';

const ZERO32: `0x${string}` = `0x${'00'.repeat(32)}`;

function makePublicSignals(): PublicSignalsV5 {
  return {
    msgSender: 1n,
    timestamp: 2n,
    nullifier: 3n,
    ctxHashHi: 4n,
    ctxHashLo: 5n,
    bindingHashHi: 6n,
    bindingHashLo: 7n,
    signedAttrsHashHi: 8n,
    signedAttrsHashLo: 9n,
    leafTbsHashHi: 10n,
    leafTbsHashLo: 11n,
    policyLeafHash: 12n,
    leafSpkiCommit: 13n,
    intSpkiCommit: 14n,
    // V5.1 additions — slots 14-18 (FROZEN, orchestration §1.1).
    identityFingerprint: 15n,
    identityCommitment: 16n,
    rotationMode: 17n,
    rotationOldCommitment: 18n,
    rotationNewWallet: 19n,
  };
}

describe('publicSignalsToArray (orchestration §1.1 layout — V5.1 FROZEN)', () => {
  it('preserves the 19-element index order (slots 0-13 unchanged, 14-18 new)', () => {
    expect(publicSignalsToArray(makePublicSignals())).toEqual([
      1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n, 13n, 14n,
      15n, 16n, 17n, 18n, 19n,
    ]);
  });

  it('emits exactly PUBLIC_SIGNALS_V5_LENGTH entries', () => {
    expect(publicSignalsToArray(makePublicSignals()).length).toBe(PUBLIC_SIGNALS_V5_LENGTH);
    expect(PUBLIC_SIGNALS_V5_LENGTH).toBe(19);
  });

  it('round-trips through publicSignalsFromArray', () => {
    const ps = makePublicSignals();
    const arr = publicSignalsToArray(ps);
    expect(publicSignalsFromArray(arr)).toEqual(ps);
  });

  it('publicSignalsFromArray accepts decimal-string arrays (snarkjs shape)', () => {
    const arr = [
      '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14',
      '15', '16', '17', '18', '19',
    ];
    expect(publicSignalsFromArray(arr)).toEqual(makePublicSignals());
  });

  it('publicSignalsFromArray rejects wrong-length arrays', () => {
    expect(() => publicSignalsFromArray([1n, 2n, 3n])).toThrow(/public-signals-v5-length/);
    expect(() => publicSignalsFromArray(new Array(18).fill(0n))).toThrow(/public-signals-v5-length/);
  });
});

describe('encodeV5RegisterCalldata (orchestration §0.2 struct order)', () => {
  function makeArgs(): RegisterArgsV5 {
    const path16 = Array.from({ length: 16 }, (): `0x${string}` => ZERO32) as unknown as RegisterArgsV5['trustMerklePath'];
    return {
      proof: {
        a: [0x1n, 0x2n] as const,
        b: [[0x3n, 0x4n] as const, [0x5n, 0x6n] as const] as const,
        c: [0x7n, 0x8n] as const,
      },
      sig: makePublicSignals(),
      leafSpki: `0x${'aa'.repeat(91)}`,
      intSpki: `0x${'bb'.repeat(91)}`,
      signedAttrs: '0x3041020100',  // arbitrary DER-ish prefix; raw bytes not validated
      leafSig: [`0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`] as const,
      intSig: [`0x${'33'.repeat(32)}`, `0x${'44'.repeat(32)}`] as const,
      trustMerklePath: path16,
      trustMerklePathBits: 0n,
      policyMerklePath: path16,
      policyMerklePathBits: 0n,
    };
  }

  it('produces decodable calldata with proof FIRST, sig SECOND', () => {
    // Proof-before-sig is the load-bearing assertion: an earlier
    // orchestration draft had the order reversed; if a future change ever
    // swaps them this test fails. Decoding via the same ABI round-trips
    // both struct positions, so we read them back and check positionally.
    const calldata = encodeV5RegisterCalldata(makeArgs());
    const decoded = decodeFunctionData({ abi: qkbRegistryV5Abi, data: calldata });
    expect(decoded.functionName).toBe('register');
    const args = decoded.args as readonly unknown[];
    // arg[0] is `proof` — Groth16Proof tuple { a, b, c }
    expect((args[0] as { a: readonly bigint[] }).a).toEqual([0x1n, 0x2n]);
    // arg[1] is `sig` — PublicSignals tuple, msgSender first
    expect((args[1] as { msgSender: bigint }).msgSender).toBe(1n);
    expect((args[1] as { intSpkiCommit: bigint }).intSpkiCommit).toBe(14n);
  });

  it('places signedAttrs raw bytes at calldata position 4 (proof[0], sig[1], leafSpki[2], intSpki[3], signedAttrs[4])', () => {
    const calldata = encodeV5RegisterCalldata(makeArgs());
    const decoded = decodeFunctionData({ abi: qkbRegistryV5Abi, data: calldata });
    const args = decoded.args as readonly unknown[];
    expect(args[2]).toBe(`0x${'aa'.repeat(91)}`);   // leafSpki
    expect(args[3]).toBe(`0x${'bb'.repeat(91)}`);   // intSpki
    expect(args[4]).toBe('0x3041020100');           // signedAttrs raw DER
  });

  it('encodes leafSig and intSig as bytes32[2] (r at 0, s at 1) — NOT flat 64-byte bytes', () => {
    const calldata = encodeV5RegisterCalldata(makeArgs());
    const decoded = decodeFunctionData({ abi: qkbRegistryV5Abi, data: calldata });
    const args = decoded.args as readonly unknown[];
    expect(args[5]).toEqual([`0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`]);
    expect(args[6]).toEqual([`0x${'33'.repeat(32)}`, `0x${'44'.repeat(32)}`]);
  });
});

describe('assertRegisterArgsV5Shape', () => {
  function validArgs(): RegisterArgsV5 {
    const path16 = Array.from({ length: 16 }, (): `0x${string}` => ZERO32) as unknown as RegisterArgsV5['trustMerklePath'];
    return {
      proof: {
        a: [1n, 2n] as const,
        b: [[3n, 4n] as const, [5n, 6n] as const] as const,
        c: [7n, 8n] as const,
      },
      sig: makePublicSignals(),
      leafSpki: `0x${'aa'.repeat(91)}`,
      intSpki: `0x${'bb'.repeat(91)}`,
      signedAttrs: '0x',
      leafSig: [`0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`] as const,
      intSig: [`0x${'33'.repeat(32)}`, `0x${'44'.repeat(32)}`] as const,
      trustMerklePath: path16,
      trustMerklePathBits: 0n,
      policyMerklePath: path16,
      policyMerklePathBits: 0n,
    };
  }

  it('accepts a well-formed args bundle', () => {
    expect(() => assertRegisterArgsV5Shape(validArgs())).not.toThrow();
  });

  it('rejects wrong-length SPKI', () => {
    const bad = { ...validArgs(), leafSpki: `0x${'aa'.repeat(90)}` as `0x${string}` };
    expect(() => assertRegisterArgsV5Shape(bad)).toThrow(/spki-shape/);
  });

  it('rejects out-of-range msgSender (≥ 2^160)', () => {
    const bad: RegisterArgsV5 = { ...validArgs(), sig: { ...makePublicSignals(), msgSender: 1n << 160n } };
    expect(() => assertRegisterArgsV5Shape(bad)).toThrow(/msgSender-range/);
  });

  it('rejects out-of-range timestamp (≥ 2^64)', () => {
    const bad: RegisterArgsV5 = { ...validArgs(), sig: { ...makePublicSignals(), timestamp: 1n << 64n } };
    expect(() => assertRegisterArgsV5Shape(bad)).toThrow(/timestamp-range/);
  });

  it('rejects merkle path with wrong depth', () => {
    const path15 = Array.from({ length: 15 }, (): `0x${string}` => ZERO32);
    const bad = { ...validArgs(), trustMerklePath: path15 as unknown as RegisterArgsV5['trustMerklePath'] };
    expect(() => assertRegisterArgsV5Shape(bad)).toThrow(/merkle-path-depth/);
  });

  it('rejects bytes32[2] sig with wrong-length entries', () => {
    const bad: RegisterArgsV5 = {
      ...validArgs(),
      leafSig: [`0x${'11'.repeat(31)}` as `0x${string}`, `0x${'22'.repeat(32)}` as `0x${string}`] as const,
    };
    expect(() => assertRegisterArgsV5Shape(bad)).toThrow(/bytes32-pair/);
  });
});

describe('classifyV5RegistryRevert', () => {
  it('maps NullifierUsed selector to registry.nullifierUsed', () => {
    const err = classifyV5RegistryRevert(REGISTRY_V5_ERROR_SELECTORS.NullifierUsed);
    expect(err?.code).toBe('registry.nullifierUsed');
  });

  it('maps BadProof to qes.sigInvalid', () => {
    const err = classifyV5RegistryRevert(REGISTRY_V5_ERROR_SELECTORS.BadProof);
    expect(err?.code).toBe('qes.sigInvalid');
  });

  it('maps BadSignedAttrsHi/Lo to witness.fieldTooLong', () => {
    expect(classifyV5RegistryRevert(REGISTRY_V5_ERROR_SELECTORS.BadSignedAttrsHi)?.code)
      .toBe('witness.fieldTooLong');
    expect(classifyV5RegistryRevert(REGISTRY_V5_ERROR_SELECTORS.BadSignedAttrsLo)?.code)
      .toBe('witness.fieldTooLong');
  });

  it('returns null for unknown selectors', () => {
    expect(classifyV5RegistryRevert('0xdeadbeef')).toBeNull();
    expect(classifyV5RegistryRevert(undefined)).toBeNull();
    expect(classifyV5RegistryRevert('not-hex')).toBeNull();
  });
});
