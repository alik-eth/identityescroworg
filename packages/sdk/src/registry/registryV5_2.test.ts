// V5.2 register-call boundary tests. The two index-order tests are
// load-bearing — they're the regression guard against spec
// §"Public-signal layout V5.1 → V5.2" (22-field FROZEN order) drift.
import { describe, expect, it } from 'vitest';
import {
  PUBLIC_SIGNALS_V5_2_LENGTH,
  assertRegisterArgsV5_2Shape,
  publicSignalsV5_2FromArray,
  publicSignalsV5_2ToArray,
  type PublicSignalsV5_2,
  type RegisterArgsV5_2,
} from './registryV5_2.js';

const ZERO32: `0x${string}` = `0x${'00'.repeat(32)}`;
const U128_MAX = 1n << 128n;

function makePublicSignalsV5_2(): PublicSignalsV5_2 {
  return {
    // Slot 0-12 — V5.1 slots 1-13, shifted down by 1 (msgSender removal).
    timestamp: 1n,
    nullifier: 2n,
    ctxHashHi: 3n,
    ctxHashLo: 4n,
    bindingHashHi: 5n,
    bindingHashLo: 6n,
    signedAttrsHashHi: 7n,
    signedAttrsHashLo: 8n,
    leafTbsHashHi: 9n,
    leafTbsHashLo: 10n,
    policyLeafHash: 11n,
    leafSpkiCommit: 12n,
    intSpkiCommit: 13n,
    // Slot 13-17 — V5.1 slots 14-18, shifted down by 1.
    identityFingerprint: 14n,
    identityCommitment: 15n,
    rotationMode: 16n,
    rotationOldCommitment: 17n,
    rotationNewWallet: 18n,
    // Slot 18-21 — V5.2 NEW pkLimb slots.
    bindingPkXHi: 19n,
    bindingPkXLo: 20n,
    bindingPkYHi: 21n,
    bindingPkYLo: 22n,
  };
}

describe('publicSignalsV5_2ToArray (spec §Public-signal-layout-V5.1→V5.2 FROZEN)', () => {
  it('preserves the 22-element index order with msgSender REMOVED + bindingPk* APPENDED', () => {
    expect(publicSignalsV5_2ToArray(makePublicSignalsV5_2())).toEqual([
      1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n,
      11n, 12n, 13n, 14n, 15n, 16n, 17n, 18n,
      19n, 20n, 21n, 22n,
    ]);
  });

  it('emits exactly PUBLIC_SIGNALS_V5_2_LENGTH entries', () => {
    expect(publicSignalsV5_2ToArray(makePublicSignalsV5_2()).length).toBe(PUBLIC_SIGNALS_V5_2_LENGTH);
    expect(PUBLIC_SIGNALS_V5_2_LENGTH).toBe(22);
  });

  it('round-trips through publicSignalsV5_2FromArray', () => {
    const ps = makePublicSignalsV5_2();
    const arr = publicSignalsV5_2ToArray(ps);
    expect(publicSignalsV5_2FromArray(arr)).toEqual(ps);
  });

  it('publicSignalsV5_2FromArray accepts decimal-string arrays (snarkjs shape)', () => {
    const arr = [
      '1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
      '11', '12', '13', '14', '15', '16', '17', '18',
      '19', '20', '21', '22',
    ];
    expect(publicSignalsV5_2FromArray(arr)).toEqual(makePublicSignalsV5_2());
  });

  it('publicSignalsV5_2FromArray rejects wrong-length arrays', () => {
    expect(() => publicSignalsV5_2FromArray([1n, 2n, 3n])).toThrow(/public-signals-v5_2-length/);
    expect(() => publicSignalsV5_2FromArray(new Array(19).fill(0n))).toThrow(/public-signals-v5_2-length/);
    // V5.1's 19-element array must NOT be accepted by V5.2's parser.
    expect(() => publicSignalsV5_2FromArray(new Array(21).fill(0n))).toThrow(/public-signals-v5_2-length/);
  });
});

describe('assertRegisterArgsV5_2Shape', () => {
  function validArgs(): RegisterArgsV5_2 {
    const path16 = Array.from({ length: 16 }, (): `0x${string}` => ZERO32) as unknown as RegisterArgsV5_2['trustMerklePath'];
    return {
      proof: {
        a: [1n, 2n] as const,
        b: [[3n, 4n] as const, [5n, 6n] as const] as const,
        c: [7n, 8n] as const,
      },
      sig: makePublicSignalsV5_2(),
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
    expect(() => assertRegisterArgsV5_2Shape(validArgs())).not.toThrow();
  });

  it('rejects out-of-range timestamp (≥ 2^64)', () => {
    const bad: RegisterArgsV5_2 = { ...validArgs(), sig: { ...makePublicSignalsV5_2(), timestamp: 1n << 64n } };
    expect(() => assertRegisterArgsV5_2Shape(bad)).toThrow(/timestamp-range/);
  });

  it('rejects bindingPkXHi ≥ 2^128 (Bits2Num(128) range)', () => {
    const bad: RegisterArgsV5_2 = { ...validArgs(), sig: { ...makePublicSignalsV5_2(), bindingPkXHi: U128_MAX } };
    expect(() => assertRegisterArgsV5_2Shape(bad)).toThrow(/bindingPk-limb-range/);
  });

  it('rejects bindingPkYLo ≥ 2^128 (Bits2Num(128) range)', () => {
    const bad: RegisterArgsV5_2 = { ...validArgs(), sig: { ...makePublicSignalsV5_2(), bindingPkYLo: U128_MAX + 1n } };
    expect(() => assertRegisterArgsV5_2Shape(bad)).toThrow(/bindingPk-limb-range/);
  });

  it('accepts bindingPk* exactly at 2^128 - 1 (max valid)', () => {
    const max128 = U128_MAX - 1n;
    const args: RegisterArgsV5_2 = {
      ...validArgs(),
      sig: {
        ...makePublicSignalsV5_2(),
        bindingPkXHi: max128,
        bindingPkXLo: max128,
        bindingPkYHi: max128,
        bindingPkYLo: max128,
      },
    };
    expect(() => assertRegisterArgsV5_2Shape(args)).not.toThrow();
  });
});
