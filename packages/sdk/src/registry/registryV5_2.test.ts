// V5.2 register-call boundary tests. The two index-order tests are
// load-bearing — they're the regression guard against spec
// §"Public-signal layout V5.1 → V5.2" (22-field FROZEN order) drift.
import { describe, expect, it } from 'vitest';
import { decodeFunctionData } from 'viem';
import { zkqesRegistryV5_2Abi } from '../abi/ZkqesRegistryV5_2.js';
import {
  PUBLIC_SIGNALS_V5_2_LENGTH,
  assertRegisterArgsV5_2Shape,
  encodeV5_2RegisterCalldata,
  encodeV5_2RotateWalletCalldata,
  publicSignalsV5_2FromArray,
  publicSignalsV5_2ToArray,
  type PublicSignalsV5_2,
  type RegisterArgsV5_2,
  type RotateWalletArgsV5_2,
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

// ===========================================================================
// Encoder round-trip — guards against drift between PublicSignalsV5_2's
// field order and the canonical pumped ABI's `register()` sig tuple.
// If contracts-eng re-pumps with a reordered sig tuple, this test fires.
// ===========================================================================

describe('encodeV5_2RegisterCalldata + decodeFunctionData round-trip', () => {
  function makeArgs(): RegisterArgsV5_2 {
    const path16 = Array.from({ length: 16 }, (): `0x${string}` => ZERO32) as unknown as RegisterArgsV5_2['trustMerklePath'];
    return {
      proof: {
        a: [0x1n, 0x2n] as const,
        b: [[0x3n, 0x4n] as const, [0x5n, 0x6n] as const] as const,
        c: [0x7n, 0x8n] as const,
      },
      sig: makePublicSignalsV5_2(),
      leafSpki: `0x${'aa'.repeat(91)}`,
      intSpki: `0x${'bb'.repeat(91)}`,
      signedAttrs: '0x3041020100',
      leafSig: [`0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`] as const,
      intSig: [`0x${'33'.repeat(32)}`, `0x${'44'.repeat(32)}`] as const,
      trustMerklePath: path16,
      trustMerklePathBits: 0n,
      policyMerklePath: path16,
      policyMerklePathBits: 0n,
    };
  }

  it('decodes back to functionName=register with proof at arg[0] and sig at arg[1]', () => {
    const calldata = encodeV5_2RegisterCalldata(makeArgs());
    const decoded = decodeFunctionData({ abi: zkqesRegistryV5_2Abi, data: calldata });
    expect(decoded.functionName).toBe('register');
    const args = decoded.args as readonly unknown[];
    // arg[0] = proof
    expect((args[0] as { a: readonly bigint[] }).a).toEqual([0x1n, 0x2n]);
    // arg[1] = sig — slot 0 is timestamp (V5.2 layout, not V5.1's msgSender).
    expect((args[1] as { timestamp: bigint }).timestamp).toBe(1n);
    // arg[1].rotationNewWallet at slot 17 (V5.1 was slot 18).
    expect((args[1] as { rotationNewWallet: bigint }).rotationNewWallet).toBe(18n);
    // arg[1] new pkLimb fields at slots 18-21.
    expect((args[1] as { bindingPkXHi: bigint }).bindingPkXHi).toBe(19n);
    expect((args[1] as { bindingPkXLo: bigint }).bindingPkXLo).toBe(20n);
    expect((args[1] as { bindingPkYHi: bigint }).bindingPkYHi).toBe(21n);
    expect((args[1] as { bindingPkYLo: bigint }).bindingPkYLo).toBe(22n);
  });

  it('preserves the signedAttrs raw-bytes contract (NOT a hash) at calldata position 4', () => {
    const calldata = encodeV5_2RegisterCalldata(makeArgs());
    const decoded = decodeFunctionData({ abi: zkqesRegistryV5_2Abi, data: calldata });
    const args = decoded.args as readonly unknown[];
    expect(args[2]).toBe(`0x${'aa'.repeat(91)}`);   // leafSpki
    expect(args[3]).toBe(`0x${'bb'.repeat(91)}`);   // intSpki
    expect(args[4]).toBe('0x3041020100');           // signedAttrs raw DER
  });

  it('rejects a V5.1-shape sig (with msgSender) at the type-system layer', () => {
    // Compile-time guard: PublicSignalsV5_2 has no `msgSender` field, so
    // attempting to inject one is a TS error. We verify here at runtime that
    // adding an extra `msgSender` property to the args.sig doesn't smuggle
    // it into the encoded calldata (viem encodes per ABI components only).
    const argsWithStrayMsgSender = {
      ...makeArgs(),
      sig: { ...makePublicSignalsV5_2(), msgSender: 999n } as unknown as PublicSignalsV5_2,
    };
    const calldata = encodeV5_2RegisterCalldata(argsWithStrayMsgSender);
    const decoded = decodeFunctionData({ abi: zkqesRegistryV5_2Abi, data: calldata });
    const sig = (decoded.args as readonly unknown[])[1] as Record<string, unknown>;
    expect(sig.msgSender).toBeUndefined();
  });
});

describe('encodeV5_2RotateWalletCalldata round-trip', () => {
  function makeRotateArgs(): RotateWalletArgsV5_2 {
    return {
      proof: {
        a: [0x10n, 0x20n] as const,
        b: [[0x30n, 0x40n] as const, [0x50n, 0x60n] as const] as const,
        c: [0x70n, 0x80n] as const,
      },
      sig: makePublicSignalsV5_2(),
      // 65-byte EIP-191 signature (0x prefix + 130 hex chars).
      oldWalletAuthSig: `0x${'aa'.repeat(64)}1c`,
    };
  }

  it('decodes back to functionName=rotateWallet with the 3-arg shape', () => {
    const calldata = encodeV5_2RotateWalletCalldata(makeRotateArgs());
    const decoded = decodeFunctionData({ abi: zkqesRegistryV5_2Abi, data: calldata });
    expect(decoded.functionName).toBe('rotateWallet');
    const args = decoded.args as readonly unknown[];
    expect(args.length).toBe(3);
    expect((args[0] as { a: readonly bigint[] }).a).toEqual([0x10n, 0x20n]);
    expect((args[1] as { bindingPkYLo: bigint }).bindingPkYLo).toBe(22n);
    expect(args[2]).toBe(`0x${'aa'.repeat(64)}1c`);
  });
});

// ===========================================================================
// V5.2 4-byte selector pinning. Selectors changed vs V5.1 because the sig
// tuple grew from 19 → 22 `uint256` components (the canonical Solidity
// function signature includes tuple components). Pinning the selectors
// here means any future ABI re-pump that reorders the sig tuple — even
// with the same field count — fires this test.
//
//   register     V5.1: 0x8843e757   →   V5.2: 0x9ab660c7
//   rotateWallet V5.1: 0x07d19c50   →   V5.2: 0x9849ff37
// ===========================================================================

describe('V5.2 4-byte selectors (changed vs V5.1 due to 22-element sig tuple)', () => {
  it('register selector is 0x9ab660c7', () => {
    const calldata = encodeV5_2RegisterCalldata({
      proof: { a: [0n, 0n], b: [[0n, 0n], [0n, 0n]], c: [0n, 0n] },
      sig: makePublicSignalsV5_2(),
      leafSpki: `0x${'00'.repeat(91)}`,
      intSpki: `0x${'00'.repeat(91)}`,
      signedAttrs: '0x',
      leafSig: [ZERO32, ZERO32],
      intSig: [ZERO32, ZERO32],
      trustMerklePath: Array.from({ length: 16 }, (): `0x${string}` => ZERO32) as unknown as RegisterArgsV5_2['trustMerklePath'],
      trustMerklePathBits: 0n,
      policyMerklePath: Array.from({ length: 16 }, (): `0x${string}` => ZERO32) as unknown as RegisterArgsV5_2['policyMerklePath'],
      policyMerklePathBits: 0n,
    });
    expect(calldata.slice(0, 10)).toBe('0x9ab660c7');
  });

  it('rotateWallet selector is 0x9849ff37', () => {
    const calldata = encodeV5_2RotateWalletCalldata({
      proof: { a: [0n, 0n], b: [[0n, 0n], [0n, 0n]], c: [0n, 0n] },
      sig: makePublicSignalsV5_2(),
      oldWalletAuthSig: `0x${'00'.repeat(65)}`,
    });
    expect(calldata.slice(0, 10)).toBe('0x9849ff37');
  });
});
