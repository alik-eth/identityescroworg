/**
 * Sprint 0 S0.4 — registry bindings + new error codes.
 *
 * - Selectors match keccak256(signature)[0..4] for the Sprint-0 custom
 *   error taxonomy.
 * - classifyRegistryRevert maps revert data → typed QkbError.
 * - classifyWalletRevert handles nested viem-style shapes.
 * - assertRegisterArgsShape enforces the 14-signal payload + pk format.
 */
import { describe, expect, it } from 'vitest';
import { keccak_256 } from '@noble/hashes/sha3';
import {
  assertRegisterArgsShape,
  classifyRegistryRevert,
  classifyWalletRevert,
  REGISTRY_ERROR_SELECTORS,
  type RegisterArgs,
} from '../../src/lib/registry';

function expectedSelector(sig: string): string {
  const h = keccak_256(new TextEncoder().encode(sig));
  let hex = '0x';
  for (let i = 0; i < 4; i++) hex += (h[i] as number).toString(16).padStart(2, '0');
  return hex;
}

describe('REGISTRY_ERROR_SELECTORS', () => {
  it('computes 4-byte selectors from the Sprint-0 error signatures', () => {
    expect(REGISTRY_ERROR_SELECTORS.NullifierUsed).toBe(expectedSelector('NullifierUsed()'));
    expect(REGISTRY_ERROR_SELECTORS.RootMismatch).toBe(expectedSelector('RootMismatch()'));
    expect(REGISTRY_ERROR_SELECTORS.AlreadyBound).toBe(expectedSelector('AlreadyBound()'));
    expect(REGISTRY_ERROR_SELECTORS.AgeExceeded).toBe(expectedSelector('AgeExceeded()'));
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

  it('maps AlreadyBound and AgeExceeded selectors', () => {
    expect(classifyRegistryRevert(REGISTRY_ERROR_SELECTORS.AlreadyBound)?.code).toBe(
      'registry.alreadyBound',
    );
    expect(classifyRegistryRevert(REGISTRY_ERROR_SELECTORS.AgeExceeded)?.code).toBe(
      'registry.ageExceeded',
    );
  });

  it('accepts selector with trailing ABI-encoded args', () => {
    const pad = '0'.repeat(64);
    const err = classifyRegistryRevert(REGISTRY_ERROR_SELECTORS.NullifierUsed + pad);
    expect(err?.code).toBe('registry.nullifierUsed');
  });

  it('returns null for unknown selector', () => {
    expect(classifyRegistryRevert('0xdeadbeef')).toBeNull();
    expect(classifyRegistryRevert('0xdeadbeef' + '0'.repeat(64))).toBeNull();
  });

  it('returns null for malformed input', () => {
    expect(classifyRegistryRevert(undefined)).toBeNull();
    expect(classifyRegistryRevert('')).toBeNull();
    expect(classifyRegistryRevert('not-hex')).toBeNull();
  });
});

describe('classifyWalletRevert', () => {
  it('recognizes NullifierUsed in an Error.message (decoded wallet shape)', () => {
    const err = new Error('execution reverted: NullifierUsed()');
    expect(classifyWalletRevert(err)?.code).toBe('registry.nullifierUsed');
  });

  it('recognizes RootMismatch, AlreadyBound, AgeExceeded via message', () => {
    expect(classifyWalletRevert(new Error('RootMismatch'))?.code).toBe('registry.rootMismatch');
    expect(classifyWalletRevert(new Error('AlreadyBound'))?.code).toBe('registry.alreadyBound');
    expect(classifyWalletRevert(new Error('AgeExceeded'))?.code).toBe('registry.ageExceeded');
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

describe('assertRegisterArgsShape', () => {
  const validPk = ('0x04' + 'ab'.repeat(64)) as `0x04${string}`;
  const validProof = {
    a: ['1', '2'] as [string, string],
    b: [
      ['3', '4'],
      ['5', '6'],
    ] as [[string, string], [string, string]],
    c: ['7', '8'] as [string, string],
  };
  const validSignals = Array.from({ length: 14 }, (_, i) => String(i));

  it('accepts a well-formed 14-signal payload', () => {
    const args: RegisterArgs = { pk: validPk, proof: validProof, publicSignals: validSignals };
    expect(() => assertRegisterArgsShape(args)).not.toThrow();
  });

  it('rejects pk with wrong length', () => {
    const args = { pk: ('0x04' + 'ab'.repeat(32)) as `0x04${string}`, proof: validProof, publicSignals: validSignals };
    expect(() => assertRegisterArgsShape(args)).toThrowError(
      expect.objectContaining({ code: 'binding.pkMismatch' }) as unknown as Error,
    );
  });

  it('rejects pk missing 0x04 prefix', () => {
    const args = {
      pk: ('0x03' + 'ab'.repeat(64)) as unknown as `0x04${string}`,
      proof: validProof,
      publicSignals: validSignals,
    };
    expect(() => assertRegisterArgsShape(args)).toThrowError(
      expect.objectContaining({ code: 'binding.pkMismatch' }) as unknown as Error,
    );
  });

  it('rejects publicSignals != 14 elements', () => {
    const args: RegisterArgs = {
      pk: validPk,
      proof: validProof,
      publicSignals: Array.from({ length: 13 }, (_, i) => String(i)),
    };
    expect(() => assertRegisterArgsShape(args)).toThrowError(
      expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error,
    );
  });

  it('rejects malformed proof arrays', () => {
    const bad = {
      pk: validPk,
      proof: { ...validProof, b: [['3', '4']] as unknown as typeof validProof.b },
      publicSignals: validSignals,
    } as RegisterArgs;
    expect(() => assertRegisterArgsShape(bad)).toThrowError(
      expect.objectContaining({ code: 'witness.fieldTooLong' }) as unknown as Error,
    );
  });
});
