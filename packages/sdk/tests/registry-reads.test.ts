import { describe, it, expect, vi } from 'vitest';
import type { PublicClient } from 'viem';
import { isVerified, nullifierOf } from '../src/registry/index.js';

const REGISTRY = '0x0000000000000000000000000000000000000001' as const;
const HOLDER   = '0x0000000000000000000000000000000000000002' as const;

function mockClient(reads: Record<string, unknown>): PublicClient {
  return {
    readContract: vi.fn(async (args: { functionName: string }) => {
      const v = reads[args.functionName];
      if (v === undefined) throw new Error(`no mock for ${args.functionName}`);
      return v;
    }),
  } as unknown as PublicClient;
}

describe('registry reads', () => {
  it('isVerified returns true when registry says yes', async () => {
    const c = mockClient({ isVerified: true });
    expect(await isVerified(c, REGISTRY, HOLDER)).toBe(true);
  });

  it('isVerified returns false when registry says no', async () => {
    const c = mockClient({ isVerified: false });
    expect(await isVerified(c, REGISTRY, HOLDER)).toBe(false);
  });

  it('nullifierOf returns the bytes32 value', async () => {
    const expected = '0x' + 'ab'.repeat(32);
    const c = mockClient({ nullifierOf: expected });
    expect(await nullifierOf(c, REGISTRY, HOLDER)).toBe(expected);
  });

  it('nullifierOf returns zero for unregistered holder', async () => {
    const c = mockClient({ nullifierOf: '0x' + '00'.repeat(32) });
    expect(await nullifierOf(c, REGISTRY, HOLDER)).toBe('0x' + '00'.repeat(32));
  });
});
