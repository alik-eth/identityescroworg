import { describe, it, expect, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { useEscrowRecover } from '../../src/features/qie/use-escrow-recover';

describe('useEscrowRecover', () => {
  it('collects shares up to threshold and stops early', async () => {
    const calls: string[] = [];
    const fetchImpl = vi.fn(async (url: string) => {
      calls.push(url);
      return new Response(JSON.stringify({ share: url, encR: '0xbeef' }), { status: 200 });
    });

    const { result } = renderHook(() => useEscrowRecover({ fetchImpl }));
    await act(async () => {
      await result.current.recover({
        escrowId: '0xabc' as `0x${string}`,
        threshold: 2,
        agents: [
          { agent_id: 'a', endpoint: 'https://a.example/' },
          { agent_id: 'b', endpoint: 'https://b.example/' },
          { agent_id: 'c', endpoint: 'https://c.example/' },
        ],
        body: { recipient_pk: '0x00' },
      });
    });
    await waitFor(() => expect(result.current.state.phase).toBe('done'));
    expect(result.current.state.shares).toHaveLength(2);
    expect(result.current.state.encR).toBe('0xbeef');
    expect(calls).toHaveLength(2);
    expect(calls[0]).toBe('https://a.example/recover/0xabc');
  });

  it('skips agents that return non-2xx and reports insufficient shares', async () => {
    const fetchImpl = vi.fn(async (url: string) =>
      url.includes('a.example')
        ? new Response('{}', { status: 500 })
        : new Response(JSON.stringify({ share: 'ok' }), { status: 200 }),
    );
    const { result } = renderHook(() => useEscrowRecover({ fetchImpl }));
    await act(async () => {
      await result.current.recover({
        escrowId: '0xabc' as `0x${string}`,
        threshold: 2,
        agents: [
          { agent_id: 'a', endpoint: 'https://a.example/' },
          { agent_id: 'b', endpoint: 'https://b.example/' },
        ],
        body: {},
      });
    });
    await waitFor(() => expect(result.current.state.phase).toBe('error'));
    expect(result.current.state.error).toMatch(/insufficient shares/);
    expect(result.current.state.shares).toHaveLength(1);
  });

  it('swallows network errors on a single agent and continues', async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.includes('a.example')) throw new Error('EAI_AGAIN');
      return new Response(JSON.stringify({ share: 'ok' }), { status: 200 });
    });
    const { result } = renderHook(() => useEscrowRecover({ fetchImpl }));
    await act(async () => {
      await result.current.recover({
        escrowId: '0xabc' as `0x${string}`,
        threshold: 1,
        agents: [
          { agent_id: 'a', endpoint: 'https://a.example/' },
          { agent_id: 'b', endpoint: 'https://b.example/' },
        ],
        body: {},
      });
    });
    await waitFor(() => expect(result.current.state.phase).toBe('done'));
    expect(result.current.state.shares).toHaveLength(1);
  });
});
