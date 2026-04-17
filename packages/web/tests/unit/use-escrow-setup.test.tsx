import { describe, it, expect, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { useEscrowSetup } from '../../src/features/qie/use-escrow-setup';

describe('useEscrowSetup', () => {
  it('POSTs one body per agent and transitions idle -> submitting -> done', async () => {
    const calls: Array<{ url: string; body: unknown }> = [];
    const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, body: JSON.parse(String(init?.body ?? 'null')) });
      return new Response('{}', { status: 200 });
    });

    const { result } = renderHook(() => useEscrowSetup({ fetchImpl }));
    expect(result.current.state.phase).toBe('idle');

    await act(async () => {
      await result.current.submit({
        escrowId: '0xabc' as `0x${string}`,
        agents: [
          { agent_id: 'a', endpoint: 'https://a.example/' },
          { agent_id: 'b', endpoint: 'https://b.example/' },
        ],
        bodiesByAgentId: {
          a: { escrowId: '0xabc', idx: 0 },
          b: { escrowId: '0xabc', idx: 1 },
        },
      });
    });

    await waitFor(() => expect(result.current.state.phase).toBe('done'));
    expect(result.current.state.escrowId).toBe('0xabc');
    expect(result.current.state.acks).toEqual({ a: 'ok', b: 'ok' });
    expect(calls).toHaveLength(2);
    expect(calls[0]!.url).toBe('https://a.example/escrow');
    expect(calls[1]!.url).toBe('https://b.example/escrow');
  });

  it('surfaces failure with an agent id in the error', async () => {
    const fetchImpl = vi.fn(async (url: string) =>
      url.includes('b.example')
        ? new Response('nope', { status: 500 })
        : new Response('{}', { status: 200 }),
    );

    const { result } = renderHook(() => useEscrowSetup({ fetchImpl }));
    await act(async () => {
      await result.current.submit({
        escrowId: '0xabc' as `0x${string}`,
        agents: [
          { agent_id: 'a', endpoint: 'https://a.example/' },
          { agent_id: 'b', endpoint: 'https://b.example/' },
        ],
        bodiesByAgentId: { a: {}, b: {} },
      });
    });
    await waitFor(() => expect(result.current.state.phase).toBe('error'));
    expect(result.current.state.error).toMatch(/agent b/);
    expect(result.current.state.acks.a).toBe('ok');
    expect(result.current.state.acks.b).toBe('pending');
  });

  it('rejects submission with a missing body', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200 }));
    const { result } = renderHook(() => useEscrowSetup({ fetchImpl }));
    await act(async () => {
      await result.current.submit({
        escrowId: '0xabc' as `0x${string}`,
        agents: [{ agent_id: 'a', endpoint: 'https://a.example/' }],
        bodiesByAgentId: {},
      });
    });
    await waitFor(() => expect(result.current.state.phase).toBe('error'));
    expect(result.current.state.error).toMatch(/missing body for agent a/);
  });
});
