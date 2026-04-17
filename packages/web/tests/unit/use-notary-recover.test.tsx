import { describe, it, expect, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { useNotaryRecover } from '../../src/hooks/use-notary-recover';

describe('useNotaryRecover', () => {
  it('posts the on_behalf_of wire format to every agent and returns shares', async () => {
    const captured: Array<{ url: string; body: unknown }> = [];
    const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
      captured.push({ url, body: JSON.parse(String(init?.body)) });
      return new Response(JSON.stringify({ share_ciphertext: 'aa' }), { status: 200 });
    });

    const { result } = renderHook(() => useNotaryRecover({ fetchImpl }));
    await act(async () => {
      await result.current.run({
        escrowId: '0xabc' as `0x${string}`,
        recipient_pk: '0x01' as `0x${string}`,
        arbitrator_unlock_tx: '0x02' as `0x${string}`,
        notary_cert: '0xcc' as `0x${string}`,
        notary_sig: '0xdd' as `0x${string}`,
        agents: [
          { agent_id: 'a', endpoint: 'https://a.example/' },
          { agent_id: 'b', endpoint: 'https://b.example/' },
        ],
      });
    });
    await waitFor(() => expect(result.current.state.phase).toBe('done'));
    expect(result.current.state.shares).toHaveLength(2);
    expect(captured).toHaveLength(2);
    expect(captured[0]!.url).toBe('https://a.example/escrow/0xabc/release');
    expect(captured[1]!.url).toBe('https://b.example/escrow/0xabc/release');
    expect(captured[0]!.body).toEqual({
      recipient_pk: '0x01',
      arbitrator_unlock_tx: '0x02',
      on_behalf_of: {
        recipient_pk: '0x01',
        notary_cert: '0xcc',
        notary_sig: '0xdd',
      },
    });
  });

  it('records HTTP and network failures per-agent', async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.includes('a.example')) throw new Error('offline');
      if (url.includes('b.example')) return new Response('forbidden', { status: 403 });
      return new Response(JSON.stringify({ share: 'ok' }), { status: 200 });
    });
    const { result } = renderHook(() => useNotaryRecover({ fetchImpl }));
    await act(async () => {
      await result.current.run({
        escrowId: '0xabc' as `0x${string}`,
        recipient_pk: '0x01' as `0x${string}`,
        arbitrator_unlock_tx: '0x02' as `0x${string}`,
        notary_cert: '0xcc' as `0x${string}`,
        notary_sig: '0xdd' as `0x${string}`,
        agents: [
          { agent_id: 'a', endpoint: 'https://a.example/' },
          { agent_id: 'b', endpoint: 'https://b.example/' },
          { agent_id: 'c', endpoint: 'https://c.example/' },
        ],
        threshold: 1,
      });
    });
    await waitFor(() => expect(result.current.state.phase).toBe('done'));
    expect(result.current.state.failures).toEqual({ a: 'network', b: 403 });
    expect(result.current.state.shares).toHaveLength(1);
    expect(result.current.state.shares[0]!.agent_id).toBe('c');
  });

  it('surfaces QIE_ESCROW_WRONG_STATE on 409 from every agent', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 409 }));
    const { result } = renderHook(() => useNotaryRecover({ fetchImpl }));
    await act(async () => {
      await result.current.run({
        escrowId: '0xabc' as `0x${string}`,
        recipient_pk: '0x01' as `0x${string}`,
        arbitrator_unlock_tx: '0x02' as `0x${string}`,
        notary_cert: '0xcc' as `0x${string}`,
        notary_sig: '0xdd' as `0x${string}`,
        agents: [{ agent_id: 'a', endpoint: 'https://a.example/' }],
      });
    });
    await waitFor(() => expect(result.current.state.phase).toBe('error'));
    expect(result.current.state.wrongState).toBe(true);
    expect(result.current.state.error).toMatch(/QIE_ESCROW_WRONG_STATE/);
  });

  it('errors out when threshold is not met', async () => {
    const fetchImpl = vi.fn(async () => new Response('no', { status: 500 }));
    const { result } = renderHook(() => useNotaryRecover({ fetchImpl }));
    await act(async () => {
      await result.current.run({
        escrowId: '0xabc' as `0x${string}`,
        recipient_pk: '0x01' as `0x${string}`,
        arbitrator_unlock_tx: '0x02' as `0x${string}`,
        notary_cert: '0xcc' as `0x${string}`,
        notary_sig: '0xdd' as `0x${string}`,
        agents: [{ agent_id: 'a', endpoint: 'https://a.example/' }],
      });
    });
    await waitFor(() => expect(result.current.state.phase).toBe('error'));
    expect(result.current.state.error).toMatch(/insufficient shares/);
  });
});
