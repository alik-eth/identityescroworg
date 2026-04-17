import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { useChainDeployment } from '../../src/hooks/use-chain-deployment';

const SAMPLE = {
  chainId: 31337,
  rpc: 'http://127.0.0.1:8545',
  registry: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
  arbitrators: {
    authority: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
    authorityAuthority: '0xf39Fd6e51aad88F6F4ce6aB8827279cfFFb92266',
  },
};

describe('useChainDeployment', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('returns localStorage payload when present without touching fetch', async () => {
    localStorage.setItem('qie.demo.local.json', JSON.stringify(SAMPLE));
    const fetchSpy = vi.fn();
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
    const { result } = renderHook(() => useChainDeployment());
    await waitFor(() => expect(result.current.status).toBe('ready'));
    expect(result.current.deployment).toEqual(SAMPLE);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('falls back to fetching /local.json and caches to localStorage', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => SAMPLE,
    });
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
    const { result } = renderHook(() => useChainDeployment());
    await waitFor(() => expect(result.current.status).toBe('ready'));
    expect(result.current.deployment).toEqual(SAMPLE);
    expect(fetchSpy).toHaveBeenCalledWith('/local.json', expect.any(Object));
    expect(JSON.parse(localStorage.getItem('qie.demo.local.json')!)).toEqual(SAMPLE);
  });

  it('returns missing state when fetch 404s and localStorage is empty', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: false, status: 404 });
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
    const { result } = renderHook(() => useChainDeployment());
    await waitFor(() => expect(result.current.status).toBe('missing'));
    expect(result.current.deployment).toBeNull();
  });
});
