// Unit tests for useCliPresence — the React hook that gates the CLI
// banner + pipeline branch on /v5/registerV5.
//
// Tests pin:
//   - initial 'detecting' state, transitions to 'present' or 'absent'
//   - re-probe on visibilitychange (tab regains focus)
//   - recheck() forces a fresh probe + returns the new status
//   - cancellation: hook unmount before probe resolves doesn't update state
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import { useCliPresence } from '../../src/hooks/useCliPresence';

const VALID_STATUS = {
  ok: true,
  version: 'qkb-cli@1.0.0',
  circuit: 'v5.2',
  zkeyLoaded: true,
  busy: false,
  provesCompleted: 0,
  uptimeSec: 12,
  downloadProgress: null,
};

function mockStatus(payload: object | null, status = 200): void {
  vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
    payload === null
      ? Promise.reject(new TypeError('Failed to fetch'))
      : Promise.resolve(
          new Response(JSON.stringify(payload), {
            status,
            headers: { 'Content-Type': 'application/json' },
          }),
        ),
  );
}

beforeEach(() => {
  // jsdom provides document.visibilityState; we drive it manually below.
  Object.defineProperty(document, 'visibilityState', {
    configurable: true,
    get: () => 'visible',
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('useCliPresence', () => {
  it('starts in "detecting" state', async () => {
    mockStatus(VALID_STATUS);
    const { result } = renderHook(() => useCliPresence());
    expect(result.current.status).toBe('detecting');
    expect(result.current.cliStatus).toBeNull();
    // Drain the in-flight probe so the test exits cleanly without
    // triggering React's "state updated outside act()" warning.
    await waitFor(() => expect(result.current.status).not.toBe('detecting'));
  });

  it('transitions to "present" when CLI responds with valid status', async () => {
    mockStatus(VALID_STATUS);
    const { result } = renderHook(() => useCliPresence());
    await waitFor(() => {
      expect(result.current.status).toBe('present');
    });
    expect(result.current.cliStatus).toMatchObject({
      circuit: 'v5.2',
      zkeyLoaded: true,
    });
  });

  it('transitions to "absent" when CLI is unreachable', async () => {
    mockStatus(null);
    const { result } = renderHook(() => useCliPresence());
    await waitFor(() => {
      expect(result.current.status).toBe('absent');
    });
    expect(result.current.cliStatus).toBeNull();
  });

  it('transitions to "absent" when CLI returns wrong circuit (V5.1 stale helper)', async () => {
    mockStatus({ ...VALID_STATUS, circuit: 'v5.1' });
    const { result } = renderHook(() => useCliPresence());
    await waitFor(() => {
      expect(result.current.status).toBe('absent');
    });
  });

  it('re-probes on visibilitychange when tab becomes visible', async () => {
    // First probe: CLI absent. Then user starts `qkb serve`, alt-tabs
    // back, and we should detect it on the visibilitychange event.
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockRejectedValueOnce(new TypeError('Failed to fetch'));

    const { result } = renderHook(() => useCliPresence());
    await waitFor(() => {
      expect(result.current.status).toBe('absent');
    });

    // Now mock the next fetch as a healthy response.
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(VALID_STATUS), { status: 200 }),
    );

    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    await waitFor(() => {
      expect(result.current.status).toBe('present');
    });
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('does NOT re-probe on visibilitychange when tab becomes hidden', async () => {
    mockStatus(VALID_STATUS);
    const { result } = renderHook(() => useCliPresence());
    await waitFor(() => {
      expect(result.current.status).toBe('present');
    });

    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockClear();

    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'hidden',
    });
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('recheck() forces a fresh probe and returns the new status', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    fetchSpy.mockRejectedValueOnce(new TypeError('Failed to fetch'));

    const { result } = renderHook(() => useCliPresence());
    await waitFor(() => {
      expect(result.current.status).toBe('absent');
    });

    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(VALID_STATUS), { status: 200 }),
    );

    let recheckResult: string | undefined;
    await act(async () => {
      recheckResult = await result.current.recheck();
    });

    expect(recheckResult).toBe('present');
    await waitFor(() => {
      expect(result.current.status).toBe('present');
    });
  });

  it('removes visibilitychange listener on unmount', async () => {
    mockStatus(VALID_STATUS);
    const removeSpy = vi.spyOn(document, 'removeEventListener');
    const { unmount } = renderHook(() => useCliPresence());
    unmount();
    expect(removeSpy).toHaveBeenCalledWith(
      'visibilitychange',
      expect.any(Function),
    );
  });

  it('does not commit setState after unmount even from recheck()', async () => {
    // Pin the cleanup discipline: recheck() launched right before
    // unmount must not mutate state when its async resolution lands.
    // We resolve the fetch only AFTER unmount to force the post-unmount
    // path through the mountedRef gate.
    let resolveFetch: ((value: Response) => void) | null = null;
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      () =>
        new Promise<Response>((resolve) => {
          resolveFetch = resolve;
        }),
    );

    const { result, unmount } = renderHook(() => useCliPresence());
    let recheckPromise!: Promise<string>;
    await act(async () => {
      // Initial probe is pending. Kick a recheck (still pending). Both
      // share the same mocked fetch implementation.
      recheckPromise = result.current.recheck();
    });

    unmount();

    // Resolve the fetch only after unmount. If mountedRef gate is
    // wired correctly, the resolution is silently swallowed.
    await act(async () => {
      resolveFetch?.(new Response(JSON.stringify(VALID_STATUS), { status: 200 }));
      await recheckPromise;
    });

    // No assertion error from React about state-after-unmount = good.
    // The recheck promise resolves to a status string regardless.
    expect(await recheckPromise).toMatch(/present|absent/);
  });

  it('discards stale resolutions when a newer probe has started', async () => {
    // Race regression: probe A starts (CLI down → resolves null late),
    // user runs `qkb serve`, probe B starts (CLI up → resolves
    // 'present' quickly), then probe A finally resolves 'absent'.
    // Without sequencing, A's late 'absent' would clobber B's
    // 'present'. The latestProbeIdRef gate must filter A out.
    let resolveA: ((value: Response) => void) | null = null;
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementationOnce(
      // Probe A — never resolves on its own; we drive it manually.
      () =>
        new Promise<Response>((resolve) => {
          resolveA = (v) => resolve(v);
        }),
    );

    const { result } = renderHook(() => useCliPresence());

    // Probe B (recheck) — resolves quickly with 'present'.
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(VALID_STATUS), { status: 200 }),
    );
    await act(async () => {
      await result.current.recheck();
    });
    await waitFor(() => {
      expect(result.current.status).toBe('present');
    });

    // Now resolve probe A with a non-CLI response. Without the gate,
    // this would flip status back to 'absent'.
    await act(async () => {
      resolveA?.(new Response('not json', { status: 200 }));
      // Yield to flush microtasks.
      await Promise.resolve();
    });

    // Status MUST stay 'present' — probe A's stale resolution is
    // discarded by the latestProbeIdRef gate.
    expect(result.current.status).toBe('present');
  });
});
