// `useCliPresence` — React hook that polls the QKB CLI server's
// /status endpoint at mount + on tab visibility transitions, returning
// a discriminated state for the UI to branch on.
//
// Plan ref: docs/superpowers/plans/2026-05-03-qkb-cli-server-web-eng.md T2.
//
// Polling discipline (CLAUDE.md V5.19):
//   - mount once, debounced — no setInterval-driven polling. The CLI
//     server's `busy` flag is observable through /status; a timer-driven
//     poll would pollute that signal for any UI that watches it.
//   - re-poll on `visibilitychange` (tab regains focus) — covers the
//     "user started qkb serve while the page was open" flow without
//     needing a manual refresh.
//   - 500 ms timeout per probe via detectCli's AbortController; never
//     blocks first paint.
//
// State machine:
//   'detecting' — initial render through the first detectCli resolution
//   'present'   — fetch succeeded + circuit:'v5.2' + zkeyLoaded:true
//   'absent'    — every other outcome (network err, wrong circuit,
//                 not-ready, malformed body — all same actionable state)
import { useCallback, useEffect, useRef, useState } from 'react';
import { detectCli, type CliStatus } from '@zkqes/sdk';

export type CliPresenceStatus = 'detecting' | 'present' | 'absent';

export interface UseCliPresenceReturn {
  /** Discriminated state — 'detecting' until first probe resolves. */
  readonly status: CliPresenceStatus;
  /** Last successful CliStatus payload, or null if never present. */
  readonly cliStatus: CliStatus | null;
  /**
   * Force-refresh the probe. Returns the status this probe observed.
   *
   * **Concurrency caveat.** With overlapping `recheck()` calls (e.g.
   * a user double-clicking the install page's "Re-check" button), the
   * earlier promise resolves with its own observed status — which may
   * differ from the hook's committed state if a later probe started
   * mid-flight. The hook's STATE is always coherent (via the
   * latestProbeIdRef gate), but the per-call PROMISE return value
   * reflects "what THIS probe saw," not "the freshest status."
   * Callers that need the freshest observation should read `status`
   * via re-render rather than chain on the recheck return value.
   */
  readonly recheck: () => Promise<CliPresenceStatus>;
}

export function useCliPresence(): UseCliPresenceReturn {
  const [status, setStatus] = useState<CliPresenceStatus>('detecting');
  const [cliStatus, setCliStatus] = useState<CliStatus | null>(null);

  // Sequencing + cleanup discipline. detectCli has a 500 ms timeout so
  // probes don't pile up indefinitely, but we still need:
  //   (1) a mounted flag so async resolutions after unmount don't
  //       invoke setState — addresses the React "memory leak" warning
  //       and prevents stale state in fast-route-switching flows.
  //   (2) a probe-ID counter so out-of-order resolutions don't flip
  //       the hook back to a stale value. Concrete failure mode this
  //       guards against: mount probe starts while CLI is down → user
  //       runs `qkb serve` → clicks "Re-check" → recheck() resolves
  //       'present' → original slow probe finally resolves 'null' →
  //       hook flips back to 'absent' over a fresher 'present'.
  const mountedRef = useRef(true);
  const latestProbeIdRef = useRef(0);

  const runProbe = useCallback(async (): Promise<CliPresenceStatus> => {
    const myId = ++latestProbeIdRef.current;
    const result = await detectCli();
    // Discard stale resolutions: only commit if (a) still mounted AND
    // (b) no newer probe has started since this one.
    if (!mountedRef.current || latestProbeIdRef.current !== myId) {
      return result === null ? 'absent' : 'present';
    }
    if (result === null) {
      setCliStatus(null);
      setStatus('absent');
      return 'absent';
    }
    setCliStatus(result);
    setStatus('present');
    return 'present';
  }, []);

  useEffect(() => {
    mountedRef.current = true;

    // Initial probe at mount. Reset to 'detecting' so consumers see the
    // detecting → present|absent transition rather than a flash of the
    // previous state when the hook re-mounts (e.g. route navigation).
    setStatus('detecting');
    void runProbe();

    // Re-probe on visibilitychange. The contract here is "the user
    // started `qkb serve` in another window, then alt-tabbed back" —
    // we want the banner to disappear without a manual page refresh.
    // Visibility-driven polling is bounded by tab activity, so it
    // doesn't pollute the CLI's `busy` flag during prove operations
    // (CLAUDE.md V5.19).
    const onVisibility = (): void => {
      if (document.visibilityState !== 'visible') return;
      void runProbe();
    };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      mountedRef.current = false;
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [runProbe]);

  return { status, cliStatus, recheck: runProbe };
}
