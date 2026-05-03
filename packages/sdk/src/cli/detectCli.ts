// `detectCli` — non-blocking probe for a running QKB CLI server.
//
// Called once at /v5/registerV5 mount + on tab visibility change. Hits
// the CLI server's `GET /status` endpoint with a tight 500 ms timeout
// so a missing server doesn't perceptibly delay the page render. The
// returned `CliStatus | null` lets callers branch on presence without
// parsing exceptions.
//
// Validation discipline (per `useCliPresence` invariant V5.16-V5.19):
//   - any network/CORS error                  → null (CLI unreachable)
//   - non-2xx response                         → null (CLI broken/unhealthy)
//   - JSON parse fail                          → null (not our server)
//   - `circuit !== 'v5.2'`                     → null (wrong circuit version)
//   - `zkeyLoaded === false`                   → null (downloading; not ready)
//   - otherwise                                → `CliStatus`
//
// We do NOT differentiate "no CLI" from "CLI on wrong port" or
// "CLI mid-download" — for the banner UX, "absent or not-ready" is the
// same actionable state ("install or wait, then retry"). The
// `downloadProgress` field on `CliStatus` is surfaced through to
// callers that want it (e.g. the /ua/cli install page can poll and
// show progress when zkeyLoaded transitions); the register flow only
// cares about ready-or-not.
//
// HTTP API contract reference: orchestration §1.1.
import type { CliStatus } from './types.js';

/** Hard-coded localhost endpoint. Origin-pinned by the server side
 *  (cross-origin POST /prove rejected with 403). Status path is open
 *  to any origin — used precisely for browser detection. */
export const CLI_STATUS_URL = 'http://127.0.0.1:9080/status';

/** Probe timeout. Smaller is better for first-paint; 500 ms is the
 *  spec-pinned upper bound — a healthy local server resolves in <50 ms,
 *  so a 500 ms ceiling is generous. AbortController is used so the
 *  underlying fetch is actually cancelled, not just ignored. */
export const CLI_DETECT_TIMEOUT_MS = 500;

/** Hard-coded V1 circuit. The `circuit` field is enforced strictly so a
 *  V5.1 helper still listening on :9080 from a previous setup doesn't
 *  silently take over the V5.2 register flow. */
export const CLI_EXPECTED_CIRCUIT = 'v5.2';

export async function detectCli(): Promise<CliStatus | null> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), CLI_DETECT_TIMEOUT_MS);
  try {
    const res = await fetch(CLI_STATUS_URL, {
      method: 'GET',
      signal: ctl.signal,
      // No credentials, no cache — we want a fresh probe every call.
      credentials: 'omit',
      cache: 'no-store',
    });
    if (!res.ok) return null;
    const raw: unknown = await res.json().catch(() => null);
    if (!isPlausibleCliStatus(raw)) return null;
    if (raw.circuit !== CLI_EXPECTED_CIRCUIT) return null;
    if (!raw.zkeyLoaded) return null;
    return raw;
  } catch {
    // AbortError, TypeError ('Failed to fetch'), CORS blockage, JSON
    // throw — every failure resolves to "no CLI present", uniformly.
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Narrow runtime guard against the CliStatus shape. Cheap shape check
 * at the boundary — the server is trusted to follow its own contract,
 * but we still validate top-level field presence + type so a stray
 * response from a misconfigured proxy/devtools can't crash the React
 * tree downstream.
 */
function isPlausibleCliStatus(value: unknown): value is CliStatus {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.ok === 'boolean' &&
    typeof v.version === 'string' &&
    typeof v.circuit === 'string' &&
    typeof v.zkeyLoaded === 'boolean' &&
    typeof v.busy === 'boolean' &&
    typeof v.provesCompleted === 'number' &&
    typeof v.uptimeSec === 'number'
  );
}
