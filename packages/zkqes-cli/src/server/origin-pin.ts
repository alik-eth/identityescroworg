// Origin-pin gate for the localhost prove API.
//
// Per orchestration plan §1.1, the helper accepts requests only from the
// configured `allowedOrigin` (production: `https://app.zkqes.org`).
// `/status` is exempt — it's used by browser-side detection from any
// origin (e.g., a dev `http://localhost:5173` that wants to probe whether
// a helper is running before deciding whether to surface the
// "fast prover available" UI).  `/prove` is always pinned: a malicious
// tab cannot co-opt the local helper to forge a proof against the user's
// witness.
//
// Empty Origin (e.g., curl smoke from CLI without -H "Origin: …") is
// treated as exempt for the same reason as /status — it can't be a
// hostile browser request.  The threat model is "browser tab on a
// different origin," and browsers always set Origin on cross-origin
// fetches.

export interface OriginGateInput {
  readonly url: string | undefined;
  readonly origin: string;
  readonly allowedOrigin: string;
}

export interface OriginGateResult {
  readonly allowed: boolean;
  readonly reason?: 'origin-mismatch';
}

const STATUS_PATHS = new Set(['/status']);

export function originGate(input: OriginGateInput): OriginGateResult {
  const { url, origin, allowedOrigin } = input;
  if (url !== undefined && STATUS_PATHS.has(url)) return { allowed: true };
  if (origin === '') return { allowed: true };
  if (origin === allowedOrigin) return { allowed: true };
  return { allowed: false, reason: 'origin-mismatch' };
}

export function originRejectionPayload(
  origin: string,
  allowedOrigin: string,
): { error: string; allowed: string; got: string } {
  return { error: 'origin not allowed', allowed: allowedOrigin, got: origin };
}

export function corsHeaders(
  origin: string,
  allowedOrigin: string,
): Record<string, string> {
  // Echo back the Origin only on a match, never `*`.  A wildcard echo
  // would defeat the origin pin from the browser's CORS-check standpoint
  // (browser would accept the response cross-origin even though the
  // helper rejected the underlying request).  Empty string when no
  // match — browser then refuses to expose the response to JS.
  return {
    'Access-Control-Allow-Origin': origin === allowedOrigin ? origin : '',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Private-Network': 'true', // Chrome 117+ PNA
    Vary: 'Origin',
  };
}
