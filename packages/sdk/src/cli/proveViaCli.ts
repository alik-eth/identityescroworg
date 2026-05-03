// `proveViaCli` — POST a V5.2 witness to the running CLI server's
// `/prove` endpoint. Throws `CliProveError` on every non-2xx (caller
// then dispatches on `status` for the fallback decision).
//
// **Fallback discipline (orchestration §1.6 — load-bearing).**
// `proveViaCli` itself does NOT decide whether to fall back; it only
// surfaces the failure mode via the thrown error's `status`. The
// pipeline orchestration (`uaProofPipelineV5_2.ts`) reads `status` and
// applies:
//
//   - 4xx        → witness is invalid; browser would also fail.
//                  Surface verbatim, do NOT fall back. (Includes 403
//                  origin-pin, 400 malformed JSON, 422 validation.)
//   - 429        → server busy. ALSO no fallback — busy means another
//                  prove is running on the same server, browser prove
//                  would compete for the same CPU. UI should toast and
//                  let the user retry once the prior prove finishes.
//   - 5xx        → rapidsnark crash, OOM, manifest fail. Browser fallback.
//   - network    → CLI stopped mid-flow. Browser fallback.
//
// HTTP API contract reference: orchestration §1.1.
import type { WitnessV5_2 } from '../witness/v5/build-witness-v5_2.js';
import type { CliProveResult, CliTimings } from './types.js';
import type { Groth16Proof } from '../core/index.js';

/** Hard-coded localhost endpoint, matches `detectCli`'s. */
export const CLI_PROVE_URL = 'http://127.0.0.1:9080/prove';

/**
 * POST a witness to the CLI server, return its proof + public signals.
 * The returned `source: 'cli'` discriminator lets the pipeline branch
 * downstream against the browser-prove path (which returns 'browser').
 *
 * Throws `CliProveError` on:
 *   - non-2xx HTTP response (status carried verbatim)
 *   - network / CORS / abort failure (status = 0)
 *   - server returned a 2xx with malformed body (status = -1)
 *
 * No retry / fallback / timeout enforcement here — those are pipeline
 * concerns. This function's sole job is "speak the wire protocol or
 * raise a structured error."
 */
export async function proveViaCli(
  witness: WitnessV5_2,
): Promise<CliProveResult> {
  let res: Response;
  try {
    res = await fetch(CLI_PROVE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(witness),
      // No credentials — origin pin is enforced via the request's
      // Origin header (browser-set, can't be spoofed from JS).
      credentials: 'omit',
      cache: 'no-store',
    });
  } catch (err) {
    // Network failure, CORS denial, abort. Pipeline reads `status === 0`
    // as "no HTTP response received — fall back to browser."
    throw new CliProveError(
      0,
      err instanceof Error ? err.message : 'network error',
      err,
    );
  }

  if (!res.ok) {
    let bodyMsg = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { error?: unknown };
      if (typeof body.error === 'string') bodyMsg = body.error;
    } catch {
      // Body wasn't JSON or read failed — fall through with HTTP status
      // text. Don't mask the original status code.
    }
    throw new CliProveError(res.status, bodyMsg);
  }

  const raw: unknown = await res.json().catch(() => null);
  if (!isPlausibleProveResponse(raw)) {
    // Server returned 2xx but the body doesn't match the contract. Use
    // status = -1 so the pipeline can dispatch this distinctly from a
    // 4xx (which is "browser would also fail") and from 5xx (which is
    // "fall back to browser"). For the malformed-body case the right
    // call is still browser fallback (the CLI is broken in some way),
    // so the pipeline groups -1 with 5xx.
    throw new CliProveError(-1, 'CLI server returned malformed prove response');
  }
  return {
    proof: raw.proof,
    publicSignals: raw.publicSignals,
    verifyOk: raw.verifyOk,
    timings: raw.timings,
    source: 'cli',
  };
}

/**
 * Discriminated error class so the pipeline can dispatch on `status`
 * without parsing message text. Carries the original cause for the
 * network-error case (so devtools shows the underlying TypeError).
 *
 * Status sentinels:
 *   - 1..599  HTTP status code from the server response
 *   - 0       network / CORS / abort failure (no response received)
 *   - -1      server returned a 2xx with malformed body
 */
export class CliProveError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public override readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'CliProveError';
  }

  /** True iff the pipeline should fall back to browser prove. False for
   *  4xx/429 responses (witness invalid or server busy — fallback would
   *  fail or compete for the same CPU). */
  get shouldFallback(): boolean {
    if (this.status === 0 || this.status === -1) return true;
    if (this.status >= 500 && this.status < 600) return true;
    return false;
  }
}

interface ProveResponseShape {
  readonly proof: Groth16Proof;
  readonly publicSignals: string[];
  readonly verifyOk: boolean;
  readonly timings: CliTimings;
}

function isPlausibleProveResponse(value: unknown): value is ProveResponseShape {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  if (
    !v.proof ||
    typeof v.proof !== 'object' ||
    !Array.isArray(v.publicSignals) ||
    typeof v.verifyOk !== 'boolean' ||
    !v.timings ||
    typeof v.timings !== 'object'
  ) {
    return false;
  }
  // Tighten the proof shape: the snarkjs Groth16 output is a fixed
  // dict with pi_a / pi_b / pi_c arrays. Without this gate a server
  // that returns `{ proof: {} }` slips through as a successful prove
  // and the malformed value reaches the on-chain register() — the
  // contract would revert with a generic BadProof, losing the
  // diagnostic. Same posture as `proveV5`'s public-signal length
  // guard in src/prover/index.ts.
  const p = v.proof as Record<string, unknown>;
  if (
    !Array.isArray(p.pi_a) ||
    !Array.isArray(p.pi_b) ||
    !Array.isArray(p.pi_c)
  ) {
    return false;
  }
  // Spot-check publicSignals contains decimal strings, not arbitrary
  // shapes. The full 22-length check happens downstream via
  // `publicSignalsV5_2FromArray`; here we just want to ensure we have
  // the right rough shape.
  for (const s of v.publicSignals) {
    if (typeof s !== 'string') return false;
  }
  // Spot-check timings has the four expected number fields.
  const t = v.timings as Record<string, unknown>;
  if (
    typeof t.wtnsCalculateSec !== 'number' ||
    typeof t.groth16ProveSec !== 'number' ||
    typeof t.groth16VerifySec !== 'number' ||
    typeof t.totalSec !== 'number'
  ) {
    return false;
  }
  return true;
}
