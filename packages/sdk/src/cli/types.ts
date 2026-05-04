// zkqes CLI-server client types — shared by `detectCli` (GET /status) and
// `proveViaCli` (POST /prove). Mirror the V1 HTTP API contract frozen in
// `docs/superpowers/plans/2026-05-03-qkb-cli-server-orchestration.md`
// §1.1 (which inherits verbatim from the helper's helper-orchestration
// §1.1). Any drift here is a cross-worker breaking change — needs lead
// sign-off + circuits-eng cross-read.
//
// V1 supports `circuit: 'v5.2'` only. The `circuit` field is kept as a
// generic string in the type so a future V5.3 server can be statically
// detected and refused by `detectCli` without a SDK rebuild gate.
import type { Groth16Proof } from '../core/index.js';

/**
 * GET /status response payload. Returned by the CLI server to advertise
 * readiness, version, and download progress (during first-run zkey
 * fetch). The `downloadProgress` field is non-null only while
 * `zkeyLoaded === false` — `detectCli` rejects sessions where
 * `zkeyLoaded === false` regardless, so consumers need not parse it.
 */
export interface CliStatus {
  /** Always true on a healthy server; absent on networking failures. */
  readonly ok: boolean;
  /** Server semver, e.g. `"zkqes-cli@1.0.0"`. */
  readonly version: string;
  /** Hard-coded `"v5.2"` in V1 — `detectCli` rejects anything else. */
  readonly circuit: string;
  /** False during first-run download; `detectCli` rejects when false. */
  readonly zkeyLoaded: boolean;
  /** True iff a `/prove` is currently in flight on this server. */
  readonly busy: boolean;
  /** Monotonic counter — useful for UI metrics, not for control flow. */
  readonly provesCompleted: number;
  /** Server uptime in seconds, integer. */
  readonly uptimeSec: number;
  /**
   * Present iff `zkeyLoaded === false`. Reports first-run zkey fetch
   * progress so the install page can surface a progress bar. `null`
   * once the zkey is cached on disk.
   */
  readonly downloadProgress: {
    readonly downloadedBytes: number;
    readonly totalBytes: number;
  } | null;
}

/**
 * Per-stage timings reported by the CLI server alongside a successful
 * `/prove` response. Cosmetic only — not load-bearing for the
 * register flow's correctness, but useful for tuning UI status copy
 * ("rapidsnark prove: 12.94s") + comparing against in-browser baseline.
 */
export interface CliTimings {
  readonly wtnsCalculateSec: number;
  readonly groth16ProveSec: number;
  readonly groth16VerifySec: number;
  readonly totalSec: number;
}

/**
 * Result of `proveViaCli`. Wraps the CLI server's `/prove` response
 * with a `source` discriminator so the consuming pipeline can branch
 * on whether the proof came from CLI or browser fallback. The
 * orchestration §1.6 contract pins `source` as the only post-prove
 * difference between the two paths.
 *
 * **`verifyOk` is NOT trustworthy alone.** The browser MUST re-verify
 * the proof against the local vkey. The field is surfaced for the
 * cosmetic UI ("CLI verified locally") but never substitutes for the
 * browser's own verifyGroth16 check.
 */
export interface CliProveResult {
  readonly proof: Groth16Proof;
  /** 22 decimal-string field elements per V5.2 layout. */
  readonly publicSignals: string[];
  /** Server-side post-prove sanity. NOT trusted alone — re-verify. */
  readonly verifyOk: boolean;
  readonly timings: CliTimings;
  /** Discriminator: 'cli' from `proveViaCli`, 'browser' from fallback. */
  readonly source: 'cli' | 'browser';
}
