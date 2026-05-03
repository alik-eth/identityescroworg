// CLI-first prove dispatcher with structured browser fallback.
//
// Extracted from `uaProofPipelineV5_2.ts` so the fallback discipline
// (orchestration §1.6) can be unit-tested in isolation, without going
// through parseP7s / buildWitnessV5_2 / extractCertSignatureSeq /
// extractSpkiFromCertDer (which require either real CMS bytes or
// heavy SDK mocking — out of scope for testing the dispatch logic).
//
// Contract:
//   - cliPresent:true + 2xx                  → return source: 'cli'
//   - cliPresent:true + 4xx (not 429)        → re-throw CliProveError
//   - cliPresent:true + 429 / 5xx / 0 / -1   → fire onCliFallback,
//                                              fall through to browser
//   - cliPresent:false                       → skip CLI, run browser
//
// `runBrowser` is injected as a callback so this module is fully
// independent of the snarkjs Worker (the actual browser-side prover).
// In production, the pipeline passes a closure that drives
// `SnarkjsWorkerProver` + `proveV5`. In tests, callers pass a stub
// that returns a canned proof.
import {
  CliProveError,
  proveViaCli,
  type Groth16Proof,
  type WitnessV5_2,
} from '@qkb/sdk';

export interface RunProverOptions {
  /** Caller-side gate: try CLI first when true; skip CLI when false. */
  readonly cliPresent: boolean;
  /** Toast callback fired iff the CLI was attempted but a fallback-eligible
   *  failure mode occurred (5xx / 429 / 0 / -1). NOT fired on 4xx. */
  readonly onCliFallback?: (err: CliProveError) => void;
  /** Browser-prover closure. Owns the snarkjs Worker / proveV5 wiring. */
  readonly runBrowser: () => Promise<{
    proofRaw: Groth16Proof;
    publicSignalsRaw: string[];
  }>;
  /** Optional progress hook with the same shape as the pipeline's tick
   *  callback (stage label only — pct/elapsed handled by the pipeline). */
  readonly onProgress?: (message: string) => void;
}

export interface RunProverResult {
  readonly proofRaw: Groth16Proof;
  readonly publicSignalsRaw: string[];
  readonly source: 'cli' | 'browser';
}

export async function runCliFirstProver(
  witness: WitnessV5_2,
  opts: RunProverOptions,
): Promise<RunProverResult> {
  if (opts.cliPresent) {
    opts.onProgress?.('attempting CLI prove via localhost:9080');
    try {
      const result = await proveViaCli(witness);
      opts.onProgress?.('CLI prove complete');
      return {
        proofRaw: result.proof,
        publicSignalsRaw: [...result.publicSignals],
        source: 'cli',
      };
    } catch (err) {
      if (!(err instanceof CliProveError)) throw err;
      if (!err.shouldFallback) throw err;
      opts.onCliFallback?.(err);
      opts.onProgress?.('CLI fallback — running browser prover');
    }
  }

  const browser = await opts.runBrowser();
  return {
    proofRaw: browser.proofRaw,
    publicSignalsRaw: browser.publicSignalsRaw,
    source: 'browser',
  };
}
