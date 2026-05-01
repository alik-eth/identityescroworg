/**
 * Thin wrapper over `snarkjs.groth16.verify`.
 *
 * Used in two contexts:
 *   1. Post-prove sanity check on browser side — fail fast before submitting
 *      a malformed proof to `register()` (which would revert and burn gas).
 *   2. Regression test against the pumped ceremony artifacts (vkey +
 *      proof-sample + public-sample) — catches drift in the §8 stub
 *      ceremony output.
 *
 * `snarkjs` is an optional peer dep; this module is only imported when the
 * consumer has installed it. Verify is cheap (~ms) and runs on the main
 * thread without OOM concerns; only `fullProve` needs Worker isolation.
 */
// @ts-expect-error — snarkjs ships no .d.ts of its own; consumer installs it.
import { groth16 } from 'snarkjs';
import type { Groth16Proof } from '../core/index.js';

export interface VerifyInputs {
  /** Parsed `verification_key.json` content (snarkjs's vkey shape). */
  readonly verificationKey: Record<string, unknown>;
  /** Decimal-string field elements — output of `proveV5().publicSignals`. */
  readonly publicSignals: readonly string[];
  /** Groth16 proof tuple — output of `proveV5().proof`. */
  readonly proof: Groth16Proof;
}

/**
 * Verify a Groth16 proof against a verification key. Returns `true` iff
 * the proof verifies cleanly. Throws only on snarkjs-internal errors
 * (malformed vkey shape, etc.); a non-verifying proof returns `false`.
 */
export async function verifyGroth16(input: VerifyInputs): Promise<boolean> {
  return (await groth16.verify(
    input.verificationKey as never,
    input.publicSignals as never,
    input.proof as never,
  )) as boolean;
}
