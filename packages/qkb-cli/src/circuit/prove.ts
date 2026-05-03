// `proveWithRapidsnark` — wraps the iden3 rapidsnark prover binary's
// CLI surface (`prover <zkey> <wtns> <proof.json> <public.json>`) as a
// single async function.  Runs the binary in a child process, captures
// stderr for failure diagnosis, rejects on non-zero exit.
//
// The temp directory + .wtns lifecycle lives in the caller (the HTTP
// server) — keeping this module focused on the spawn-and-wait so it
// can be unit-tested with a fake binary.

import { spawn } from 'node:child_process';

export interface RapidsnarkProveInput {
  /** Absolute path to the rapidsnark `prover` binary (sidecar). */
  readonly binaryPath: string;
  /** Absolute path to the V5.2 zkey on disk. */
  readonly zkeyPath: string;
  /** Absolute path to the witness binary produced by snarkjs.wtns.calculate. */
  readonly wtnsPath: string;
  /** Absolute path where rapidsnark will write proof.json. */
  readonly proofOutPath: string;
  /** Absolute path where rapidsnark will write public.json. */
  readonly publicOutPath: string;
}

export class RapidsnarkError extends Error {
  constructor(
    message: string,
    public readonly exitCode: number | null,
    public readonly stderr: string,
  ) {
    super(message);
    this.name = 'RapidsnarkError';
  }
}

export function proveWithRapidsnark(input: RapidsnarkProveInput): Promise<void> {
  return new Promise((resolve, reject) => {
    const proc = spawn(
      input.binaryPath,
      [input.zkeyPath, input.wtnsPath, input.proofOutPath, input.publicOutPath],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    );

    let stderr = '';
    proc.stderr?.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });

    proc.on('error', (err) => {
      // Spawn failure (binary missing, EPERM, etc.) — distinct from
      // non-zero exit; surface the underlying errno.
      reject(new RapidsnarkError(`spawn failed: ${err.message}`, null, stderr));
    });

    proc.on('exit', (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(
        new RapidsnarkError(
          `rapidsnark exited with code ${code}`,
          code,
          stderr.trim(),
        ),
      );
    });
  });
}
