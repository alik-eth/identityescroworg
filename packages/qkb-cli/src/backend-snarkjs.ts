/**
 * Backend using snarkjs.groth16.fullProve in-process.
 *
 * Node.js with --max-old-space-size=16384 handles the 4.5 GB leaf zkey
 * comfortably; this path works out of the box on any machine with ~8+ GB
 * free RAM. Proves are sequential by virtue of backend.prove() being called
 * once per side.
 */

import type { IProverBackend, ProveInput, ProveResult } from './backend.js';

export class SnarkjsBackend implements IProverBackend {
  readonly name = 'snarkjs';

  async prove(input: ProveInput): Promise<ProveResult> {
    input.onLog?.(`[${input.side}] snarkjs.groth16.fullProve start`);
    // snarkjs has no TS types; cast at the import boundary.
    const snarkjs = (await import('snarkjs')) as unknown as {
      groth16: {
        fullProve: (
          witness: Record<string, unknown>,
          wasmPath: string,
          zkeyPath: string,
        ) => Promise<{ proof: unknown; publicSignals: string[] }>;
      };
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input.witness,
      input.wasmPath,
      input.zkeyPath,
    );
    input.onLog?.(`[${input.side}] snarkjs.groth16.fullProve done`);
    return {
      proof: proof as ProveResult['proof'],
      publicSignals,
    };
  }
}
