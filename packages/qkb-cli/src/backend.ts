/**
 * Prover backend interface. Backends consume (witness, wasmPath, zkeyPath)
 * and produce a Groth16 proof + public signals. `side` is threaded so the
 * backend can emit progress tagged with which half of the split proof is
 * running.
 */

export type ProofSide = 'leaf' | 'chain' | 'age';

export interface Groth16Proof {
  readonly pi_a: string[];
  readonly pi_b: string[][];
  readonly pi_c: string[];
  readonly protocol?: string;
  readonly curve?: string;
}

export interface ProveResult {
  readonly proof: Groth16Proof;
  readonly publicSignals: string[];
}

export interface ProveInput {
  readonly side: ProofSide;
  readonly witness: Record<string, unknown>;
  readonly wasmPath: string;
  readonly zkeyPath: string;
  readonly onLog?: (msg: string) => void;
}

export interface IProverBackend {
  readonly name: string;
  prove(input: ProveInput): Promise<ProveResult>;
}
