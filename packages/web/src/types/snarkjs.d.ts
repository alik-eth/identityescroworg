declare module 'snarkjs' {
  export const groth16: {
    fullProve(
      input: Record<string, unknown>,
      wasmUrl: string,
      zkeyUrl: string,
    ): Promise<{
      proof: {
        pi_a: string[];
        pi_b: string[][];
        pi_c: string[];
        protocol?: string;
        curve?: string;
      };
      publicSignals: string[];
    }>;
  };
}
