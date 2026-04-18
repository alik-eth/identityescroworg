/**
 * Split-proof prover configuration — one (wasm, zkey, zkey-sha256) tuple
 * per circuit per algorithm. Consumed by the `/upload` screen when it
 * dispatches the two Groth16 proofs (leaf + chain) to the SnarkjsProver.
 *
 * Spec: docs/superpowers/specs/2026-04-18-split-proof-pivot.md
 * Orchestration §7 artifact pump: circuits worker uploads the .wasm + .zkey
 * to R2 after each ceremony completes; lead pumps the resulting URLs +
 * sha256 digests back into this file. Until the ceremony lands the sha256
 * values are the string `<pending-ceremony>` — validation in
 * `loadProofArtifacts` accepts either a real 64-hex digest or that literal
 * to make local-dev + Playwright-with-MockProver work before ceremony day.
 *
 * RSA is intentionally absent: Phase-2 ships ECDSA only (real Diia fixture)
 * and the plan defers RSA to a later pump when real QES test material lands.
 *
 * Two zkeys loaded simultaneously in one browser tab is a ~7 GB peak RAM
 * risk (leaf ≈ 5.5 GB, chain ≈ 2.3 GB). Callers MUST prove serially — the
 * SnarkjsProver worker streams one zkey at a time and terminates between
 * runs so the VM reclaims memory before the chain prove starts. See
 * `lib/prover.ts::proveSplit` for the orchestration.
 */
import { QkbError } from './errors';

export type ProverAlgorithm = 'ecdsa' | 'rsa';

export interface CircuitArtifactUrls {
  /** Public R2 URL of the compiled circuit wasm. */
  readonly wasmUrl: string;
  /** Public R2 URL of the Groth16 proving key. */
  readonly zkeyUrl: string;
  /**
   * Hex-encoded SHA-256 digest of the zkey bytes. Anchors the zkey against
   * CDN-side mutation. `<pending-ceremony>` is a placeholder the lead
   * replaces after the ceremony's zkey lands.
   */
  readonly zkeySha256: string;
}

export interface AlgorithmArtifactUrls {
  readonly leaf: CircuitArtifactUrls;
  readonly chain: CircuitArtifactUrls;
}

export type ProverConfig = {
  readonly [K in ProverAlgorithm]?: AlgorithmArtifactUrls;
};

export const PROVER_CONFIG: ProverConfig = {
  ecdsa: {
    leaf: {
      wasmUrl: 'https://prove.identityescrow.org/ecdsa-leaf/QKBPresentationEcdsaLeaf.wasm',
      zkeyUrl: 'https://prove.identityescrow.org/ecdsa-leaf/qkb-leaf.zkey',
      zkeySha256: '<pending-ceremony>',
    },
    chain: {
      wasmUrl: 'https://prove.identityescrow.org/ecdsa-chain/QKBPresentationEcdsaChain.wasm',
      zkeyUrl: 'https://prove.identityescrow.org/ecdsa-chain/qkb-chain.zkey',
      zkeySha256: '<pending-ceremony>',
    },
  },
  // rsa: deferred — add `leaf` + `chain` entries when real RSA QES material
  //      is available and the circuits team runs the RSA ceremony.
} as const;

/**
 * Pick the leaf + chain artifact URLs for the requested algorithm. Throws
 * if the algorithm isn't configured (e.g. RSA before its ceremony lands).
 */
export function getProverConfig(algorithm: ProverAlgorithm): AlgorithmArtifactUrls {
  const cfg = PROVER_CONFIG[algorithm];
  if (!cfg) {
    throw new QkbError('prover.artifactMismatch', {
      reason: 'prover-algo-unconfigured',
      algorithm,
    });
  }
  return cfg;
}

/**
 * Check whether a circuit's zkey sha256 is still the pre-ceremony
 * placeholder. Callers should either refuse to prove (when requesting
 * real proof) or fall back to the MockProver (when happy-path testing).
 */
export function isPendingCeremony(sha256: string): boolean {
  return sha256 === '<pending-ceremony>';
}
