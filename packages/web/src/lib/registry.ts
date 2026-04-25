/**
 * Shared Solidity ABI shapes + Groth16 proof packer.
 *
 * Originally hosted the QKBRegistryV3 register / registerEscrow / revokeEscrow
 * surface (split-proof pivot 2026-04-18); the V3 routes have been deleted and
 * V4 country-scoped registries are the only on-chain target. What remains is
 * the chain-side struct shapes and the snarkjs → Solidity proof packer that
 * `lib/registryV4.ts` (and its tests) reuses verbatim.
 */
import type { Groth16Proof } from './prover';

/** Solidity `Proof` struct — `(uint[2] a, uint[2][2] b, uint[2] c)`. */
export interface SolidityProof {
  readonly a: readonly [string, string];
  readonly b: readonly [readonly [string, string], readonly [string, string]];
  readonly c: readonly [string, string];
}

/**
 * Solidity `ChainInputs` struct — the 3 public signals from the chain proof
 * promoted to wallet-friendly types: `rTL` is the trusted-list Merkle root,
 * `algorithmTag` is 0 (RSA) or 1 (ECDSA), `leafSpkiCommit` is the cross-proof
 * glue equality the on-chain verifier asserts against the leaf inputs.
 */
export interface ChainInputs {
  readonly rTL: `0x${string}`;
  readonly algorithmTag: 0 | 1;
  readonly leafSpkiCommit: `0x${string}`;
}

/**
 * Pack a snarkjs Groth16 proof into the Solidity struct layout. snarkjs
 * emits `pi_a` / `pi_c` as 3-element arrays (third element is the Jacobian
 * `z` coordinate, always `"1"` for normalized proofs) and `pi_b` as 3×2;
 * the Solidity verifier only consumes the first two coords. The bn254
 * convention swaps `pi_b[i]` at encode time — the Solidity verifier (as
 * circom's own verifier.sol template does) handles the flip, so we keep
 * snarkjs's native ordering here. Reversing here would double-flip and
 * make proofs fail.
 */
export function packProof(proof: Groth16Proof): SolidityProof {
  const a: [string, string] = [String(proof.pi_a[0]), String(proof.pi_a[1])];
  const c: [string, string] = [String(proof.pi_c[0]), String(proof.pi_c[1])];
  const b00 = String(proof.pi_b[0]![0]);
  const b01 = String(proof.pi_b[0]![1]);
  const b10 = String(proof.pi_b[1]![0]);
  const b11 = String(proof.pi_b[1]![1]);
  return {
    a: [a[0], a[1]] as const,
    b: [
      [b01, b00],
      [b11, b10],
    ] as const,
    c: [c[0], c[1]] as const,
  };
}
