# Trusted setup transcript

Phase 1 demonstration deployments use a single-contributor Groth16 Phase 2 ceremony with system-RNG entropy, on top of a pinned Powers of Tau (Hermez 2^24). This is adequate for the NLNet demo milestone and explicitly **not** adequate for a production qualified deployment.

## Phase 1 entropy (demo)

- Phase 1 PoT: Hermez `powersOfTau28_hez_final_24.ptau`. SHA-256 pinned in `packages/circuits/ceremony/scripts/setup.sh`.
- Phase 2 contributions:
  - `dev-contrib-0`: local contributor, system RNG entropy, run by team lead before the first circuit build.

Contributions accumulate in `packages/circuits/ceremony/contributions/` (committed), each as `*.zkey` + SHA-256.

## Production plan (Phase 2 milestone)

Before any production-qualified deployment:

1. Announce ceremony window.
2. Minimum 5 geographically-distributed contributors, each attesting in a public repo issue.
3. Final `.zkey` published with contribution hashes + transcript + `snarkjs zkey verify` output.
4. `QKBVerifier` redeployed against the new verifier + `.zkey` hash updated in `packages/contracts/src/QKBVerifier.sol` constant.

See `docs/superpowers/specs/2026-04-17-qkb-phase1-design.md` §5.7.
