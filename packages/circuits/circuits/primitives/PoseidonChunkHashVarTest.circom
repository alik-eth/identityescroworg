pragma circom 2.1.9;

include "./PoseidonChunkHashVar.circom";

// MAX_BYTES = 512 → N_CHUNKS_MAX=17, N_FE_MAX=18, N_ROUNDS_MAX=2. Small
// len values exercise the single-round path; values > 14*31=434 spill
// into the second round, exercising the conditional-absorb gate.
component main = PoseidonChunkHashVar(512);
