pragma circom 2.1.9;

// PoseidonChunkHashVar — variable-length counterpart of PoseidonChunkHash.
//
// Semantics (must match `canonicalizeCertHash` in
// packages/lotl-flattener/src/ca/canonicalize.ts):
//
//   chunks[i]     = big-endian packing of bytes[i*31 .. min((i+1)*31, len)-1]
//                   (LAST chunk packs only len - (nChunks-1)*31 bytes at its
//                    natural magnitude — NOT zero-padded-right)
//   nChunks       = ⌈len / 31⌉   (0 if len == 0)
//   fe            = [chunks[0], ..., chunks[nChunks-1], len]
//   sponge(16/15) : state_0 = 0
//                   each round consumes the next 15 fe values
//   out           = state after the last real round
//
// Because the number of rounds depends on len, we run a compile-time fixed
// MAX_ROUNDS and gate each round via a conditional mux:
//
//   state_{r+1} = active[r] * Poseidon(state_r, W_r) + (1-active[r]) * state_r
//
// All loop-local signals/components are pre-declared at the template's
// initial scope per circom 2.1.x constraints.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

template PoseidonChunkHashVar(MAX_BYTES) {
    var CHUNK = 31;
    var RATE = 15;
    var N_CHUNKS_MAX = (MAX_BYTES + CHUNK - 1) \ CHUNK;
    var N_FE_MAX = N_CHUNKS_MAX + 1;
    var N_ROUNDS_MAX = (N_FE_MAX + RATE - 1) \ RATE;
    var TOTAL_SLOTS = N_ROUNDS_MAX * RATE;

    signal input bytes[MAX_BYTES];
    signal input len;
    signal output out;

    // =====================================================================
    // 1. Range-check len.
    // =====================================================================
    component lenBound = LessEqThan(16);
    lenBound.in[0] <== len;
    lenBound.in[1] <== MAX_BYTES;
    lenBound.out === 1;

    // =====================================================================
    // 2. nChunks := ⌈len / 31⌉, pinned by 31*nChunks ∈ [len, len+31).
    // =====================================================================
    signal nChunks;
    nChunks <-- (len + CHUNK - 1) \ CHUNK;

    component nLo = GreaterEqThan(16);
    nLo.in[0] <== CHUNK * nChunks;
    nLo.in[1] <== len;
    nLo.out === 1;
    component nHi = LessThan(16);
    nHi.in[0] <== CHUNK * nChunks;
    nHi.in[1] <== len + CHUNK;
    nHi.out === 1;

    // =====================================================================
    // 3. Per-chunk packing with case flags and a Horner active-mask. All
    //    loop-local signals/components pre-declared at template scope.
    // =====================================================================
    // Padded view over `bytes` that extends cleanly to the next 31-byte
    // boundary so per-chunk loops can index without bounds checks. Tail
    // slots are provably zero (unconstrained `<== 0`).
    signal bytesPadded[N_CHUNKS_MAX * CHUNK];
    for (var k = 0; k < MAX_BYTES; k++) bytesPadded[k] <== bytes[k];
    for (var k = MAX_BYTES; k < N_CHUNKS_MAX * CHUNK; k++) bytesPadded[k] <== 0;

    signal lastLenAtC[N_CHUNKS_MAX];
    signal fullChunk[N_CHUNKS_MAX];
    signal partialChunk[N_CHUNKS_MAX];
    signal zeroChunk[N_CHUNKS_MAX];
    component lbChunk[N_CHUNKS_MAX];
    component cmpFull[N_CHUNKS_MAX];
    component cmpZero[N_CHUNKS_MAX];
    component activeByte[N_CHUNKS_MAX][CHUNK];
    signal acc[N_CHUNKS_MAX][CHUNK + 1];
    signal chunks[N_CHUNKS_MAX];

    for (var c = 0; c < N_CHUNKS_MAX; c++) {
        // Case flags (exclusive, exhaustive).
        fullChunk[c] <-- (len >= (c + 1) * CHUNK) ? 1 : 0;
        partialChunk[c] <-- (len >= c * CHUNK && len < (c + 1) * CHUNK) ? 1 : 0;
        zeroChunk[c] <-- (len < c * CHUNK) ? 1 : 0;
        fullChunk[c] * (fullChunk[c] - 1) === 0;
        partialChunk[c] * (partialChunk[c] - 1) === 0;
        zeroChunk[c] * (zeroChunk[c] - 1) === 0;
        fullChunk[c] + partialChunk[c] + zeroChunk[c] === 1;

        // Pin flags against comparators (one-way pins suffice because the
        // sum-to-one constraint above forces the third flag).
        cmpFull[c] = GreaterEqThan(16);
        cmpFull[c].in[0] <== len;
        cmpFull[c].in[1] <== (c + 1) * CHUNK;
        cmpFull[c].out === fullChunk[c];

        cmpZero[c] = LessThan(16);
        cmpZero[c].in[0] <== len;
        cmpZero[c].in[1] <== c * CHUNK;
        cmpZero[c].out === zeroChunk[c];

        // lastLenAtC by case: fullChunk*31 + partialChunk*(len - c*31).
        lastLenAtC[c] <== fullChunk[c] * CHUNK + partialChunk[c] * (len - c * CHUNK);

        lbChunk[c] = LessEqThan(8);
        lbChunk[c].in[0] <== lastLenAtC[c];
        lbChunk[c].in[1] <== CHUNK;
        lbChunk[c].out === 1;

        // Horner with active mask.
        acc[c][0] <== 0;
        for (var j = 0; j < CHUNK; j++) {
            activeByte[c][j] = LessThan(8);
            activeByte[c][j].in[0] <== j;
            activeByte[c][j].in[1] <== lastLenAtC[c];
            // active ? acc*256 + byte : acc
            //        = acc + active * (acc*255 + byte)
            acc[c][j + 1] <== acc[c][j]
                + activeByte[c][j].out * (acc[c][j] * 255 + bytesPadded[c * CHUNK + j]);
        }
        chunks[c] <== acc[c][CHUNK];
    }

    // =====================================================================
    // 4. Assemble fe[] via per-slot IsEqual/LessThan against nChunks.
    // =====================================================================
    component feEq[TOTAL_SLOTS];
    component feLt[TOTAL_SLOTS];
    signal feChunkProd[TOTAL_SLOTS];
    signal feLenProd[TOTAL_SLOTS];
    signal fe[TOTAL_SLOTS];
    for (var i = 0; i < TOTAL_SLOTS; i++) {
        feEq[i] = IsEqual();
        feEq[i].in[0] <== i;
        feEq[i].in[1] <== nChunks;

        feLt[i] = LessThan(16);
        feLt[i].in[0] <== i;
        feLt[i].in[1] <== nChunks;

        if (i < N_CHUNKS_MAX) {
            feChunkProd[i] <== feLt[i].out * chunks[i];
        } else {
            feChunkProd[i] <== 0;
        }
        feLenProd[i] <== feEq[i].out * len;
        fe[i] <== feChunkProd[i] + feLenProd[i];
    }

    // =====================================================================
    // 5. Gated sponge. nRounds = ⌈(nChunks+1) / 15⌉.
    // =====================================================================
    signal nRounds;
    nRounds <-- (nChunks + 1 + RATE - 1) \ RATE;
    component rLo = GreaterEqThan(16);
    rLo.in[0] <== RATE * nRounds;
    rLo.in[1] <== nChunks + 1;
    rLo.out === 1;
    component rHi = LessThan(16);
    rHi.in[0] <== RATE * nRounds;
    rHi.in[1] <== nChunks + 1 + RATE;
    rHi.out === 1;

    component round[N_ROUNDS_MAX];
    component active[N_ROUNDS_MAX];
    signal stateAfter[N_ROUNDS_MAX + 1];
    signal roundActive[N_ROUNDS_MAX];
    signal roundKeep[N_ROUNDS_MAX];
    stateAfter[0] <== 0;
    for (var r = 0; r < N_ROUNDS_MAX; r++) {
        round[r] = Poseidon(16);
        round[r].inputs[0] <== stateAfter[r];
        for (var j = 0; j < RATE; j++) {
            round[r].inputs[1 + j] <== fe[r * RATE + j];
        }
        active[r] = LessThan(16);
        active[r].in[0] <== r;
        active[r].in[1] <== nRounds;

        roundActive[r] <== active[r].out * round[r].out;
        roundKeep[r] <== (1 - active[r].out) * stateAfter[r];
        stateAfter[r + 1] <== roundActive[r] + roundKeep[r];
    }

    out <== stateAfter[N_ROUNDS_MAX];
}
