pragma circom 2.1.9;

// PoseidonChunkHash — fixed-byte-length variant.
//
// Mirrors `canonicalizeCertHash` in
// `packages/lotl-flattener/src/ca/canonicalize.ts`:
//
//   1. Pack input bytes into BN254 field elements, 31 bytes per element,
//      BIG-ENDIAN within each chunk. The first byte of the slice becomes
//      the highest-order byte of the chunk. The final chunk packs only the
//      remaining `len % 31` bytes (no implicit zero-padding inside the
//      packed integer).
//   2. After all data chunks, append ONE extra field element whose value
//      is `len` — the length-domain separator.
//   3. Run a Poseidon sponge of width 16 (rate 15, capacity 1):
//        state₀ = 0
//        state_{r+1} = Poseidon(16)([state_r, c_{15r}, c_{15r+1}, …, c_{15r+14}])
//        (zero-padding the final window if the total field-element count is
//        not a multiple of 15)
//   4. Output: state_R after the final round.
//
// This template is a FIXED-LENGTH instantiation. Provide N_BYTES as a
// compile-time parameter; the variable-length variant (Task 9) builds on
// top of this with byte-by-byte gating.
//
// Inputs:
//   bytes[N_BYTES] — each in 0..255 (caller is responsible for byte-range,
//                    or pass through Num2Bits(8) at the call site).
//
// Output:
//   out — single field element, the canonical hash.

include "circomlib/circuits/poseidon.circom";

template PoseidonChunkHash(N_BYTES) {
    var CHUNK = 31;
    var RATE = 15;
    // Number of data chunks ⌈N_BYTES / 31⌉.
    var N_CHUNKS = (N_BYTES + CHUNK - 1) \ CHUNK;
    // Plus one length-separator field element.
    var N_FE = N_CHUNKS + 1;
    // Rounds = ⌈N_FE / 15⌉.
    var N_ROUNDS = (N_FE + RATE - 1) \ RATE;
    // Number of bytes in the final (possibly short) chunk.
    var LAST_LEN = N_BYTES - (N_CHUNKS - 1) * CHUNK;

    signal input bytes[N_BYTES];
    signal output out;

    // === 1. Pack bytes into chunks (BE) ===
    signal chunks[N_CHUNKS];
    // Full-width chunks: indices 0..N_CHUNKS-2.
    // Each chunk = sum_{j=0..30} bytes[i*31 + j] * 256^(30-j).
    for (var c = 0; c < N_CHUNKS - 1; c++) {
        var acc = 0;
        for (var j = 0; j < CHUNK; j++) {
            acc = acc * 256 + bytes[c * CHUNK + j];
        }
        chunks[c] <== acc;
    }
    // Last chunk packs only LAST_LEN bytes (no padding inside the integer).
    var lastAcc = 0;
    for (var j = 0; j < LAST_LEN; j++) {
        lastAcc = lastAcc * 256 + bytes[(N_CHUNKS - 1) * CHUNK + j];
    }
    chunks[N_CHUNKS - 1] <== lastAcc;

    // === 2. Build the input field-element vector with length separator ===
    // We materialize a fixed-size vector `fe[N_ROUNDS * RATE]` zero-padded
    // beyond N_FE so the sponge windows are uniform.
    var TOTAL_SLOTS = N_ROUNDS * RATE;
    signal fe[TOTAL_SLOTS];
    for (var i = 0; i < N_CHUNKS; i++) {
        fe[i] <== chunks[i];
    }
    fe[N_CHUNKS] <== N_BYTES;
    for (var i = N_FE; i < TOTAL_SLOTS; i++) {
        fe[i] <== 0;
    }

    // === 3. Sponge ===
    // Each round: Poseidon(16)([state, fe[15r..15r+14]]) → new state.
    component round[N_ROUNDS];
    signal stateAfter[N_ROUNDS + 1];
    stateAfter[0] <== 0;
    for (var r = 0; r < N_ROUNDS; r++) {
        round[r] = Poseidon(16);
        round[r].inputs[0] <== stateAfter[r];
        for (var j = 0; j < RATE; j++) {
            round[r].inputs[1 + j] <== fe[r * RATE + j];
        }
        stateAfter[r + 1] <== round[r].out;
    }
    out <== stateAfter[N_ROUNDS];
}
