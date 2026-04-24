pragma circom 2.1.9;

// Sha256CanonPad — enforces that `paddedIn[0..MAX_BYTES)` is the canonical
// FIPS 180-4 §5.1.1 SHA-256 padding of `data[0..dataLen)` with total
// padded length `paddedLen`. Without this check, the prover could hand
// Sha256Var a `paddedIn` whose suffix is unconstrained beyond the claimed
// `dataLen`, so the digest the circuit proves would be sha256 of some
// other message that merely shares the first `dataLen` bytes. This
// module closes that gap: the circuit can only commit to
// sha256(data[0..dataLen)).
//
// The honest prover still supplies `paddedIn` and `paddedLen` directly
// (witness-convenient — no in-circuit ceil/division arithmetic); the
// constraints force those witness values to match the canonical padding
// of `data`.
//
// Constraints:
//   paddedLen is a multiple of 64.
//   paddedLen is the MINIMUM multiple of 64 that is ≥ dataLen + 9
//     (dataLen + 9 ≤ paddedLen < dataLen + 73 — a single window, so the
//      prover cannot pad with an extra full block of zeros).
//   For each 0 ≤ i < MAX_BYTES:
//     i < dataLen                    → paddedIn[i] == data[i]
//     i == dataLen                   → paddedIn[i] == 0x80
//     dataLen < i < paddedLen - 8    → paddedIn[i] == 0
//     paddedLen - 8 ≤ i < paddedLen  → paddedIn[i] == BE byte of dataLen*8
//     i ≥ paddedLen                  → unconstrained (outside SHA compression)
//
// MAX_BYTES must be large enough that paddedLen ≤ MAX_BYTES for every
// honest dataLen. Keep Sha256Var's own range check for paddedLen ≤ MAX_BYTES
// in place; this template concerns itself only with the shape, not the
// absolute bound.

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/multiplexer.circom";

template Sha256CanonPad(MAX_BYTES) {
    signal input data[MAX_BYTES];
    signal input dataLen;
    signal input paddedIn[MAX_BYTES];
    signal input paddedLen;

    // paddedLen is a multiple of 64.
    signal q;
    q <-- paddedLen \ 64;
    q * 64 === paddedLen;

    // paddedLen ≥ dataLen + 9
    component geMin = GreaterEqThan(16);
    geMin.in[0] <== paddedLen;
    geMin.in[1] <== dataLen + 9;
    geMin.out === 1;

    // paddedLen < dataLen + 9 + 64  — minimality: no extra block of zeros.
    component ltMax = LessThan(16);
    ltMax.in[0] <== paddedLen;
    ltMax.in[1] <== dataLen + 9 + 64;
    ltMax.out === 1;

    // Length trailer: 8 big-endian bytes encoding dataLen*8. Decompose
    // (dataLen*8) into 64 bits and repack as 8 bytes.
    component bitLenBits = Num2Bits(64);
    bitLenBits.in <== dataLen * 8;
    signal trailer[8];
    for (var k = 0; k < 8; k++) {
        var acc = 0;
        for (var b = 0; b < 8; b++) acc = acc + bitLenBits.out[8 * (7 - k) + b] * (1 << b);
        trailer[k] <== acc;
    }

    component iLtLen[MAX_BYTES];
    component iEqLen[MAX_BYTES];
    component iLtTrailerStart[MAX_BYTES];
    component iLtPadded[MAX_BYTES];
    component trailerPick[MAX_BYTES];
    signal iGtLen[MAX_BYTES];
    signal inZeros[MAX_BYTES];
    signal inTrailer[MAX_BYTES];

    for (var i = 0; i < MAX_BYTES; i++) {
        iLtLen[i] = LessThan(16);
        iLtLen[i].in[0] <== i;
        iLtLen[i].in[1] <== dataLen;

        iEqLen[i] = IsEqual();
        iEqLen[i].in[0] <== i;
        iEqLen[i].in[1] <== dataLen;

        iLtTrailerStart[i] = LessThan(16);
        iLtTrailerStart[i].in[0] <== i;
        iLtTrailerStart[i].in[1] <== paddedLen - 8;

        iLtPadded[i] = LessThan(16);
        iLtPadded[i].in[0] <== i;
        iLtPadded[i].in[1] <== paddedLen;

        // i > dataLen  (since one-of iLtLen / iEqLen / iGtLen holds).
        iGtLen[i] <== 1 - iLtLen[i].out - iEqLen[i].out;

        // dataLen < i < paddedLen - 8
        inZeros[i] <== iGtLen[i] * iLtTrailerStart[i].out;

        // paddedLen - 8 ≤ i < paddedLen
        inTrailer[i] <== (1 - iLtTrailerStart[i].out) * iLtPadded[i].out;

        // i < dataLen  →  paddedIn[i] == data[i]
        iLtLen[i].out * (paddedIn[i] - data[i]) === 0;

        // i == dataLen →  paddedIn[i] == 0x80
        iEqLen[i].out * (paddedIn[i] - 0x80) === 0;

        // dataLen < i < paddedLen - 8  →  paddedIn[i] == 0
        inZeros[i] * paddedIn[i] === 0;

        // paddedLen - 8 ≤ i < paddedLen →  paddedIn[i] == trailer[i - (paddedLen - 8)]
        // sel = (i - paddedLen + 8) * inTrailer so sel=0 when inTrailer=0
        // (Multiplexer rejects out-of-range sel; forcing to 0 in the
        // inactive case keeps it valid).
        trailerPick[i] = Multiplexer(1, 8);
        for (var k = 0; k < 8; k++) trailerPick[i].inp[k][0] <== trailer[k];
        trailerPick[i].sel <== (i - paddedLen + 8) * inTrailer[i];
        inTrailer[i] * (paddedIn[i] - trailerPick[i].out[0]) === 0;
    }
}
