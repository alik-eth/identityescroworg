pragma circom 2.1.9;

// Hex-decoding helpers for binding fields encoded as `"0x<hex>"` in JCS.
//
// `HexNibble()` constrains an ASCII byte to be one of '0'..'9' / 'a'..'f'
// (lowercase only, per the §4.1 lock that hex-encoded fields are
// lowercase) and outputs the 4-bit nibble value 0..15. JCS doesn't
// mandate hex case, but our binding template fixes lowercase to make the
// circuit deterministic.
//
// `HexBytesFromAsciiSlice(N)` converts 2N ASCII bytes into N bytes.

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

// Constrain `c` ∈ {'0'..'9'} ∪ {'a'..'f'} and output its nibble value.
//
// Strategy: the prover supplies a hint `isLetter ∈ {0,1}` (=1 for 'a'..'f').
// We then assert (digit OR letter) is true and consistent.
template HexNibble() {
    signal input c;
    signal output v;

    // isDigit = 1 iff '0' ≤ c ≤ '9'
    component geD = GreaterEqThan(8);
    geD.in[0] <== c;
    geD.in[1] <== 0x30;
    component leD = LessEqThan(8);
    leD.in[0] <== c;
    leD.in[1] <== 0x39;
    signal isDigit;
    isDigit <== geD.out * leD.out;

    // isLetter = 1 iff 'a' ≤ c ≤ 'f'
    component geL = GreaterEqThan(8);
    geL.in[0] <== c;
    geL.in[1] <== 0x61;
    component leL = LessEqThan(8);
    leL.in[0] <== c;
    leL.in[1] <== 0x66;
    signal isLetter;
    isLetter <== geL.out * leL.out;

    // Exactly one of isDigit or isLetter is true.
    isDigit + isLetter === 1;

    // Compute nibble:
    //   digit  → c - 0x30
    //   letter → c - 0x61 + 10  =  c - 0x57
    // Split into two intermediates so each constraint stays quadratic
    // (A*B = C form).
    signal vDigit;
    signal vLetter;
    vDigit <== isDigit * (c - 0x30);
    vLetter <== isLetter * (c - 0x57);
    v <== vDigit + vLetter;

    // Range-check v ∈ 0..15 (defence in depth).
    component vBits = Num2Bits(4);
    vBits.in <== v;
}

// Decode N bytes from 2N ASCII hex characters in `ascii[0..2N-1]` into
// `bytes[0..N-1]`. Each output byte = (nibble[2i] << 4) | nibble[2i+1].
template HexBytesFromAscii(N) {
    signal input ascii[2 * N];
    signal output bytes[N];

    component nibble[2 * N];
    for (var i = 0; i < 2 * N; i++) {
        nibble[i] = HexNibble();
        nibble[i].c <== ascii[i];
    }
    for (var i = 0; i < N; i++) {
        bytes[i] <== nibble[2 * i].v * 16 + nibble[2 * i + 1].v;
    }
}
