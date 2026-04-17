pragma circom 2.1.9;

// X509Validity — assert notBefore ≤ tsAscii ≤ notAfter where all three are
// 14-byte ASCII strings in `YYYYMMDDHHMMSS` form (the GeneralizedTime
// digits, with the trailing 'Z' stripped).
//
// Lexicographic comparison on these strings is equivalent to chronological
// comparison because the format is fixed-width zero-padded. This avoids
// converting decimal ASCII into a unix integer inside the circuit; the main
// circuit handles that conversion separately when binding `tsAscii` to the
// public `timestamp` field element.
//
// All three inputs must be ASCII digits (the upstream slicer enforces this
// for notBefore/notAfter; the witness builder enforces it for tsAscii).

include "circomlib/circuits/comparators.circom";

// Returns 1 iff `a[0..n-1] ≤ b[0..n-1]` lexicographically, where each entry
// is a single byte 0..255. Implemented as a chain: equal-prefix-then-less.
template ByteArrayLessEq(n) {
    signal input a[n];
    signal input b[n];
    signal output out;

    // eq[i] = 1 iff a[0..i] == b[0..i]
    // ltAtI = 1 iff first differing byte at position i has a[i] < b[i]
    // out = 1 iff for some i, eq[i-1] && a[i] < b[i], OR all bytes equal.

    component byteEq[n];
    component byteLt[n];
    signal eqPrefix[n + 1];
    signal lessFoundCum[n + 1];
    signal newlyLess[n];

    eqPrefix[0] <== 1;
    lessFoundCum[0] <== 0;

    for (var i = 0; i < n; i++) {
        byteEq[i] = IsEqual();
        byteEq[i].in[0] <== a[i];
        byteEq[i].in[1] <== b[i];

        byteLt[i] = LessThan(9);
        byteLt[i].in[0] <== a[i];
        byteLt[i].in[1] <== b[i];

        // less-found if not yet found AND prefix-equal AND a[i] < b[i].
        newlyLess[i] <== eqPrefix[i] * byteLt[i].out;
        // OR via x + y - x*y
        lessFoundCum[i + 1] <==
            lessFoundCum[i] + newlyLess[i] - lessFoundCum[i] * newlyLess[i];

        eqPrefix[i + 1] <== eqPrefix[i] * byteEq[i].out;
    }

    // a ≤ b iff equal-throughout OR strictly-less-found.
    out <== eqPrefix[n] + lessFoundCum[n] - eqPrefix[n] * lessFoundCum[n];
}

// Asserts notBefore ≤ ts ≤ notAfter. Each input is a 14-byte ASCII digit
// string `YYYYMMDDHHMMSS`.
template X509Validity() {
    signal input notBefore[14];
    signal input notAfter[14];
    signal input ts[14];

    component a = ByteArrayLessEq(14);
    component b = ByteArrayLessEq(14);
    for (var i = 0; i < 14; i++) {
        a.a[i] <== notBefore[i];
        a.b[i] <== ts[i];
        b.a[i] <== ts[i];
        b.b[i] <== notAfter[i];
    }
    a.out === 1;
    b.out === 1;
}
