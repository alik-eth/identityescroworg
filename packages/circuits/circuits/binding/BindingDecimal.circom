pragma circom 2.1.9;

// Decimal-ASCII to uint64.
//
// Witness supplies up to MAX_DIGITS ASCII bytes (high-index slots may be
// 0) plus `numDigits`. The circuit asserts:
//   - 1 ≤ numDigits ≤ MAX_DIGITS  (zero-digit numbers are not a valid
//     JSON number; we reject them at this layer rather than relying on
//     callers).
//   - For each i < numDigits, ascii[i] is in 0x30..0x39.
//   - If numDigits > 1, ascii[0] is NOT 0x30 (no leading zeros — JSON
//     forbids them; this matches RFC 8785 §3.2.2.3 numeric serialization).
//
// Output value = sum_{i<numDigits} digit_i * 10^(numDigits - 1 - i)
// computed via Horner with an active-mask.
//
// MAX_DIGITS = 20 covers the entire uint64 range (max 18446744073709551615
// is 20 chars).

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

template DecimalAsciiToUint64(MAX_DIGITS) {
    signal input ascii[MAX_DIGITS];
    signal input numDigits;
    signal output value;

    // 1 ≤ numDigits ≤ MAX_DIGITS.
    component nLo = GreaterEqThan(8);
    nLo.in[0] <== numDigits;
    nLo.in[1] <== 1;
    nLo.out === 1;
    component nHi = LessEqThan(8);
    nHi.in[0] <== numDigits;
    nHi.in[1] <== MAX_DIGITS;
    nHi.out === 1;

    // Pre-declare all signals + components outside the loop to satisfy
    // circom's "signal decl only at initial scope or static-condition If".
    component active[MAX_DIGITS];
    component geD[MAX_DIGITS];
    component leD[MAX_DIGITS];
    signal isDigit[MAX_DIGITS];
    signal digit[MAX_DIGITS];
    signal acc[MAX_DIGITS + 1];
    signal step[MAX_DIGITS];
    signal delta[MAX_DIGITS];

    acc[0] <== 0;

    for (var i = 0; i < MAX_DIGITS; i++) {
        active[i] = LessThan(8);
        active[i].in[0] <== i;
        active[i].in[1] <== numDigits;

        geD[i] = GreaterEqThan(8);
        geD[i].in[0] <== ascii[i];
        geD[i].in[1] <== 0x30;

        leD[i] = LessEqThan(8);
        leD[i].in[0] <== ascii[i];
        leD[i].in[1] <== 0x39;

        isDigit[i] <== geD[i].out * leD[i].out;
        // active ⇒ isDigit  ↔  active * (1 - isDigit) === 0
        active[i].out * (1 - isDigit[i]) === 0;

        // digit = active ? (ascii - 0x30) : 0
        digit[i] <== active[i].out * (ascii[i] - 0x30);

        // Horner: acc[i+1] = acc[i] + active[i] * (acc[i] * 9 + digit[i])
        step[i] <== acc[i] * 9 + digit[i];
        delta[i] <== active[i].out * step[i];
        acc[i + 1] <== acc[i] + delta[i];
    }

    value <== acc[MAX_DIGITS];

    // Leading-zero check: if numDigits > 1, ascii[0] != 0x30.
    // Encoded as: (numDigits > 1) AND (ascii[0] == 0x30) is impossible.
    component multiDigit = GreaterThan(8);
    multiDigit.in[0] <== numDigits;
    multiDigit.in[1] <== 1;
    component firstIsZero = IsEqual();
    firstIsZero.in[0] <== ascii[0];
    firstIsZero.in[1] <== 0x30;
    multiDigit.out * firstIsZero.out === 0;
}
