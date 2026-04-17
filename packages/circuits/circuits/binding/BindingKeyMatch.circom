pragma circom 2.1.9;

// Templates that assert a JCS field key literal appears at a prover-
// supplied offset inside the Bcanon byte buffer.
//
// The orchestration §4.1 lock fixes the field set and JCS-sorted order:
//   "context" "declaration" "escrow_commitment" "nonce" "pk" "scheme"
//   "timestamp" "version"
//
// For each string-valued field K, the JCS encoding contains the literal
//   "K":"
// immediately preceding the value byte run. For a number-valued field
// (timestamp), the literal is `"K":` (no opening quote on the value side).
//
// The witness builder supplies `valueOffset` (the byte index of the FIRST
// byte of the value content — i.e. one past the opening quote for string
// values, or the first digit for number values). These templates assert
// that bytes[valueOffset - KEY_LEN .. valueOffset - 1] equals the expected
// key literal.
//
// Bounds (`valueOffset >= KEY_LEN`, `valueOffset + valueLen <= MAX_B`) are
// enforced by the call site that knows the value length.

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";

// Generic key-match: assert that bytes[offset - KEY_LEN .. offset - 1]
// equals KEY[0..KEY_LEN-1] (KEY supplied by the parent template via signals).
template BindingKeyAt(MAX_B, KEY_LEN) {
    signal input bytes[MAX_B];
    signal input offset;
    signal input key[KEY_LEN];

    // Lower bound: offset >= KEY_LEN.
    component lo = GreaterEqThan(16);
    lo.in[0] <== offset;
    lo.in[1] <== KEY_LEN;
    lo.out === 1;

    // Upper bound: offset <= MAX_B (loose; per-field caller tightens).
    component hi = LessEqThan(16);
    hi.in[0] <== offset;
    hi.in[1] <== MAX_B;
    hi.out === 1;

    component pick[KEY_LEN];
    for (var i = 0; i < KEY_LEN; i++) {
        pick[i] = Multiplexer(1, MAX_B);
        for (var j = 0; j < MAX_B; j++) {
            pick[i].inp[j][0] <== bytes[j];
        }
        pick[i].sel <== offset - KEY_LEN + i;
        pick[i].out[0] === key[i];
    }
}

// Convenience wrappers: each field's literal is hard-coded by the parent
// (BindingParse), passed in as a signal vector to keep this template
// generic. The parent fills in:
//
//   "pk":"            → 7 bytes:  0x22,0x70,0x6b,0x22,0x3a,0x22
//                                 = " p k " : "
//                       (Note: 6 bytes, not 7. " p k " : " = 6 chars.)
//   "scheme":"        → 10 bytes
//   "context":"       → 11 bytes
//   "declaration":"   → 15 bytes
//   "nonce":"         → 9  bytes
//   "timestamp":      → 12 bytes
//   "version":"       → 11 bytes
//   "escrow_commitment":  → 20 bytes
