pragma circom 2.1.9;

// BindingParse — locate-and-extract for the binding statement Bcanon.
//
// Per orchestration §4.1, Bcanon is JCS-sorted JSON (keys alphabetical):
//   {"context":"0x…","declaration":"…","escrow_commitment":null,
//    "nonce":"0x<64hex>","pk":"0x04<128hex>","scheme":"secp256k1",
//    "timestamp":<digits>,"version":"…"}
//
// The witness builder supplies the byte offset of the FIRST value-content
// byte for each field we care about (i.e., one past the opening quote for
// string-valued fields, the first digit for the number-valued timestamp).
// This circuit asserts the bytes immediately preceding each offset match
// the expected key literal, then extracts the value bytes.
//
// Scope of THIS sub-circuit (Task 7):
//   - Assert key literals at supplied offsets for: "pk", "scheme",
//     "declaration", "context".
//   - Extract & decode pk bytes (65 B) from `0x04<128 hex>`.
//   - Assert scheme value bytes equal `"secp256k1"`.
//   - Range-check Bcanon length ≤ MAX_B.
//
// Out of scope (deferred to Task 9 main-circuit wiring):
//   - timestamp digit parsing (digit→uint64 conversion)
//   - nonce extraction (only used in declHash binding, not in public signals)
//   - escrow_commitment null literal check
//   - version string check
//   - Connecting `pkBytes` to `Secp256k1PkMatch` and `declarationHash` to
//     `DeclarationWhitelist` (the main circuit wires those).
//
// MAX_B is fixed at 2048 bytes per spec §5.1 (raised from 1024 in the
// b800521 spec amendment to fit the UK declaration plus envelope).

include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "./BindingKeyMatch.circom";
include "./BindingHex.circom";

// Helper: pulls `LEN` consecutive bytes starting at `offset` out of a
// MAX_B-sized buffer. Each output is one Multiplexer over the buffer.
template BindingSlice(MAX_B, LEN) {
    signal input bytes[MAX_B];
    signal input offset;
    signal output out[LEN];

    component pick[LEN];
    for (var i = 0; i < LEN; i++) {
        pick[i] = Multiplexer(1, MAX_B);
        for (var j = 0; j < MAX_B; j++) {
            pick[i].inp[j][0] <== bytes[j];
        }
        pick[i].sel <== offset + i;
        out[i] <== pick[i].out[0];
    }
}

template BindingParse(MAX_B) {
    // === Inputs ===
    signal input bytes[MAX_B];     // padded Bcanon
    signal input bcanonLen;        // actual byte length, 0 < bcanonLen ≤ MAX_B

    signal input pkValueOffset;    // first byte of pk hex value (after `"pk":"`)
    signal input schemeValueOffset;// first byte of scheme value (after `"scheme":"`)

    // === Outputs ===
    // 65-byte uncompressed pk decoded from the JCS hex value.
    signal output pkBytes[65];

    // === Length bound ===
    component lenLo = GreaterThan(16);
    lenLo.in[0] <== bcanonLen;
    lenLo.in[1] <== 0;
    lenLo.out === 1;
    component lenHi = LessEqThan(16);
    lenHi.in[0] <== bcanonLen;
    lenHi.in[1] <== MAX_B;
    lenHi.out === 1;

    // === Key match: "pk":" ===
    // Literal bytes: " p k " : "  →  0x22 0x70 0x6B 0x22 0x3A 0x22  (6 bytes)
    var PK_KEY_LEN = 6;
    var PK_KEY_BYTES[6] = [0x22, 0x70, 0x6B, 0x22, 0x3A, 0x22];
    component pkKey = BindingKeyAt(MAX_B, PK_KEY_LEN);
    for (var i = 0; i < MAX_B; i++) pkKey.bytes[i] <== bytes[i];
    pkKey.offset <== pkValueOffset;
    for (var i = 0; i < PK_KEY_LEN; i++) pkKey.key[i] <== PK_KEY_BYTES[i];

    // === Key match: "scheme":" ===
    // " s c h e m e " : "  →  0x22 0x73 0x63 0x68 0x65 0x6D 0x65 0x22 0x3A 0x22  (10 bytes)
    var SCHEME_KEY_LEN = 10;
    var SCHEME_KEY_BYTES[10] = [0x22, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x65, 0x22, 0x3A, 0x22];
    component schKey = BindingKeyAt(MAX_B, SCHEME_KEY_LEN);
    for (var i = 0; i < MAX_B; i++) schKey.bytes[i] <== bytes[i];
    schKey.offset <== schemeValueOffset;
    for (var i = 0; i < SCHEME_KEY_LEN; i++) schKey.key[i] <== SCHEME_KEY_BYTES[i];

    // === pk value: "0x04" + 128 hex chars → 65 bytes ===
    // Slice 132 ASCII bytes starting at pkValueOffset.
    var PK_HEX_LEN = 132; // "0x" + 130 hex chars (= 65 bytes)
    component pkSlice = BindingSlice(MAX_B, PK_HEX_LEN);
    for (var i = 0; i < MAX_B; i++) pkSlice.bytes[i] <== bytes[i];
    pkSlice.offset <== pkValueOffset;

    // First two ascii bytes must be '0' (0x30) and 'x' (0x78).
    pkSlice.out[0] === 0x30;
    pkSlice.out[1] === 0x78;

    // Decode the next 130 hex chars to 65 bytes.
    component pkHex = HexBytesFromAscii(65);
    for (var i = 0; i < 130; i++) pkHex.ascii[i] <== pkSlice.out[2 + i];
    for (var i = 0; i < 65; i++) pkBytes[i] <== pkHex.bytes[i];

    // === scheme value: must equal "secp256k1" (9 bytes), then closing '"' ===
    // s e c p 2 5 6 k 1 → 0x73 0x65 0x63 0x70 0x32 0x35 0x36 0x6B 0x31
    var SCHEME_VAL_LEN = 10; // 9 chars + closing 0x22
    var SCHEME_VAL_BYTES[10] = [
        0x73, 0x65, 0x63, 0x70, 0x32, 0x35, 0x36, 0x6B, 0x31, 0x22
    ];
    component schSlice = BindingSlice(MAX_B, SCHEME_VAL_LEN);
    for (var i = 0; i < MAX_B; i++) schSlice.bytes[i] <== bytes[i];
    schSlice.offset <== schemeValueOffset;
    for (var i = 0; i < SCHEME_VAL_LEN; i++) {
        schSlice.out[i] === SCHEME_VAL_BYTES[i];
    }
}
