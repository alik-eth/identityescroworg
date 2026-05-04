pragma circom 2.1.9;

// BindingParseFull — full 8-field locate-and-extract for the binding
// statement Bcanon. Builds on BindingParse (Task 7) by adding the
// remaining fields needed by the ZkqesPresentation main circuit.
//
// Per orchestration §4.1, Bcanon is JCS-sorted JSON (alphabetical):
//   {"context":"0x…","declaration":"…","escrow_commitment":null,
//    "nonce":"0x<64hex>","pk":"0x04<128hex>","scheme":"secp256k1",
//    "timestamp":<digits>,"version":"…"}
//
// Witness supplies, for each field we extract, the byte offset of the
// FIRST value-content byte (one past the opening quote for string-valued
// fields, the first digit for the number-valued timestamp). Circuit
// asserts the bytes immediately preceding each offset match the expected
// JSON key literal, then extracts/decodes the value bytes.
//
// Public outputs (consumed by the main circuit):
//   pkBytes[65]               uncompressed SEC1 pubkey, hex-decoded
//   ctxBytes[MAX_CTX]         raw context bytes (hex-decoded), zero-padded
//   ctxLen                    actual context byte length (0 ≤ ≤ MAX_CTX)
//   declBytes[MAX_DECL]       raw declaration bytes verbatim, zero-padded
//   declLen                   actual declaration byte length
//   tsValue                   timestamp as uint64
//
// Out of scope (deferred — main circuit doesn't use them in public signals):
//   - nonce extraction (bound only via Bcanon SHA-256, no circuit use)
//   - escrow_commitment null literal check (Phase 2 hook)
//   - version string check (advisory, not security-critical)

include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "./BindingKeyMatch.circom";
include "./BindingHex.circom";
include "./BindingDecimal.circom";

// =========================================================================
// Slicers
// =========================================================================

// Pulls `LEN` consecutive bytes starting at `offset` out of a MAX_B-sized
// buffer. Each output is one Multiplexer over the buffer.
template BPFSlice(MAX_B, LEN) {
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

// Pulls up to MAX_LEN bytes starting at `offset`, masking trailing slots
// (where i ≥ valueLen) to zero. Caller is responsible for asserting
// valueLen ≤ MAX_LEN.
template BPFSliceVar(MAX_B, MAX_LEN) {
    signal input bytes[MAX_B];
    signal input offset;
    signal input valueLen;
    signal output out[MAX_LEN];

    component pick[MAX_LEN];
    component active[MAX_LEN];
    signal raw[MAX_LEN];
    for (var i = 0; i < MAX_LEN; i++) {
        pick[i] = Multiplexer(1, MAX_B);
        for (var j = 0; j < MAX_B; j++) {
            pick[i].inp[j][0] <== bytes[j];
        }
        pick[i].sel <== offset + i;
        raw[i] <== pick[i].out[0];

        active[i] = LessThan(16);
        active[i].in[0] <== i;
        active[i].in[1] <== valueLen;
        out[i] <== raw[i] * active[i].out;
    }
}

// =========================================================================
// Variable-length hex decoder
// =========================================================================
//
// Decodes up to MAX_BYTES bytes from up to 2*MAX_BYTES ASCII hex chars,
// where the first `hexLen` chars are real and the remaining slots may be
// arbitrary (typically zero-padded by BPFSliceVar). For inactive slots
// we synthesize the ASCII '0' before feeding to HexNibble so its
// digit-range check still accepts; the resulting nibble is 0, which
// produces a 0 byte (and the parent template's `ctxLen` output gates
// which bytes are meaningful).
//
// Asserts hexLen ≤ 2*MAX_BYTES and hexLen even.
template BPFHexBytesVar(MAX_BYTES) {
    signal input ascii[2 * MAX_BYTES];
    signal input hexLen;
    signal output bytes[MAX_BYTES];

    // hexLen ≤ 2*MAX_BYTES.
    component hexBound = LessEqThan(16);
    hexBound.in[0] <== hexLen;
    hexBound.in[1] <== 2 * MAX_BYTES;
    hexBound.out === 1;

    // Even: hexLen mod 2 = 0 via low bit.
    component hexBits = Num2Bits(16);
    hexBits.in <== hexLen;
    hexBits.out[0] === 0;

    // Per-position activity, fed-byte synthesis, nibble decode.
    component activeHi[MAX_BYTES];
    component activeLo[MAX_BYTES];
    signal feedHi[MAX_BYTES];
    signal feedLo[MAX_BYTES];
    component nh[MAX_BYTES];
    component nl[MAX_BYTES];
    for (var i = 0; i < MAX_BYTES; i++) {
        activeHi[i] = LessThan(16);
        activeHi[i].in[0] <== 2 * i;
        activeHi[i].in[1] <== hexLen;

        activeLo[i] = LessThan(16);
        activeLo[i].in[0] <== 2 * i + 1;
        activeLo[i].in[1] <== hexLen;

        // feed = 0x30 + active * (raw - 0x30); inactive → 0x30 ('0').
        feedHi[i] <== 0x30 + activeHi[i].out * (ascii[2 * i] - 0x30);
        feedLo[i] <== 0x30 + activeLo[i].out * (ascii[2 * i + 1] - 0x30);

        nh[i] = HexNibble();
        nh[i].c <== feedHi[i];
        nl[i] = HexNibble();
        nl[i].c <== feedLo[i];

        bytes[i] <== nh[i].v * 16 + nl[i].v;
    }
}

// =========================================================================
// BindingParseFull
// =========================================================================

template BindingParseFull(MAX_B, MAX_CTX, MAX_DECL, MAX_TS_DIGITS) {
    // === Inputs ===
    signal input bytes[MAX_B];          // padded Bcanon
    signal input bcanonLen;             // 0 < bcanonLen ≤ MAX_B

    signal input pkValueOffset;
    signal input schemeValueOffset;
    signal input ctxValueOffset;
    signal input ctxHexLen;             // even, 0 ≤ ctxHexLen ≤ 2*MAX_CTX
    signal input declValueOffset;
    signal input declValueLen;          // raw declaration bytes (not JCS-escaped count)
    signal input tsValueOffset;
    signal input tsDigitCount;          // 1 ≤ tsDigitCount ≤ MAX_TS_DIGITS

    // === Outputs ===
    signal output pkBytes[65];
    signal output ctxBytes[MAX_CTX];
    signal output ctxLen;
    signal output declBytes[MAX_DECL];
    signal output declLen;
    signal output tsValue;

    // === Length bound on Bcanon ===
    component lenLo = GreaterThan(16);
    lenLo.in[0] <== bcanonLen;
    lenLo.in[1] <== 0;
    lenLo.out === 1;
    component lenHi = LessEqThan(16);
    lenHi.in[0] <== bcanonLen;
    lenHi.in[1] <== MAX_B;
    lenHi.out === 1;

    // === Key match: "pk":"  (6 bytes) ===
    var PK_KEY[6] = [0x22, 0x70, 0x6B, 0x22, 0x3A, 0x22];
    component pkKey = BindingKeyAt(MAX_B, 6);
    for (var i = 0; i < MAX_B; i++) pkKey.bytes[i] <== bytes[i];
    pkKey.offset <== pkValueOffset;
    for (var i = 0; i < 6; i++) pkKey.key[i] <== PK_KEY[i];

    // === Key match: "scheme":"  (10 bytes) ===
    var SCH_KEY[10] = [0x22, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x65, 0x22, 0x3A, 0x22];
    component schKey = BindingKeyAt(MAX_B, 10);
    for (var i = 0; i < MAX_B; i++) schKey.bytes[i] <== bytes[i];
    schKey.offset <== schemeValueOffset;
    for (var i = 0; i < 10; i++) schKey.key[i] <== SCH_KEY[i];

    // === Key match: "context":"  (11 bytes) ===
    var CTX_KEY[11] = [0x22, 0x63, 0x6F, 0x6E, 0x74, 0x65, 0x78, 0x74, 0x22, 0x3A, 0x22];
    component ctxKey = BindingKeyAt(MAX_B, 11);
    for (var i = 0; i < MAX_B; i++) ctxKey.bytes[i] <== bytes[i];
    ctxKey.offset <== ctxValueOffset;
    for (var i = 0; i < 11; i++) ctxKey.key[i] <== CTX_KEY[i];

    // === Key match: "declaration":"  (15 bytes) ===
    var DECL_KEY[15] = [
        0x22, 0x64, 0x65, 0x63, 0x6C, 0x61, 0x72, 0x61,
        0x74, 0x69, 0x6F, 0x6E, 0x22, 0x3A, 0x22
    ];
    component declKey = BindingKeyAt(MAX_B, 15);
    for (var i = 0; i < MAX_B; i++) declKey.bytes[i] <== bytes[i];
    declKey.offset <== declValueOffset;
    for (var i = 0; i < 15; i++) declKey.key[i] <== DECL_KEY[i];

    // === Key match: "timestamp":  (12 bytes — no opening quote on value) ===
    var TS_KEY[12] = [
        0x22, 0x74, 0x69, 0x6D, 0x65, 0x73, 0x74, 0x61, 0x6D, 0x70, 0x22, 0x3A
    ];
    component tsKey = BindingKeyAt(MAX_B, 12);
    for (var i = 0; i < MAX_B; i++) tsKey.bytes[i] <== bytes[i];
    tsKey.offset <== tsValueOffset;
    for (var i = 0; i < 12; i++) tsKey.key[i] <== TS_KEY[i];

    // === pk value: "0x" + 130 hex chars → 65 bytes ===
    component pkSlice = BPFSlice(MAX_B, 132);
    for (var i = 0; i < MAX_B; i++) pkSlice.bytes[i] <== bytes[i];
    pkSlice.offset <== pkValueOffset;
    pkSlice.out[0] === 0x30;  // '0'
    pkSlice.out[1] === 0x78;  // 'x'
    component pkHex = HexBytesFromAscii(65);
    for (var i = 0; i < 130; i++) pkHex.ascii[i] <== pkSlice.out[2 + i];
    for (var i = 0; i < 65; i++) pkBytes[i] <== pkHex.bytes[i];

    // === scheme value: "secp256k1\""  (10 bytes) ===
    var SCH_VAL[10] = [
        0x73, 0x65, 0x63, 0x70, 0x32, 0x35, 0x36, 0x6B, 0x31, 0x22
    ];
    component schSlice = BPFSlice(MAX_B, 10);
    for (var i = 0; i < MAX_B; i++) schSlice.bytes[i] <== bytes[i];
    schSlice.offset <== schemeValueOffset;
    for (var i = 0; i < 10; i++) schSlice.out[i] === SCH_VAL[i];

    // === context value: "0x" + ctxHexLen hex chars → ctxHexLen/2 bytes ===
    component ctxPrefix = BPFSlice(MAX_B, 2);
    for (var i = 0; i < MAX_B; i++) ctxPrefix.bytes[i] <== bytes[i];
    ctxPrefix.offset <== ctxValueOffset;
    ctxPrefix.out[0] === 0x30;
    ctxPrefix.out[1] === 0x78;

    // Pull up to 2*MAX_CTX hex chars (variable length) starting after "0x".
    component ctxHexSlice = BPFSliceVar(MAX_B, 2 * MAX_CTX);
    for (var i = 0; i < MAX_B; i++) ctxHexSlice.bytes[i] <== bytes[i];
    ctxHexSlice.offset <== ctxValueOffset + 2;
    ctxHexSlice.valueLen <== ctxHexLen;

    // Decode hex-pairs to bytes (handles zero-padded slots safely).
    component ctxDecode = BPFHexBytesVar(MAX_CTX);
    for (var i = 0; i < 2 * MAX_CTX; i++) ctxDecode.ascii[i] <== ctxHexSlice.out[i];
    ctxDecode.hexLen <== ctxHexLen;
    for (var i = 0; i < MAX_CTX; i++) ctxBytes[i] <== ctxDecode.bytes[i];
    // ctxLen = ctxHexLen / 2. The witness supplies ctxLen via <-- and the
    // constraint 2*ctxLen === ctxHexLen pins it (combined with the even-bit
    // check above guaranteeing ctxHexLen is even, so the integer division
    // is exact).
    ctxLen <-- ctxHexLen \ 2;
    2 * ctxLen === ctxHexLen;

    // === declaration value: declValueLen raw bytes ===
    component declSlice = BPFSliceVar(MAX_B, MAX_DECL);
    for (var i = 0; i < MAX_B; i++) declSlice.bytes[i] <== bytes[i];
    declSlice.offset <== declValueOffset;
    declSlice.valueLen <== declValueLen;
    for (var i = 0; i < MAX_DECL; i++) declBytes[i] <== declSlice.out[i];
    declLen <== declValueLen;

    component declBound = LessEqThan(16);
    declBound.in[0] <== declValueLen;
    declBound.in[1] <== MAX_DECL;
    declBound.out === 1;

    // === timestamp value: tsDigitCount decimal digits → uint64 ===
    component tsSlice = BPFSlice(MAX_B, MAX_TS_DIGITS);
    for (var i = 0; i < MAX_B; i++) tsSlice.bytes[i] <== bytes[i];
    tsSlice.offset <== tsValueOffset;
    component tsParse = DecimalAsciiToUint64(MAX_TS_DIGITS);
    for (var i = 0; i < MAX_TS_DIGITS; i++) tsParse.ascii[i] <== tsSlice.out[i];
    tsParse.numDigits <== tsDigitCount;
    tsValue <== tsParse.value;
}
