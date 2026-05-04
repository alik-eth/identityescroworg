pragma circom 2.1.9;

// BindingParseV2CoreFast — same parse contract as BindingParseV2Core
// (legacy), refactored to use one-Decoder + K-EscalarProduct shifted-view
// extractions instead of K independent Multiplexer(1, MAX_B) calls.
//
// Why this exists
// ===============
// Legacy V2Core compiles to ~2.62M constraints @ MAX_BCANON=1024 (measured
// 2026-04-29). The cost is dominated by per-offset slicing, where each of
// the 12 BindingKeyAt(MAX_B, K) instances and 6 BPFSlice(MAX_B, K)
// instances spends K × Multiplexer(1, MAX_B) ≈ 2K × MAX_B constraints.
//
// Each Multiplexer(1, MAX_B) internally builds a Decoder(MAX_B) (~MAX_B
// constraints) and an EscalarProduct(MAX_B) (~MAX_B constraints). The
// Decoder is the same for every byte at the same offset — it's just a
// one-hot encoding of `sel`. This template amortizes the Decoder across
// all K bytes of a slice, paying ~(K+1) × MAX_B instead of ~2K × MAX_B
// (asymptote 2× savings).
//
// Soundness invariants preserved
// ==============================
// 1. Identical input/output signal names + ordering as V2Core; the V5 main
//    circuit's BindingParseV2CoreLegacy callsite swaps to ...Fast with no
//    other edits. Parity test in test/binding/BindingParseV2CoreParity.test.ts
//    asserts byte-equal outputs across both templates on the zkqes binding fixture (version "QKB/2.0" frozen).
//
// 2. Direct Decoder usage instead of Multiplexer means soundness now
//    depends on this template asserting `dec.success === 1` itself
//    (Multiplexer asserts that internally; Decoder alone permits
//    out-of-range `inp` to silently produce an all-zero one-hot vector).
//    Every Decoder instance below has a `decN.success === 1` line — if you
//    ever copy this pattern elsewhere, KEEP IT.
//
// 3. The terminator pins ('"', '}', ',') and value-content equalities from
//    V2Core legacy are unchanged byte-for-byte. No relaxation of any
//    pin or any range check.
//
// Style note
// ==========
// circomlib's `EscalarProduct` is imported directly. This is intentional
// (refactor-driven) — please don't "simplify" calls back to Multiplexer,
// that defeats the entire amortization. See handoff doc §8.3.

include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/aliascheck.circom";
include "./BindingHex.circom";
include "./BindingDecimal.circom";

// Slice K consecutive bytes from `bytes` starting at `offset`, paying
// ~(K+1) × MAX_B constraints instead of ~2K × MAX_B.
//
// Safety: `Decoder(MAX_B - K + 1).success === 1` forces `offset` to be
// exactly one of [0, MAX_B - K + 1), which guarantees `offset + i < MAX_B`
// for every i ∈ [0, K). A prover supplying `offset` outside that range
// makes `dec.success` collapse to 0 and the assert fails.
template BPFSliceFast(MAX_B, K) {
    signal input bytes[MAX_B];
    signal input offset;
    signal output out[K];

    var W = MAX_B - K + 1;

    component dec = Decoder(W);
    dec.inp <== offset;
    dec.success === 1;

    component prod[K];
    for (var i = 0; i < K; i++) {
        prod[i] = EscalarProduct(W);
        for (var j = 0; j < W; j++) {
            prod[i].in1[j] <== bytes[j + i];
            prod[i].in2[j] <== dec.out[j];
        }
        out[i] <== prod[i].out;
    }
}

// Variant of BPFSliceFast that masks output bytes beyond `valueLen`.
// Used for variable-length fields (ctx hex, policyId).
//
// Caveat: this masks the OUTPUT but the Decoder is still bounded only by
// MAX_B - MAX_LEN + 1, NOT by valueLen. The mask is applied to enforce the
// V2Core legacy invariant that out[i] === 0 for i >= valueLen — important
// because the parent uses these masked-zero outputs to drive the
// `(1 - active[i]) * policyIdBytesIn[i] === 0` style equality checks.
template BPFSliceVarFast(MAX_B, MAX_LEN) {
    signal input bytes[MAX_B];
    signal input offset;
    signal input valueLen;
    signal output out[MAX_LEN];

    var W = MAX_B - MAX_LEN + 1;

    component dec = Decoder(W);
    dec.inp <== offset;
    dec.success === 1;

    component prod[MAX_LEN];
    component active[MAX_LEN];
    signal raw[MAX_LEN];
    for (var i = 0; i < MAX_LEN; i++) {
        prod[i] = EscalarProduct(W);
        for (var j = 0; j < W; j++) {
            prod[i].in1[j] <== bytes[j + i];
            prod[i].in2[j] <== dec.out[j];
        }
        raw[i] <== prod[i].out;

        active[i] = LessThan(16);
        active[i].in[0] <== i;
        active[i].in[1] <== valueLen;
        out[i] <== raw[i] * active[i].out;
    }
}

// Key-prefix gate: assert that bytes[offset - KEY_LEN .. offset - 1] equals
// the parent-supplied KEY[0..KEY_LEN-1]. Same contract as BindingKeyAt
// (legacy) but uses a single Decoder + KEY_LEN EscalarProducts.
//
// Range checks identical to BindingKeyAt: offset >= KEY_LEN and
// offset <= MAX_B (loose); per-field caller tightens via the closing-quote
// or terminator pin downstream.
template BindingKeyAtFast(MAX_B, KEY_LEN) {
    signal input bytes[MAX_B];
    signal input offset;
    signal input key[KEY_LEN];

    component lo = GreaterEqThan(16);
    lo.in[0] <== offset;
    lo.in[1] <== KEY_LEN;
    lo.out === 1;

    component hi = LessEqThan(16);
    hi.in[0] <== offset;
    hi.in[1] <== MAX_B;
    hi.out === 1;

    var W = MAX_B - KEY_LEN + 1;
    component dec = Decoder(W);
    dec.inp <== offset - KEY_LEN;
    dec.success === 1;

    component prod[KEY_LEN];
    for (var i = 0; i < KEY_LEN; i++) {
        prod[i] = EscalarProduct(W);
        for (var j = 0; j < W; j++) {
            prod[i].in1[j] <== bytes[j + i];
            prod[i].in2[j] <== dec.out[j];
        }
        prod[i].out === key[i];
    }
}

// Bits256ToFieldFast — byte-identical to BindingParseV2CoreLegacy.Bits256ToField,
// inlined here so this file has no `include "./BindingParseV2CoreLegacy.circom"`
// dependency. That keeps Legacy + Fast in a single compilation unit safe (e.g.
// for a future parity-wrapper that needs to instantiate both side-by-side
// without circom complaining about a doubly-defined template).
template Bits256ToFieldFast() {
    signal input digestBits[256];
    signal output packed;

    digestBits[0] === 0;
    digestBits[1] === 0;

    component alias = AliasCheck();
    for (var i = 0; i < 254; i++) {
        alias.in[i] <== digestBits[255 - i];
    }

    var acc = 0;
    for (var i = 2; i < 256; i++) acc = acc * 2 + digestBits[i];
    packed <== acc;
}

// Same hex-decode template as BindingParseV2CoreLegacy.BPFHexBytesVar, copied
// verbatim. (It uses Multiplexer(1, ...) only as a stand-in for one-byte
// equality — there's nothing to amortize because each ASCII byte is paired
// with its own constants. The legacy implementation here is already optimal.)
template BPFHexBytesVarFast(MAX_BYTES) {
    signal input ascii[2 * MAX_BYTES];
    signal input hexLen;
    signal output bytes[MAX_BYTES];

    component hexBound = LessEqThan(16);
    hexBound.in[0] <== hexLen;
    hexBound.in[1] <== 2 * MAX_BYTES;
    hexBound.out === 1;

    component hexBits = Num2Bits(16);
    hexBits.in <== hexLen;
    hexBits.out[0] === 0;

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

        feedHi[i] <== 0x30 + activeHi[i].out * (ascii[2 * i] - 0x30);
        feedLo[i] <== 0x30 + activeLo[i].out * (ascii[2 * i + 1] - 0x30);

        nh[i] = HexNibble();
        nh[i].c <== feedHi[i];
        nl[i] = HexNibble();
        nl[i].c <== feedLo[i];

        bytes[i] <== nh[i].v * 16 + nl[i].v;
    }
}

template BindingParseV2CoreFast(MAX_B, MAX_CTX, MAX_TS_DIGITS) {
    var MAX_POLICY_ID = 128;

    signal input bytes[MAX_B];
    signal input bcanonLen;

    signal input pkValueOffset;
    signal input schemeValueOffset;
    signal input assertionsValueOffset;
    signal input statementSchemaValueOffset;
    signal input nonceValueOffset;
    signal input ctxValueOffset;
    signal input ctxHexLen;
    signal input policyIdValueOffset;
    signal input policyIdLen;
    signal input policyLeafHashValueOffset;
    signal input policyBindingSchemaValueOffset;
    signal input policyVersionValueOffset;
    signal input policyVersionDigitCount;
    signal input tsValueOffset;
    signal input tsDigitCount;
    signal input versionValueOffset;
    signal input nonceBytesIn[32];
    signal input policyIdBytesIn[MAX_POLICY_ID];
    signal input policyVersionIn;

    signal output pkBytes[65];
    signal output nonceBytes[32];
    signal output ctxBytes[MAX_CTX];
    signal output ctxLen;
    signal output policyIdBytes[MAX_POLICY_ID];
    signal output policyLeafHash;
    signal output policyVersion;
    signal output tsValue;

    component lenLo = GreaterThan(16);
    lenLo.in[0] <== bcanonLen;
    lenLo.in[1] <== 0;
    lenLo.out === 1;
    component lenHi = LessEqThan(16);
    lenHi.in[0] <== bcanonLen;
    lenHi.in[1] <== MAX_B;
    lenHi.out === 1;

    // === KEY-PREFIX GATES (12× BindingKeyAtFast) ============================

    // "pk":"  (6 bytes)
    var PK_KEY[6] = [0x22, 0x70, 0x6B, 0x22, 0x3A, 0x22];
    component pkKey = BindingKeyAtFast(MAX_B, 6);
    for (var i = 0; i < MAX_B; i++) pkKey.bytes[i] <== bytes[i];
    pkKey.offset <== pkValueOffset;
    for (var i = 0; i < 6; i++) pkKey.key[i] <== PK_KEY[i];

    // "scheme":"  (10 bytes)
    var SCH_KEY[10] = [0x22, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x65, 0x22, 0x3A, 0x22];
    component schKey = BindingKeyAtFast(MAX_B, 10);
    for (var i = 0; i < MAX_B; i++) schKey.bytes[i] <== bytes[i];
    schKey.offset <== schemeValueOffset;
    for (var i = 0; i < 10; i++) schKey.key[i] <== SCH_KEY[i];

    // "assertions":  (13 bytes)
    var ASSERT_KEY[13] = [0x22,0x61,0x73,0x73,0x65,0x72,0x74,0x69,0x6F,0x6E,0x73,0x22,0x3A];
    component assertKey = BindingKeyAtFast(MAX_B, 13);
    for (var i = 0; i < MAX_B; i++) assertKey.bytes[i] <== bytes[i];
    assertKey.offset <== assertionsValueOffset;
    for (var i = 0; i < 13; i++) assertKey.key[i] <== ASSERT_KEY[i];

    // "statementSchema":"  (19 bytes)
    var STMT_KEY[19] = [
        0x22,0x73,0x74,0x61,0x74,0x65,0x6D,0x65,0x6E,0x74,0x53,0x63,0x68,0x65,0x6D,0x61,0x22,0x3A,0x22
    ];
    component stmtKey = BindingKeyAtFast(MAX_B, 19);
    for (var i = 0; i < MAX_B; i++) stmtKey.bytes[i] <== bytes[i];
    stmtKey.offset <== statementSchemaValueOffset;
    for (var i = 0; i < 19; i++) stmtKey.key[i] <== STMT_KEY[i];

    // "nonce":"  (9 bytes)
    var NONCE_KEY[9] = [0x22,0x6E,0x6F,0x6E,0x63,0x65,0x22,0x3A,0x22];
    component nonceKey = BindingKeyAtFast(MAX_B, 9);
    for (var i = 0; i < MAX_B; i++) nonceKey.bytes[i] <== bytes[i];
    nonceKey.offset <== nonceValueOffset;
    for (var i = 0; i < 9; i++) nonceKey.key[i] <== NONCE_KEY[i];

    // "context":"  (11 bytes)
    var CTX_KEY[11] = [0x22, 0x63, 0x6F, 0x6E, 0x74, 0x65, 0x78, 0x74, 0x22, 0x3A, 0x22];
    component ctxKey = BindingKeyAtFast(MAX_B, 11);
    for (var i = 0; i < MAX_B; i++) ctxKey.bytes[i] <== bytes[i];
    ctxKey.offset <== ctxValueOffset;
    for (var i = 0; i < 11; i++) ctxKey.key[i] <== CTX_KEY[i];

    // "policyId":"  (12 bytes)
    var POLICY_ID_KEY[12] = [0x22,0x70,0x6F,0x6C,0x69,0x63,0x79,0x49,0x64,0x22,0x3A,0x22];
    component policyIdKey = BindingKeyAtFast(MAX_B, 12);
    for (var i = 0; i < MAX_B; i++) policyIdKey.bytes[i] <== bytes[i];
    policyIdKey.offset <== policyIdValueOffset;
    for (var i = 0; i < 12; i++) policyIdKey.key[i] <== POLICY_ID_KEY[i];

    // "leafHash":"  (12 bytes)
    var LEAF_KEY[12] = [0x22,0x6C,0x65,0x61,0x66,0x48,0x61,0x73,0x68,0x22,0x3A,0x22];
    component leafKey = BindingKeyAtFast(MAX_B, 12);
    for (var i = 0; i < MAX_B; i++) leafKey.bytes[i] <== bytes[i];
    leafKey.offset <== policyLeafHashValueOffset;
    for (var i = 0; i < 12; i++) leafKey.key[i] <== LEAF_KEY[i];

    // "bindingSchema":"  (17 bytes)
    var POLICY_SCHEMA_KEY[17] = [0x22,0x62,0x69,0x6E,0x64,0x69,0x6E,0x67,0x53,0x63,0x68,0x65,0x6D,0x61,0x22,0x3A,0x22];
    component policySchemaKey = BindingKeyAtFast(MAX_B, 17);
    for (var i = 0; i < MAX_B; i++) policySchemaKey.bytes[i] <== bytes[i];
    policySchemaKey.offset <== policyBindingSchemaValueOffset;
    for (var i = 0; i < 17; i++) policySchemaKey.key[i] <== POLICY_SCHEMA_KEY[i];

    // "policyVersion":  (16 bytes)
    var POLICY_VERSION_KEY[16] = [0x22,0x70,0x6F,0x6C,0x69,0x63,0x79,0x56,0x65,0x72,0x73,0x69,0x6F,0x6E,0x22,0x3A];
    component policyVersionKey = BindingKeyAtFast(MAX_B, 16);
    for (var i = 0; i < MAX_B; i++) policyVersionKey.bytes[i] <== bytes[i];
    policyVersionKey.offset <== policyVersionValueOffset;
    for (var i = 0; i < 16; i++) policyVersionKey.key[i] <== POLICY_VERSION_KEY[i];

    // "timestamp":  (12 bytes)
    var TS_KEY[12] = [
        0x22, 0x74, 0x69, 0x6D, 0x65, 0x73, 0x74, 0x61, 0x6D, 0x70, 0x22, 0x3A
    ];
    component tsKey = BindingKeyAtFast(MAX_B, 12);
    for (var i = 0; i < MAX_B; i++) tsKey.bytes[i] <== bytes[i];
    tsKey.offset <== tsValueOffset;
    for (var i = 0; i < 12; i++) tsKey.key[i] <== TS_KEY[i];

    // "version":"  (11 bytes)
    var VER_KEY[11] = [0x22,0x76,0x65,0x72,0x73,0x69,0x6F,0x6E,0x22,0x3A,0x22];
    component verKey = BindingKeyAtFast(MAX_B, 11);
    for (var i = 0; i < MAX_B; i++) verKey.bytes[i] <== bytes[i];
    verKey.offset <== versionValueOffset;
    for (var i = 0; i < 11; i++) verKey.key[i] <== VER_KEY[i];

    // === VALUE EXTRACTION + EQUALITIES ======================================

    // pk = "0x" + 130 hex chars + closing `"`
    component pkSlice = BPFSliceFast(MAX_B, 133);
    for (var i = 0; i < MAX_B; i++) pkSlice.bytes[i] <== bytes[i];
    pkSlice.offset <== pkValueOffset;
    pkSlice.out[0] === 0x30;
    pkSlice.out[1] === 0x78;
    pkSlice.out[132] === 0x22;
    component pkHex = HexBytesFromAscii(65);
    for (var i = 0; i < 130; i++) pkHex.ascii[i] <== pkSlice.out[2 + i];
    for (var i = 0; i < 65; i++) pkBytes[i] <== pkHex.bytes[i];

    // scheme = "secp256k1"
    var SCH_VAL[10] = [
        0x73, 0x65, 0x63, 0x70, 0x32, 0x35, 0x36, 0x6B, 0x31, 0x22
    ];
    component schSlice = BPFSliceFast(MAX_B, 10);
    for (var i = 0; i < MAX_B; i++) schSlice.bytes[i] <== bytes[i];
    schSlice.offset <== schemeValueOffset;
    for (var i = 0; i < 10; i++) schSlice.out[i] === SCH_VAL[i];

    // assertions = literal 91-byte JSON object
    var ASSERT_VAL[91] = [
        0x7B,0x22,0x61,0x63,0x63,0x65,0x70,0x74,0x73,0x41,0x74,0x74,0x72,0x69,0x62,0x75,0x74,0x69,0x6F,0x6E,0x22,0x3A,0x74,0x72,0x75,0x65,0x2C,
        0x22,0x62,0x69,0x6E,0x64,0x73,0x43,0x6F,0x6E,0x74,0x65,0x78,0x74,0x22,0x3A,0x74,0x72,0x75,0x65,0x2C,
        0x22,0x6B,0x65,0x79,0x43,0x6F,0x6E,0x74,0x72,0x6F,0x6C,0x22,0x3A,0x74,0x72,0x75,0x65,0x2C,
        0x22,0x72,0x65,0x76,0x6F,0x63,0x61,0x74,0x69,0x6F,0x6E,0x52,0x65,0x71,0x75,0x69,0x72,0x65,0x64,0x22,0x3A,0x74,0x72,0x75,0x65,0x7D
    ];
    component assertSlice = BPFSliceFast(MAX_B, 91);
    for (var i = 0; i < MAX_B; i++) assertSlice.bytes[i] <== bytes[i];
    assertSlice.offset <== assertionsValueOffset;
    for (var i = 0; i < 91; i++) assertSlice.out[i] === ASSERT_VAL[i];

    // statementSchema = "qkb-binding-core/v1"  // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
    var CORE_SCHEMA_VAL[20] = [
        0x71,0x6B,0x62,0x2D,0x62,0x69,0x6E,0x64,0x69,0x6E,0x67,0x2D,0x63,0x6F,0x72,0x65,0x2F,0x76,0x31,0x22
    ];
    component stmtSlice = BPFSliceFast(MAX_B, 20);
    for (var i = 0; i < MAX_B; i++) stmtSlice.bytes[i] <== bytes[i];
    stmtSlice.offset <== statementSchemaValueOffset;
    for (var i = 0; i < 20; i++) stmtSlice.out[i] === CORE_SCHEMA_VAL[i];

    // nonce = "0x" + 64 hex chars + closing `"`
    component nonceSlice = BPFSliceFast(MAX_B, 67);
    for (var i = 0; i < MAX_B; i++) nonceSlice.bytes[i] <== bytes[i];
    nonceSlice.offset <== nonceValueOffset;
    nonceSlice.out[0] === 0x30;
    nonceSlice.out[1] === 0x78;
    nonceSlice.out[66] === 0x22;
    component nonceHex = HexBytesFromAscii(32);
    for (var i = 0; i < 64; i++) nonceHex.ascii[i] <== nonceSlice.out[2 + i];
    for (var i = 0; i < 32; i++) {
        nonceBytes[i] <== nonceHex.bytes[i];
        nonceBytes[i] === nonceBytesIn[i];
    }

    // context = "0x" + ctxHexLen hex chars + closing `"`
    component ctxPrefix = BPFSliceFast(MAX_B, 2);
    for (var i = 0; i < MAX_B; i++) ctxPrefix.bytes[i] <== bytes[i];
    ctxPrefix.offset <== ctxValueOffset;
    ctxPrefix.out[0] === 0x30;
    ctxPrefix.out[1] === 0x78;

    // Single-byte closing-quote read at variable offset — kept as Multiplexer
    // because there's nothing to amortize (one byte = one EscalarProduct
    // either way, and Multiplexer's range check is identical).
    component ctxClose = Multiplexer(1, MAX_B);
    for (var i = 0; i < MAX_B; i++) ctxClose.inp[i][0] <== bytes[i];
    ctxClose.sel <== ctxValueOffset + 2 + ctxHexLen;
    ctxClose.out[0] === 0x22;

    component ctxHexSlice = BPFSliceVarFast(MAX_B, 2 * MAX_CTX);
    for (var i = 0; i < MAX_B; i++) ctxHexSlice.bytes[i] <== bytes[i];
    ctxHexSlice.offset <== ctxValueOffset + 2;
    ctxHexSlice.valueLen <== ctxHexLen;

    component ctxDecode = BPFHexBytesVarFast(MAX_CTX);
    for (var i = 0; i < 2 * MAX_CTX; i++) ctxDecode.ascii[i] <== ctxHexSlice.out[i];
    ctxDecode.hexLen <== ctxHexLen;
    for (var i = 0; i < MAX_CTX; i++) ctxBytes[i] <== ctxDecode.bytes[i];

    ctxLen <-- ctxHexLen \ 2;
    2 * ctxLen === ctxHexLen;

    // policyId — variable-length string with byte-equality + closing-quote pin
    component policyIdBound = LessEqThan(16);
    policyIdBound.in[0] <== policyIdLen;
    policyIdBound.in[1] <== MAX_POLICY_ID;
    policyIdBound.out === 1;
    component policyIdSlice = BPFSliceVarFast(MAX_B, MAX_POLICY_ID);
    for (var i = 0; i < MAX_B; i++) policyIdSlice.bytes[i] <== bytes[i];
    policyIdSlice.offset <== policyIdValueOffset;
    policyIdSlice.valueLen <== policyIdLen;
    component policyIdActive[MAX_POLICY_ID];
    for (var i = 0; i < MAX_POLICY_ID; i++) {
        policyIdBytes[i] <== policyIdSlice.out[i];
        policyIdActive[i] = LessThan(16);
        policyIdActive[i].in[0] <== i;
        policyIdActive[i].in[1] <== policyIdLen;
        policyIdBytes[i] === policyIdBytesIn[i] * policyIdActive[i].out;
        (1 - policyIdActive[i].out) * policyIdBytesIn[i] === 0;
    }
    component policyIdClose = Multiplexer(1, MAX_B);
    for (var i = 0; i < MAX_B; i++) policyIdClose.inp[i][0] <== bytes[i];
    policyIdClose.sel <== policyIdValueOffset + policyIdLen;
    policyIdClose.out[0] === 0x22;

    // policy.leafHash = "0x" + 64 hex chars + closing `"` → Bits256ToField
    component leafHashSlice = BPFSliceFast(MAX_B, 67);
    for (var i = 0; i < MAX_B; i++) leafHashSlice.bytes[i] <== bytes[i];
    leafHashSlice.offset <== policyLeafHashValueOffset;
    leafHashSlice.out[0] === 0x30;
    leafHashSlice.out[1] === 0x78;
    leafHashSlice.out[66] === 0x22;

    component leafHashHex = HexBytesFromAscii(32);
    for (var i = 0; i < 64; i++) leafHashHex.ascii[i] <== leafHashSlice.out[2 + i];

    component leafHashBits[32];
    signal digestBits[256];
    for (var i = 0; i < 32; i++) {
        leafHashBits[i] = Num2Bits(8);
        leafHashBits[i].in <== leafHashHex.bytes[i];
        for (var b = 0; b < 8; b++) {
            digestBits[i * 8 + (7 - b)] <== leafHashBits[i].out[b];
        }
    }
    component leafHashPack = Bits256ToFieldFast();
    for (var i = 0; i < 256; i++) leafHashPack.digestBits[i] <== digestBits[i];
    policyLeafHash <== leafHashPack.packed;

    // policy.bindingSchema = "qkb-binding-core/v1"  // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
    component policySchemaSlice = BPFSliceFast(MAX_B, 20);
    for (var i = 0; i < MAX_B; i++) policySchemaSlice.bytes[i] <== bytes[i];
    policySchemaSlice.offset <== policyBindingSchemaValueOffset;
    for (var i = 0; i < 20; i++) policySchemaSlice.out[i] === CORE_SCHEMA_VAL[i];

    // policyVersion decimal digits + closing `}` pin
    component policyVersionSlice = BPFSliceFast(MAX_B, MAX_TS_DIGITS);
    for (var i = 0; i < MAX_B; i++) policyVersionSlice.bytes[i] <== bytes[i];
    policyVersionSlice.offset <== policyVersionValueOffset;
    component policyVersionParse = DecimalAsciiToUint64(MAX_TS_DIGITS);
    for (var i = 0; i < MAX_TS_DIGITS; i++) policyVersionParse.ascii[i] <== policyVersionSlice.out[i];
    policyVersionParse.numDigits <== policyVersionDigitCount;
    policyVersion <== policyVersionParse.value;
    policyVersion === policyVersionIn;

    component policyVersionClose = Multiplexer(1, MAX_B);
    for (var i = 0; i < MAX_B; i++) policyVersionClose.inp[i][0] <== bytes[i];
    policyVersionClose.sel <== policyVersionValueOffset + policyVersionDigitCount;
    policyVersionClose.out[0] === 0x7D;

    // timestamp decimal digits + closing `,` pin
    component tsSlice = BPFSliceFast(MAX_B, MAX_TS_DIGITS);
    for (var i = 0; i < MAX_B; i++) tsSlice.bytes[i] <== bytes[i];
    tsSlice.offset <== tsValueOffset;
    component tsParse = DecimalAsciiToUint64(MAX_TS_DIGITS);
    for (var i = 0; i < MAX_TS_DIGITS; i++) tsParse.ascii[i] <== tsSlice.out[i];
    tsParse.numDigits <== tsDigitCount;
    tsValue <== tsParse.value;

    component tsClose = Multiplexer(1, MAX_B);
    for (var i = 0; i < MAX_B; i++) tsClose.inp[i][0] <== bytes[i];
    tsClose.sel <== tsValueOffset + tsDigitCount;
    tsClose.out[0] === 0x2C;

    // version = "QKB/2.0"  // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
    var VER_VAL[8] = [0x51,0x4B,0x42,0x2F,0x32,0x2E,0x30,0x22];
    component verSlice = BPFSliceFast(MAX_B, 8);
    for (var i = 0; i < MAX_B; i++) verSlice.bytes[i] <== bytes[i];
    verSlice.offset <== versionValueOffset;
    for (var i = 0; i < 8; i++) verSlice.out[i] === VER_VAL[i];
}
