pragma circom 2.1.9;

// BindingParseV2Core — draft parser for the circuit-bound `QKB/2.0` core.
//
// This is the successor-oriented analogue of BindingParseFull.circom. It is
// intentionally narrow: it extracts the fields the draft leaf circuit needs
// today and pins the field names / value encodings at prover-supplied offsets.
//
// Circuit-bound object shape (JCS key order):
//   {
//     "assertions": {...},
//     "context":"0x...",
//     "nonce":"0x<64hex>",
//     "pk":"0x04<128hex>",
//     "policy":{"bindingSchema":"qkb-binding-core/v1","leafHash":"0x<64hex>",...},
//     "scheme":"secp256k1",
//     "statementSchema":"qkb-binding-core/v1",
//     "timestamp":<digits>,
//     "version":"QKB/2.0"
//   }
//
// Current hardening status:
//   pinned exactly:
//     - `assertions`
//     - `statementSchema`
//     - `version`
//     - `nonce`
//     - `pk`
//     - `scheme`
//     - `context`
//     - `policy.policyId`
//     - `policy.bindingSchema`
//     - `policy.leafHash`
//     - `policy.policyVersion`
//     - `timestamp`
//
// This locks the whole machine-readable core shape used by `bindingCoreV2(...)`.

include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "./BindingKeyMatch.circom";
include "./BindingHex.circom";
include "./BindingDecimal.circom";

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

template BPFHexBytesVar(MAX_BYTES) {
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

template Bits256ToField() {
    signal input digestBits[256];
    signal output packed;
    var acc = 0;
    for (var i = 0; i < 256; i++) acc = acc * 2 + digestBits[i];
    packed <== acc;
}

template BindingParseV2Core(MAX_B, MAX_CTX, MAX_TS_DIGITS) {
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

    // "pk":"  (6 bytes)
    var PK_KEY[6] = [0x22, 0x70, 0x6B, 0x22, 0x3A, 0x22];
    component pkKey = BindingKeyAt(MAX_B, 6);
    for (var i = 0; i < MAX_B; i++) pkKey.bytes[i] <== bytes[i];
    pkKey.offset <== pkValueOffset;
    for (var i = 0; i < 6; i++) pkKey.key[i] <== PK_KEY[i];

    // "scheme":"  (10 bytes)
    var SCH_KEY[10] = [0x22, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x65, 0x22, 0x3A, 0x22];
    component schKey = BindingKeyAt(MAX_B, 10);
    for (var i = 0; i < MAX_B; i++) schKey.bytes[i] <== bytes[i];
    schKey.offset <== schemeValueOffset;
    for (var i = 0; i < 10; i++) schKey.key[i] <== SCH_KEY[i];

    // "assertions":  (13 bytes)
    var ASSERT_KEY[13] = [0x22,0x61,0x73,0x73,0x65,0x72,0x74,0x69,0x6F,0x6E,0x73,0x22,0x3A];
    component assertKey = BindingKeyAt(MAX_B, 13);
    for (var i = 0; i < MAX_B; i++) assertKey.bytes[i] <== bytes[i];
    assertKey.offset <== assertionsValueOffset;
    for (var i = 0; i < 13; i++) assertKey.key[i] <== ASSERT_KEY[i];

    // "statementSchema":"  (19 bytes)
    var STMT_KEY[19] = [
        0x22,0x73,0x74,0x61,0x74,0x65,0x6D,0x65,0x6E,0x74,0x53,0x63,0x68,0x65,0x6D,0x61,0x22,0x3A,0x22
    ];
    component stmtKey = BindingKeyAt(MAX_B, 19);
    for (var i = 0; i < MAX_B; i++) stmtKey.bytes[i] <== bytes[i];
    stmtKey.offset <== statementSchemaValueOffset;
    for (var i = 0; i < 19; i++) stmtKey.key[i] <== STMT_KEY[i];

    // "nonce":"  (9 bytes)
    var NONCE_KEY[9] = [0x22,0x6E,0x6F,0x6E,0x63,0x65,0x22,0x3A,0x22];
    component nonceKey = BindingKeyAt(MAX_B, 9);
    for (var i = 0; i < MAX_B; i++) nonceKey.bytes[i] <== bytes[i];
    nonceKey.offset <== nonceValueOffset;
    for (var i = 0; i < 9; i++) nonceKey.key[i] <== NONCE_KEY[i];

    // "context":"  (11 bytes)
    var CTX_KEY[11] = [0x22, 0x63, 0x6F, 0x6E, 0x74, 0x65, 0x78, 0x74, 0x22, 0x3A, 0x22];
    component ctxKey = BindingKeyAt(MAX_B, 11);
    for (var i = 0; i < MAX_B; i++) ctxKey.bytes[i] <== bytes[i];
    ctxKey.offset <== ctxValueOffset;
    for (var i = 0; i < 11; i++) ctxKey.key[i] <== CTX_KEY[i];

    // "policyId":"  (12 bytes)
    var POLICY_ID_KEY[12] = [0x22,0x70,0x6F,0x6C,0x69,0x63,0x79,0x49,0x64,0x22,0x3A,0x22];
    component policyIdKey = BindingKeyAt(MAX_B, 12);
    for (var i = 0; i < MAX_B; i++) policyIdKey.bytes[i] <== bytes[i];
    policyIdKey.offset <== policyIdValueOffset;
    for (var i = 0; i < 12; i++) policyIdKey.key[i] <== POLICY_ID_KEY[i];

    // "leafHash":"  (12 bytes) inside the nested policy object.
    var LEAF_KEY[12] = [0x22,0x6C,0x65,0x61,0x66,0x48,0x61,0x73,0x68,0x22,0x3A,0x22];
    component leafKey = BindingKeyAt(MAX_B, 12);
    for (var i = 0; i < MAX_B; i++) leafKey.bytes[i] <== bytes[i];
    leafKey.offset <== policyLeafHashValueOffset;
    for (var i = 0; i < 12; i++) leafKey.key[i] <== LEAF_KEY[i];

    // "bindingSchema":"  (17 bytes)
    var POLICY_SCHEMA_KEY[17] = [0x22,0x62,0x69,0x6E,0x64,0x69,0x6E,0x67,0x53,0x63,0x68,0x65,0x6D,0x61,0x22,0x3A,0x22];
    component policySchemaKey = BindingKeyAt(MAX_B, 17);
    for (var i = 0; i < MAX_B; i++) policySchemaKey.bytes[i] <== bytes[i];
    policySchemaKey.offset <== policyBindingSchemaValueOffset;
    for (var i = 0; i < 17; i++) policySchemaKey.key[i] <== POLICY_SCHEMA_KEY[i];

    // "policyVersion":  (16 bytes)
    var POLICY_VERSION_KEY[16] = [0x22,0x70,0x6F,0x6C,0x69,0x63,0x79,0x56,0x65,0x72,0x73,0x69,0x6F,0x6E,0x22,0x3A];
    component policyVersionKey = BindingKeyAt(MAX_B, 16);
    for (var i = 0; i < MAX_B; i++) policyVersionKey.bytes[i] <== bytes[i];
    policyVersionKey.offset <== policyVersionValueOffset;
    for (var i = 0; i < 16; i++) policyVersionKey.key[i] <== POLICY_VERSION_KEY[i];

    // "timestamp":  (12 bytes)
    var TS_KEY[12] = [
        0x22, 0x74, 0x69, 0x6D, 0x65, 0x73, 0x74, 0x61, 0x6D, 0x70, 0x22, 0x3A
    ];
    component tsKey = BindingKeyAt(MAX_B, 12);
    for (var i = 0; i < MAX_B; i++) tsKey.bytes[i] <== bytes[i];
    tsKey.offset <== tsValueOffset;
    for (var i = 0; i < 12; i++) tsKey.key[i] <== TS_KEY[i];

    // "version":"  (11 bytes)
    var VER_KEY[11] = [0x22,0x76,0x65,0x72,0x73,0x69,0x6F,0x6E,0x22,0x3A,0x22];
    component verKey = BindingKeyAt(MAX_B, 11);
    for (var i = 0; i < MAX_B; i++) verKey.bytes[i] <== bytes[i];
    verKey.offset <== versionValueOffset;
    for (var i = 0; i < 11; i++) verKey.key[i] <== VER_KEY[i];

    // pk = "0x" + 130 hex chars
    component pkSlice = BPFSlice(MAX_B, 132);
    for (var i = 0; i < MAX_B; i++) pkSlice.bytes[i] <== bytes[i];
    pkSlice.offset <== pkValueOffset;
    pkSlice.out[0] === 0x30;
    pkSlice.out[1] === 0x78;
    component pkHex = HexBytesFromAscii(65);
    for (var i = 0; i < 130; i++) pkHex.ascii[i] <== pkSlice.out[2 + i];
    for (var i = 0; i < 65; i++) pkBytes[i] <== pkHex.bytes[i];

    // scheme = "secp256k1"
    var SCH_VAL[10] = [
        0x73, 0x65, 0x63, 0x70, 0x32, 0x35, 0x36, 0x6B, 0x31, 0x22
    ];
    component schSlice = BPFSlice(MAX_B, 10);
    for (var i = 0; i < MAX_B; i++) schSlice.bytes[i] <== bytes[i];
    schSlice.offset <== schemeValueOffset;
    for (var i = 0; i < 10; i++) schSlice.out[i] === SCH_VAL[i];

    // assertions object — exact fixed JSON value.
    var ASSERT_VAL[91] = [
        0x7B,0x22,0x61,0x63,0x63,0x65,0x70,0x74,0x73,0x41,0x74,0x74,0x72,0x69,0x62,0x75,0x74,0x69,0x6F,0x6E,0x22,0x3A,0x74,0x72,0x75,0x65,0x2C,
        0x22,0x62,0x69,0x6E,0x64,0x73,0x43,0x6F,0x6E,0x74,0x65,0x78,0x74,0x22,0x3A,0x74,0x72,0x75,0x65,0x2C,
        0x22,0x6B,0x65,0x79,0x43,0x6F,0x6E,0x74,0x72,0x6F,0x6C,0x22,0x3A,0x74,0x72,0x75,0x65,0x2C,
        0x22,0x72,0x65,0x76,0x6F,0x63,0x61,0x74,0x69,0x6F,0x6E,0x52,0x65,0x71,0x75,0x69,0x72,0x65,0x64,0x22,0x3A,0x74,0x72,0x75,0x65,0x7D
    ];
    component assertSlice = BPFSlice(MAX_B, 91);
    for (var i = 0; i < MAX_B; i++) assertSlice.bytes[i] <== bytes[i];
    assertSlice.offset <== assertionsValueOffset;
    for (var i = 0; i < 91; i++) assertSlice.out[i] === ASSERT_VAL[i];

    // statementSchema = "qkb-binding-core/v1"
    var CORE_SCHEMA_VAL[20] = [
        0x71,0x6B,0x62,0x2D,0x62,0x69,0x6E,0x64,0x69,0x6E,0x67,0x2D,0x63,0x6F,0x72,0x65,0x2F,0x76,0x31,0x22
    ];
    component stmtSlice = BPFSlice(MAX_B, 20);
    for (var i = 0; i < MAX_B; i++) stmtSlice.bytes[i] <== bytes[i];
    stmtSlice.offset <== statementSchemaValueOffset;
    for (var i = 0; i < 20; i++) stmtSlice.out[i] === CORE_SCHEMA_VAL[i];

    // nonce = "0x" + 64 hex chars
    component nonceSlice = BPFSlice(MAX_B, 66);
    for (var i = 0; i < MAX_B; i++) nonceSlice.bytes[i] <== bytes[i];
    nonceSlice.offset <== nonceValueOffset;
    nonceSlice.out[0] === 0x30;
    nonceSlice.out[1] === 0x78;
    component nonceHex = HexBytesFromAscii(32);
    for (var i = 0; i < 64; i++) nonceHex.ascii[i] <== nonceSlice.out[2 + i];
    for (var i = 0; i < 32; i++) {
        nonceBytes[i] <== nonceHex.bytes[i];
        nonceBytes[i] === nonceBytesIn[i];
    }

    // context = "0x" + ctxHexLen hex chars
    component ctxPrefix = BPFSlice(MAX_B, 2);
    for (var i = 0; i < MAX_B; i++) ctxPrefix.bytes[i] <== bytes[i];
    ctxPrefix.offset <== ctxValueOffset;
    ctxPrefix.out[0] === 0x30;
    ctxPrefix.out[1] === 0x78;

    component ctxHexSlice = BPFSliceVar(MAX_B, 2 * MAX_CTX);
    for (var i = 0; i < MAX_B; i++) ctxHexSlice.bytes[i] <== bytes[i];
    ctxHexSlice.offset <== ctxValueOffset + 2;
    ctxHexSlice.valueLen <== ctxHexLen;

    component ctxDecode = BPFHexBytesVar(MAX_CTX);
    for (var i = 0; i < 2 * MAX_CTX; i++) ctxDecode.ascii[i] <== ctxHexSlice.out[i];
    ctxDecode.hexLen <== ctxHexLen;
    for (var i = 0; i < MAX_CTX; i++) ctxBytes[i] <== ctxDecode.bytes[i];

    ctxLen <-- ctxHexLen \ 2;
    2 * ctxLen === ctxHexLen;

    // policyId string — exact byte equality against witness-provided bytes.
    component policyIdBound = LessEqThan(16);
    policyIdBound.in[0] <== policyIdLen;
    policyIdBound.in[1] <== MAX_POLICY_ID;
    policyIdBound.out === 1;
    component policyIdSlice = BPFSliceVar(MAX_B, MAX_POLICY_ID);
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

    // policy.leafHash = "0x" + 64 hex chars, already reduced mod p off-chain.
    component leafHashSlice = BPFSlice(MAX_B, 66);
    for (var i = 0; i < MAX_B; i++) leafHashSlice.bytes[i] <== bytes[i];
    leafHashSlice.offset <== policyLeafHashValueOffset;
    leafHashSlice.out[0] === 0x30;
    leafHashSlice.out[1] === 0x78;

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
    component leafHashPack = Bits256ToField();
    for (var i = 0; i < 256; i++) leafHashPack.digestBits[i] <== digestBits[i];
    policyLeafHash <== leafHashPack.packed;

    // policy.bindingSchema = "qkb-binding-core/v1"
    component policySchemaSlice = BPFSlice(MAX_B, 20);
    for (var i = 0; i < MAX_B; i++) policySchemaSlice.bytes[i] <== bytes[i];
    policySchemaSlice.offset <== policyBindingSchemaValueOffset;
    for (var i = 0; i < 20; i++) policySchemaSlice.out[i] === CORE_SCHEMA_VAL[i];

    // policyVersion decimal digits — exact value equality against witness input.
    component policyVersionSlice = BPFSlice(MAX_B, MAX_TS_DIGITS);
    for (var i = 0; i < MAX_B; i++) policyVersionSlice.bytes[i] <== bytes[i];
    policyVersionSlice.offset <== policyVersionValueOffset;
    component policyVersionParse = DecimalAsciiToUint64(MAX_TS_DIGITS);
    for (var i = 0; i < MAX_TS_DIGITS; i++) policyVersionParse.ascii[i] <== policyVersionSlice.out[i];
    policyVersionParse.numDigits <== policyVersionDigitCount;
    policyVersion <== policyVersionParse.value;
    policyVersion === policyVersionIn;

    // timestamp decimal digits
    component tsSlice = BPFSlice(MAX_B, MAX_TS_DIGITS);
    for (var i = 0; i < MAX_B; i++) tsSlice.bytes[i] <== bytes[i];
    tsSlice.offset <== tsValueOffset;
    component tsParse = DecimalAsciiToUint64(MAX_TS_DIGITS);
    for (var i = 0; i < MAX_TS_DIGITS; i++) tsParse.ascii[i] <== tsSlice.out[i];
    tsParse.numDigits <== tsDigitCount;
    tsValue <== tsParse.value;

    // version = "QKB/2.0"
    var VER_VAL[8] = [0x51,0x4B,0x42,0x2F,0x32,0x2E,0x30,0x22];
    component verSlice = BPFSlice(MAX_B, 8);
    for (var i = 0; i < MAX_B; i++) verSlice.bytes[i] <== bytes[i];
    verSlice.offset <== versionValueOffset;
    for (var i = 0; i < 8; i++) verSlice.out[i] === VER_VAL[i];
}
