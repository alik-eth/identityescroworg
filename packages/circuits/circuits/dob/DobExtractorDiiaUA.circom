pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";

// DobExtractorDiiaUA — extracts the DOB embedded in Diia QES leaf certs under
// a SubjectDirectoryAttributes extension (X.509 ext OID 2.5.29.9). The inner
// attribute OID Diia uses is UA-specific (1.2.804.2.1.1.1.11.1.4.11.1) and
// the value is an ASN.1 PrintableString "YYYYMMDD-NNNNN" (NOT GeneralizedTime
// as earlier drafts assumed).
//
// Encoding (hex offsets from the start of the outer OID bytes, `p0`):
//   p0 +  0..4   06 03 55 1D 09        -- ext OID 2.5.29.9  (5 bytes)
//   p0 +  5..6   04 24                 -- OCTET STRING wrap
//   p0 +  7..8   30 22                 -- SEQUENCE OF Attribute
//   p0 +  9..10  30 20                 -- first Attribute SEQUENCE
//   p0 + 11..24  06 0C 2A 86 24 02 01 01 01 0B 01 04 0B 01
//                                      -- attr OID 1.2.804.2.1.1.1.11.1.4.11.1
//   p0 + 25..26  31 10                 -- SET of 16 bytes
//   p0 + 27..28  13 0E                 -- PrintableString, 14 bytes
//   p0 + 29..36  8 ASCII digits YYYYMMDD
//
// sourceTag = 1 (Diia UA, per IDobExtractor.circom).
//
// Constraint-budget note: the scan is a bank of byte-equalities across all
// possible outer-OID start positions p ∈ [0, MAX_DER - 5]. Because we enforce
// `hitSum === dobSupported` (0 or 1), the one-hot `hitMasked[]` lets us pull
// the 8 digit bytes and the 14-byte inner-OID match as sum-of-products with
// no additional multiplexers.
template DobExtractor(MAX_DER) {
    var OUTER_OID_LEN = 5;
    var INNER_OID_LEN = 14;
    var DIGIT_COUNT = 8;
    var DIGIT_OFFSET_FROM_P0 = 29;
    var INNER_OID_OFFSET_FROM_P0 = 11;

    var OUTER_OID[5] = [0x06, 0x03, 0x55, 0x1d, 0x09];
    var INNER_OID[14] = [0x06, 0x0c, 0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x0b, 0x01, 0x04, 0x0b, 0x01];

    signal input leafDER[MAX_DER];
    signal input leafDerLen;

    signal output dobYmd;
    signal output sourceTag;
    signal output dobSupported;

    sourceTag <== 1;

    // =========================================================================
    // 1. Scan for the 5-byte outer OID header. We need enough room after p0
    //    to contain the 37-byte DOB attribute block (up to digit end at p0+36),
    //    so valid start positions run up to MAX_DER - 37.
    // =========================================================================
    var BLOCK_LEN = DIGIT_OFFSET_FROM_P0 + DIGIT_COUNT;  // 37
    var NPOS = MAX_DER - BLOCK_LEN + 1;

    component byteEq[NPOS][OUTER_OID_LEN];
    component inLen[NPOS];
    signal m01[NPOS];
    signal m012[NPOS];
    signal m0123[NPOS];
    signal allMatch[NPOS];
    signal hitMasked[NPOS];

    var hitAcc = 0;
    for (var p = 0; p < NPOS; p++) {
        for (var b = 0; b < OUTER_OID_LEN; b++) {
            byteEq[p][b] = IsEqual();
            byteEq[p][b].in[0] <== leafDER[p + b];
            byteEq[p][b].in[1] <== OUTER_OID[b];
        }
        m01[p]   <== byteEq[p][0].out * byteEq[p][1].out;
        m012[p]  <== m01[p]  * byteEq[p][2].out;
        m0123[p] <== m012[p] * byteEq[p][3].out;
        allMatch[p] <== m0123[p] * byteEq[p][4].out;

        // Gate: the entire 37-byte block must fit within leafDerLen so we
        // don't read digit bytes out of the padded region.
        inLen[p] = LessEqThan(16);
        inLen[p].in[0] <== p + BLOCK_LEN;
        inLen[p].in[1] <== leafDerLen;

        hitMasked[p] <== allMatch[p] * inLen[p].out;
        hitAcc += hitMasked[p];
    }
    signal hitSum;
    hitSum <== hitAcc;

    // =========================================================================
    // 2. Pull the 14-byte inner attribute OID and the 8 digit bytes via
    //    sum-of-products against hitMasked. Since hitMasked is one-hot on a
    //    single p0 (guaranteed by the `hitSum === dobSupported` constraint
    //    below), these evaluate to leafDER[p0 + offset] exactly.
    // =========================================================================
    // Sum-of-products pick: each position contributes (hitMasked[p] * byte[p+offset])
    // as an explicit quadratic signal; we then sum the linear combination into
    // the output byte. Going through per-position signals avoids circom's var
    // accumulator, which only collects linear terms.
    signal innerOidProd[INNER_OID_LEN][NPOS];
    signal innerOidByte[INNER_OID_LEN];
    for (var j = 0; j < INNER_OID_LEN; j++) {
        var acc = 0;
        for (var p = 0; p < NPOS; p++) {
            innerOidProd[j][p] <== hitMasked[p] * leafDER[p + INNER_OID_OFFSET_FROM_P0 + j];
            acc += innerOidProd[j][p];
        }
        innerOidByte[j] <== acc;
    }

    signal digitProd[DIGIT_COUNT][NPOS];
    signal digitByte[DIGIT_COUNT];
    for (var k = 0; k < DIGIT_COUNT; k++) {
        var acc = 0;
        for (var p = 0; p < NPOS; p++) {
            digitProd[k][p] <== hitMasked[p] * leafDER[p + DIGIT_OFFSET_FROM_P0 + k];
            acc += digitProd[k][p];
        }
        digitByte[k] <== acc;
    }

    // =========================================================================
    // 3. Validate the inner OID matches Diia's attr OID when dobSupported=1.
    //    When no outer hit (dobSupported=0), all innerOidByte[] are 0 and we
    //    skip the check; otherwise every byte must equal the literal.
    // =========================================================================
    component innerEq[INNER_OID_LEN];
    signal innerMatch[INNER_OID_LEN + 1];
    innerMatch[0] <== 1;
    for (var j = 0; j < INNER_OID_LEN; j++) {
        innerEq[j] = IsEqual();
        innerEq[j].in[0] <== innerOidByte[j];
        innerEq[j].in[1] <== INNER_OID[j];
        innerMatch[j + 1] <== innerMatch[j] * innerEq[j].out;
    }
    signal innerOidAllMatch;
    innerOidAllMatch <== innerMatch[INNER_OID_LEN];

    // =========================================================================
    // 4. Validate each digit byte is ASCII [0x30..0x39] when dobSupported=1,
    //    and convert to integer k_digit = digitByte - 0x30.
    // =========================================================================
    component digitGe[DIGIT_COUNT];
    component digitLe[DIGIT_COUNT];
    signal digit[DIGIT_COUNT];
    signal digitInRange[DIGIT_COUNT];
    signal digitsAllValid[DIGIT_COUNT + 1];
    digitsAllValid[0] <== 1;
    for (var k = 0; k < DIGIT_COUNT; k++) {
        digitGe[k] = GreaterEqThan(8);
        digitGe[k].in[0] <== digitByte[k];
        digitGe[k].in[1] <== 0x30;
        digitLe[k] = LessEqThan(8);
        digitLe[k].in[0] <== digitByte[k];
        digitLe[k].in[1] <== 0x39;
        digitInRange[k] <== digitGe[k].out * digitLe[k].out;
        digitsAllValid[k + 1] <== digitsAllValid[k] * digitInRange[k];
        digit[k] <== digitByte[k] - 0x30;
    }
    signal digitsValid;
    digitsValid <== digitsAllValid[DIGIT_COUNT];

    // =========================================================================
    // 5. dobSupported = outerFound AND innerOidMatch AND all-digits-valid.
    //    Force hitSum === outerFound so the sum-of-products above collapses
    //    to a single p0 selector (any adversarial multi-hit DER fails here).
    //    Using outerFound (not dobSupported) keeps the multi-hit guard
    //    orthogonal to the inner-OID and digit-validity checks.
    // =========================================================================
    component isZeroSum = IsZero();
    isZeroSum.in <== hitSum;
    signal outerFound;
    outerFound <== 1 - isZeroSum.out;

    signal inAnd;
    inAnd <== outerFound * innerOidAllMatch;
    dobSupported <== inAnd * digitsValid;

    hitSum === outerFound;

    // =========================================================================
    // 6. dobYmd = digit[0]*10^7 + … + digit[7]*10^0, masked by dobSupported
    //    so the non-DOB path emits a clean 0 (digit[k] = digitByte[k] - 0x30
    //    would otherwise leak -0x30 for every zero-padded byte).
    // =========================================================================
    var POW10[8] = [10000000, 1000000, 100000, 10000, 1000, 100, 10, 1];
    var ymdAcc = 0;
    for (var k = 0; k < DIGIT_COUNT; k++) ymdAcc += digit[k] * POW10[k];
    signal ymdRaw;
    ymdRaw <== ymdAcc;
    dobYmd <== ymdRaw * dobSupported;
}
