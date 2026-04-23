pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";

// DobExtractorDiiaUA — extracts the DOB embedded in Diia QES leaf certs under
// a SubjectDirectoryAttributes extension (X.509 ext OID 2.5.29.9). The inner
// attribute OID Diia uses is UA-specific (1.2.804.2.1.1.1.11.1.4.11.1) and
// the value is an ASN.1 PrintableString "YYYYMMDD-NNNNN" — NOT GeneralizedTime
// as earlier drafts assumed. See spec §Circuit family + task M2.3b for the
// full digit-extract path.
//
// Current stage (M2.3): detect presence of the ext-OID header bytes
// {06 03 55 1D 09} inside leafDerLen; set dobSupported=1 iff present. dobYmd
// is left at 0 until M2.3b wires the PrintableString read.
//
// sourceTag = 1 (Diia UA, per IDobExtractor.circom).
template DobExtractor() {
    var MAX_DER = 2048;
    var OID_LEN = 5;
    // OID 2.5.29.9 header: 06 03 55 1D 09
    var OID[5] = [0x06, 0x03, 0x55, 0x1d, 0x09];

    signal input leafDER[MAX_DER];
    signal input leafDerLen;

    signal output dobYmd;
    signal output sourceTag;
    signal output dobSupported;

    sourceTag <== 1;

    // =========================================================================
    // Scan leafDER[0..leafDerLen-OID_LEN] for the 5-byte OID header.
    // For each starting position p we compute hitMasked[p] = 1 iff
    //   - leafDER[p..p+4] == OID, AND
    //   - p + OID_LEN <= leafDerLen  (the window sits entirely within the
    //     actual DER, not the zero padding beyond leafDerLen).
    // =========================================================================
    var NPOS = MAX_DER - OID_LEN + 1;  // valid starting positions
    component byteEq[NPOS][OID_LEN];
    component inLen[NPOS];
    signal allMatch[NPOS];              // product of the 5 byte-equality bits
    signal hitMasked[NPOS];             // allMatch * inLen (both 0/1)
    // Intermediate signals for 5-way AND (circom is quadratic — chain products).
    signal m01[NPOS];
    signal m012[NPOS];
    signal m0123[NPOS];

    signal hitSum;
    var hitAcc = 0;

    for (var p = 0; p < NPOS; p++) {
        for (var b = 0; b < OID_LEN; b++) {
            byteEq[p][b] = IsEqual();
            byteEq[p][b].in[0] <== leafDER[p + b];
            byteEq[p][b].in[1] <== OID[b];
        }
        // Chain products: allMatch = b0 * b1 * b2 * b3 * b4
        m01[p]   <== byteEq[p][0].out * byteEq[p][1].out;
        m012[p]  <== m01[p]  * byteEq[p][2].out;
        m0123[p] <== m012[p] * byteEq[p][3].out;
        allMatch[p] <== m0123[p] * byteEq[p][4].out;

        // Gate: require the match window to fit within leafDerLen.
        inLen[p] = LessEqThan(16);
        inLen[p].in[0] <== p + OID_LEN;
        inLen[p].in[1] <== leafDerLen;

        hitMasked[p] <== allMatch[p] * inLen[p].out;
        hitAcc += hitMasked[p];
    }
    hitSum <== hitAcc;

    // dobSupported = 1 iff hitSum >= 1. Since DER is well-formed, the 5-byte
    // sequence `06 03 55 1D 09` should appear at most a handful of times; we
    // normalize via IsZero.
    component isZeroSum = IsZero();
    isZeroSum.in <== hitSum;
    dobSupported <== 1 - isZeroSum.out;

    // TODO(M2.3b): locate the inner attribute OID 1.2.804.2.1.1.1.11.1.4.11.1
    // (14-byte prefix `06 0C 2A 86 24 02 01 01 01 0B 01 04 0B 01`), read the
    // following PrintableString (tag 0x13) and decode the first 8 ASCII digits
    // (YYYYMMDD) via 10^k weighting. Until then, dobYmd = 0 and registry
    // consumers must gate on dobSupported only.
    dobYmd <== 0;
}

component main = DobExtractor();
