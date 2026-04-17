pragma circom 2.1.9;

// Long-form ASN.1 TLV check + RSA 2048 SPKI modulus/exponent extractors.
//
// Motivation: the Phase-1 short-form Asn1ShortTLVCheck (X509Parse.circom)
// only covers content < 128 bytes. A 2048-bit RSA modulus encodes as a
// 257-byte INTEGER (256 modulus bytes + one sign-byte 0x00), whose length
// field uses DER long-form: the tag is followed by `0x82` (indicating
// 2 length bytes) and then a big-endian 16-bit length.
//
// Concrete layout for a 2048-bit modulus:
//   bytes[modulusOffset - 5] == 0x02   (INTEGER tag)
//   bytes[modulusOffset - 4] == 0x82   (long-form indicator: 2 length bytes)
//   bytes[modulusOffset - 3] == 0x01   (high byte of length = 0x0101 = 257)
//   bytes[modulusOffset - 2] == 0x01   (low  byte of length)
//   bytes[modulusOffset - 1] == 0x00   (sign-bit padding — top bit of
//                                       modulus is always 1 for a proper
//                                       2048-bit modulus, so DER prepends
//                                       a zero byte)
//   bytes[modulusOffset .. modulusOffset + 255] == 256-byte modulus
//
// The exponent is almost always 65537 = 0x010001, encoded as a 3-byte
// INTEGER:
//   bytes[exponentOffset - 2] == 0x02
//   bytes[exponentOffset - 1] == 0x03
//   bytes[exponentOffset .. +2] == 0x01 0x00 0x01
//
// This circuit constrains the prover to pick offsets that land on real
// TLV headers matching these fixed patterns, and surfaces the 256 modulus
// bytes as outputs. It does NOT validate anything about the rest of the
// certificate — that is handled separately by X509Parse + X509Validity +
// the Merkle inclusion check on the issuer chain.

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";

// =========================================================================
// Asn1LongTLVCheck — asserts a TLV with DER 2-byte long-form length.
//
// Expected bytes at the 4 positions preceding `offset`:
//   offset - 4 : expectedTag
//   offset - 3 : 0x82
//   offset - 2 : expectedLenHi
//   offset - 1 : expectedLenLo
// =========================================================================
template Asn1LongTLVCheck(MAX_LEN, expectedTag, expectedLenHi, expectedLenLo) {
    signal input bytes[MAX_LEN];
    signal input offset;

    var CONTENT_LEN = expectedLenHi * 256 + expectedLenLo;

    // 4 ≤ offset and offset + CONTENT_LEN ≤ MAX_LEN.
    component lo = GreaterEqThan(16);
    lo.in[0] <== offset;
    lo.in[1] <== 4;
    lo.out === 1;

    component hi = LessEqThan(16);
    hi.in[0] <== offset + CONTENT_LEN;
    hi.in[1] <== MAX_LEN;
    hi.out === 1;

    component mTag = Multiplexer(1, MAX_LEN);
    component mInd = Multiplexer(1, MAX_LEN);
    component mHi = Multiplexer(1, MAX_LEN);
    component mLo = Multiplexer(1, MAX_LEN);
    for (var i = 0; i < MAX_LEN; i++) {
        mTag.inp[i][0] <== bytes[i];
        mInd.inp[i][0] <== bytes[i];
        mHi.inp[i][0] <== bytes[i];
        mLo.inp[i][0] <== bytes[i];
    }
    mTag.sel <== offset - 4;
    mInd.sel <== offset - 3;
    mHi.sel <== offset - 2;
    mLo.sel <== offset - 1;

    mTag.out[0] === expectedTag;
    mInd.out[0] === 0x82;
    mHi.out[0] === expectedLenHi;
    mLo.out[0] === expectedLenLo;
}

// =========================================================================
// RsaSpkiExtract2048 — pulls the 256-byte modulus and verifies the e=65537
// exponent encoding.
//
// Inputs:
//   bytes[MAX_LEN]       the DER buffer (SPKI prefix or full cert, padded)
//   modulusOffset        first modulus byte (after the 0x00 sign pad)
//   exponentOffset       first byte of the 3-byte exponent value
//
// Outputs:
//   modulusBytes[256]    big-endian 2048-bit modulus
// =========================================================================
template RsaSpkiExtract2048(MAX_LEN) {
    signal input bytes[MAX_LEN];
    signal input modulusOffset;
    signal input exponentOffset;
    signal output modulusBytes[256];

    // Long-form TLV: INTEGER tag 0x02, length 0x0101 = 257.
    // Content length in CONTENT_LEN includes the sign byte; the caller hands
    // us `modulusOffset` at the byte AFTER the sign pad, so we also need to
    // assert bytes[modulusOffset - 1] == 0x00 separately and treat the
    // effective content check at a shifted offset.
    //
    // We set expectedTag=0x02, lenHi=0x01, lenLo=0x01 against a "virtual
    // offset" one byte before modulusOffset — then separately check the sign
    // byte at modulusOffset - 1.
    component tlv = Asn1LongTLVCheck(MAX_LEN, 0x02, 0x01, 0x01);
    for (var i = 0; i < MAX_LEN; i++) tlv.bytes[i] <== bytes[i];
    tlv.offset <== modulusOffset - 1;

    // Sign byte: bytes[modulusOffset - 1] == 0x00.
    component mSign = Multiplexer(1, MAX_LEN);
    for (var i = 0; i < MAX_LEN; i++) mSign.inp[i][0] <== bytes[i];
    mSign.sel <== modulusOffset - 1;
    mSign.out[0] === 0x00;

    // Extract the 256 modulus bytes.
    component pick[256];
    for (var i = 0; i < 256; i++) {
        pick[i] = Multiplexer(1, MAX_LEN);
        for (var j = 0; j < MAX_LEN; j++) pick[i].inp[j][0] <== bytes[j];
        pick[i].sel <== modulusOffset + i;
        modulusBytes[i] <== pick[i].out[0];
    }

    // Exponent check: 3-byte INTEGER with value 65537 (0x010001).
    // Preamble at (expOff - 2, expOff - 1) = (0x02, 0x03).
    // Content at (expOff, expOff + 1, expOff + 2) = (0x01, 0x00, 0x01).
    component eBound = LessEqThan(16);
    eBound.in[0] <== exponentOffset + 3;
    eBound.in[1] <== MAX_LEN;
    eBound.out === 1;
    component eLo = GreaterEqThan(16);
    eLo.in[0] <== exponentOffset;
    eLo.in[1] <== 2;
    eLo.out === 1;

    component eTag = Multiplexer(1, MAX_LEN);
    component eLen = Multiplexer(1, MAX_LEN);
    component e0 = Multiplexer(1, MAX_LEN);
    component e1 = Multiplexer(1, MAX_LEN);
    component e2 = Multiplexer(1, MAX_LEN);
    for (var i = 0; i < MAX_LEN; i++) {
        eTag.inp[i][0] <== bytes[i];
        eLen.inp[i][0] <== bytes[i];
        e0.inp[i][0] <== bytes[i];
        e1.inp[i][0] <== bytes[i];
        e2.inp[i][0] <== bytes[i];
    }
    eTag.sel <== exponentOffset - 2;
    eLen.sel <== exponentOffset - 1;
    e0.sel <== exponentOffset;
    e1.sel <== exponentOffset + 1;
    e2.sel <== exponentOffset + 2;
    eTag.out[0] === 0x02;
    eLen.out[0] === 0x03;
    e0.out[0] === 0x01;
    e1.out[0] === 0x00;
    e2.out[0] === 0x01;
}
