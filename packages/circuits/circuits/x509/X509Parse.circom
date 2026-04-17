pragma circom 2.1.9;

// X509Parse — constrained ASN.1 slicers for X.509 DER bytes.
//
// Strategy (per design spec §5.5): we do NOT do full ASN.1 parsing inside
// the circuit. The witness builder supplies (offset, length) hints for each
// field; this template family constrains the prover to picking offsets that
// land on a real ASN.1 TLV header for the expected tag, and that the
// declared length is consistent with the byte at `offset - 1` (short-form
// length only — DER short form covers all tag values up through 127, which
// suffices for every X.509 field we care about extracting in this circuit:
// validity dates (15 bytes), modulus (sliced separately by parent SEQUENCE),
// etc.). Any field whose length needs > 1 byte is sliced via its parent
// SEQUENCE wrapper instead.
//
// Failure mode: if the prover lies about an offset, the byte at offset-2
// won't match `expectedTag` and the constraint fails. If they lie about
// the length, the byte at offset-1 won't match `expectedLen`.

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";

// Asserts that `bytes[offset - 2] == expectedTag` and
// `bytes[offset - 1] == expectedLen`.
//
// `bytes`: the DER buffer (fixed size MAX_LEN, padded with zeros).
// `offset`: prover-supplied content-start index inside `bytes`.
// `expectedTag`: literal ASN.1 tag byte (e.g., 0x18 for GeneralizedTime).
// `expectedLen`: literal short-form length byte (the content length, < 128).
//
// Caller is responsible for separately constraining that the content bytes
// (bytes[offset .. offset + expectedLen - 1]) carry the semantics they need.
template Asn1ShortTLVCheck(MAX_LEN, expectedTag, expectedLen) {
    signal input bytes[MAX_LEN];
    signal input offset;

    // Range-check offset: 2 ≤ offset ≤ MAX_LEN - expectedLen.
    component lo = GreaterEqThan(16);
    lo.in[0] <== offset;
    lo.in[1] <== 2;
    lo.out === 1;

    component hi = LessEqThan(16);
    hi.in[0] <== offset + expectedLen;
    hi.in[1] <== MAX_LEN;
    hi.out === 1;

    // Pull bytes[offset - 2] and bytes[offset - 1] via Multiplexer.
    component mTag = Multiplexer(1, MAX_LEN);
    component mLen = Multiplexer(1, MAX_LEN);
    for (var i = 0; i < MAX_LEN; i++) {
        mTag.inp[i][0] <== bytes[i];
        mLen.inp[i][0] <== bytes[i];
    }
    mTag.sel <== offset - 2;
    mLen.sel <== offset - 1;

    mTag.out[0] === expectedTag;
    mLen.out[0] === expectedLen;
}

// Convenience for slicing a 15-byte GeneralizedTime field: tag 0x18, length
// 0x0F, content `YYYYMMDDHHMMSSZ`. Exposes the 15 content bytes for use by
// X509Validity. Uses Multiplexer once per output byte.
template Asn1GeneralizedTime15(MAX_LEN) {
    signal input bytes[MAX_LEN];
    signal input offset;
    signal output content[15];

    component tlv = Asn1ShortTLVCheck(MAX_LEN, 0x18, 0x0F);
    for (var i = 0; i < MAX_LEN; i++) {
        tlv.bytes[i] <== bytes[i];
    }
    tlv.offset <== offset;

    component pick[15];
    for (var i = 0; i < 15; i++) {
        pick[i] = Multiplexer(1, MAX_LEN);
        for (var j = 0; j < MAX_LEN; j++) {
            pick[i].inp[j][0] <== bytes[j];
        }
        pick[i].sel <== offset + i;
        content[i] <== pick[i].out[0];
    }

    // Last content byte must be 'Z' (0x5A); other 14 must be ASCII digits.
    content[14] === 0x5A;
    component digit[14];
    for (var i = 0; i < 14; i++) {
        digit[i] = Num2Bits(8);
        digit[i].in <== content[i] - 0x30;
        // 0..9 fits in 4 bits; require top 4 bits zero and total ≤ 9.
        for (var b = 4; b < 8; b++) {
            digit[i].out[b] === 0;
        }
        // bit3 high implies value ≥ 8; if bit3 high then bit1 and bit2 must be zero (so ≤ 9).
        // (8 = 1000, 9 = 1001). digit[i].out[1] and out[2] must both be 0 when out[3] is 1.
        digit[i].out[3] * digit[i].out[2] === 0;
        digit[i].out[3] * digit[i].out[1] === 0;
    }
}
