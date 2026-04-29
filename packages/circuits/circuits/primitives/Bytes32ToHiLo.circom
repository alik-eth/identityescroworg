pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";

/// @notice Decomposes a 256-bit value (held as 32 bytes, big-endian) into two
///         128-bit field elements `(hi, lo)` suitable for BN254 public-signal
///         exposure under V5's hi/lo split convention (spec §0.1, signals
///         3..10 of the public-signal layout).
///
/// @dev    Each input byte is range-constrained to <2^8 via Num2Bits(8). The
///         hi/lo packing is a linear combination over the constrained bytes.
///         Each output is implicitly < 2^128 << p (BN254 modulus ≈ 2^254), so
///         the M11 hardening "<p" invariant for hi/lo public signals holds
///         trivially without an explicit comparator.
template Bytes32ToHiLo() {
    signal input  bytes[32]; // big-endian: bytes[0] is the most significant
    signal output hi;        // bytes[0..15] packed as a 128-bit BE field element
    signal output lo;        // bytes[16..31] packed as a 128-bit BE field element

    component byteRange[32];
    for (var i = 0; i < 32; i++) {
        byteRange[i] = Num2Bits(8);
        byteRange[i].in <== bytes[i];
    }

    var hiAcc = 0;
    for (var i = 0; i < 16; i++) {
        hiAcc += bytes[i] * (256 ** (15 - i));
    }
    hi <== hiAcc;

    var loAcc = 0;
    for (var i = 0; i < 16; i++) {
        loAcc += bytes[16 + i] * (256 ** (15 - i));
    }
    lo <== loAcc;
}
