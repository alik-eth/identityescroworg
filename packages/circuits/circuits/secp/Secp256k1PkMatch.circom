pragma circom 2.1.9;

// Secp256k1PkMatch — pure byte-to-limb packing + equality.
//
// Input: `pkBytes[65]` — the uncompressed SEC1 representation of a
// secp256k1 public key (`0x04 || X(32 BE) || Y(32 BE)`), as sliced from
// Bcanon by the BindingParse step. The 0x04 prefix is asserted; the
// remaining 64 bytes are repacked into 4 × 64-bit limbs, little-endian
// across limbs (i.e. limb[0] is the LEAST-significant 64 bits), to match
// the public-signal layout in orchestration §2.2.
//
// Bytes within each 32-byte coordinate are big-endian per SEC1, so:
//   limb[3] = bytes[0..7]   BE   (most-significant 64 bits)
//   limb[2] = bytes[8..15]  BE
//   limb[1] = bytes[16..23] BE
//   limb[0] = bytes[24..31] BE   (least-significant 64 bits)
//
// The circuit asserts each repacked limb equals the supplied public-input
// limb. No curve-point arithmetic. No y-recovery (the y coordinate comes
// from the user's wallet via the uncompressed encoding inside Bcanon).
//
// Bytes are constrained to be in 0..255 via Num2Bits(8) — defence in depth
// against malicious witness builders feeding non-byte field elements.

include "circomlib/circuits/bitify.circom";

template Secp256k1PkMatch() {
    signal input pkBytes[65];
    signal input pkX[4];
    signal input pkY[4];

    // 1. Prefix byte 0x04.
    pkBytes[0] === 0x04;

    // 2. Range-check every byte to 0..255.
    component byteRange[65];
    for (var i = 0; i < 65; i++) {
        byteRange[i] = Num2Bits(8);
        byteRange[i].in <== pkBytes[i];
    }

    // 3. Pack X = bytes[1..33] into 4 LE limbs of 64 bits each (BE inside each limb).
    // limb 3 (highest) = bytes[1..9], limb 2 = bytes[9..17], etc.
    for (var l = 0; l < 4; l++) {
        var off = 1 + (3 - l) * 8;  // l=3 → off=1, l=2 → off=9, l=1 → off=17, l=0 → off=25
        var acc = 0;
        for (var j = 0; j < 8; j++) {
            acc = acc * 256 + pkBytes[off + j];
        }
        pkX[l] === acc;
    }

    // 4. Pack Y = bytes[33..65] the same way.
    for (var l = 0; l < 4; l++) {
        var off = 33 + (3 - l) * 8;
        var acc = 0;
        for (var j = 0; j < 8; j++) {
            acc = acc * 256 + pkBytes[off + j];
        }
        pkY[l] === acc;
    }
}

component main = Secp256k1PkMatch();
