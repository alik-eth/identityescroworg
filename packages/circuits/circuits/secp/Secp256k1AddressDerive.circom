pragma circom 2.1.9;

// Secp256k1AddressDerive — derive the Ethereum address from an uncompressed
// secp256k1 public key (X || Y, 64 bytes, big-endian SEC1 within each
// coordinate) and expose it as a single field element ≤ 2^160.
//
// Formula (Ethereum convention):
//   address = uint160(uint256(keccak256(uncompressedPk)) mod 2^160)
//           = bytes [12..32] of the 32-byte digest, interpreted big-endian.
//
// Wiring (V5 §6.8):
//   parser.pkBytes is the binding's `pk` field — 65 bytes uncompressed SEC1
//   (`0x04 || X(32) || Y(32)`). Secp256k1PkMatch elsewhere asserts byte 0 is
//   0x04 and that the remaining 64 bytes repack into the witness pkX/pkY
//   limbs. This template ignores the prefix and consumes the trailing 64
//   bytes as the keccak input. Output address is equality-bound to the
//   `msgSender` public signal in the V5 main circuit body.
//
// Vendor: bkomuves/hash-circuits @ 4ef64777cc9b78ba987fbace27e0be7348670296
// (MIT, see ../primitives/vendor/bkomuves-keccak/PROVENANCE.md). Selected
// over vocdoni (GPL-3.0, 4-year stale) and rarimo (active but transitive
// vendor surface) for minimal-include footprint + byte-level API.
//
// Cost: ~150K constraints (Keccak_256_bytes(64) — single absorb block,
// 64 B < 136 B rate) + ~20 linear (address packing). Sole keccak in V5.

include "../primitives/vendor/bkomuves-keccak/circuits/keccak_bytes.circom";

template Secp256k1AddressDerive() {
    signal input pkBytes64[64];   // X || Y, no 0x04 prefix
    signal output addr;           // ≤ 2^160, Ethereum address

    // 1. Run Keccak-256 over the 64 raw bytes (byte-level API — bkomuves's
    //    Keccak_256_bytes wraps the bit-level core with an UnpackBytes/
    //    PackBytes pair internally). Output is 32 raw digest bytes.
    component keccak = Keccak_256_bytes(64);
    for (var i = 0; i < 64; i++) {
        keccak.inp_bytes[i] <== pkBytes64[i];
    }

    // 2. Address = uint160 of out_bytes[12..32], big-endian. Linear chain
    //    of constraints: addrAcc[b+1] = addrAcc[b] * 256 + out_bytes[12+b].
    signal addrAcc[21];
    addrAcc[0] <== 0;
    for (var b = 0; b < 20; b++) {
        addrAcc[b + 1] <== addrAcc[b] * 256 + keccak.out_bytes[12 + b];
    }
    addr <== addrAcc[20];
}
