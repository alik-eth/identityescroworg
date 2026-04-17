pragma circom 2.1.9;

// EcdsaP256Verify
//
// Thin local alias around the vendored ECDSA P-256 verifier from
// privacy-scaling-explorations/circom-ecdsa-p256 (commit 5b916ea, GPLv3).
// See `vendor/circom-ecdsa-p256/PROVENANCE.md` for full source provenance,
// per-file checksums, and patch list.
//
// Constraints:
//  - Curve: NIST P-256 (a.k.a. secp256r1, prime256v1).
//  - Limb encoding (matches upstream test suite): n=43, k=6 → 6 limbs of
//    43 bits each, little-endian across limbs. Each limb satisfies
//    0 ≤ limb < 2^43.
//  - Estimated cost: ~3M constraints per verify (full scalar mul + curve
//    arithmetic on BN254).
//
// Inputs:
//  - msghash[6]    : SHA-256(message) packed into 6×43-bit limbs LE.
//  - r[6], s[6]    : ECDSA signature components, same encoding.
//  - pubkey[2][6]  : public point (x, y) in affine coordinates, same
//                    encoding for each coordinate.
//
// Behavior: the upstream `ECDSAVerifyNoPubkeyCheck` template outputs a
// `result` signal (1 = valid, 0 = invalid). This wrapper enforces
// `result === 1`, so invalid signatures fail witness calculation and
// are caught at proving time — matching the failure mode of
// `RsaPkcs1V15Verify` and the rest of the QKB sub-circuits.

include "./vendor/circom-ecdsa-p256/p256/ecdsa.circom";

template EcdsaP256Verify() {
    var N_BITS = 43;
    var K_LIMBS = 6;

    signal input msghash[K_LIMBS];
    signal input r[K_LIMBS];
    signal input s[K_LIMBS];
    signal input pubkey[2][K_LIMBS];

    component v = ECDSAVerifyNoPubkeyCheck(N_BITS, K_LIMBS);
    for (var i = 0; i < K_LIMBS; i++) {
        v.r[i] <== r[i];
        v.s[i] <== s[i];
        v.msghash[i] <== msghash[i];
        v.pubkey[0][i] <== pubkey[0][i];
        v.pubkey[1][i] <== pubkey[1][i];
    }
    v.result === 1;
}

component main = EcdsaP256Verify();
