pragma circom 2.1.9;

// RsaPkcs1V15Verify
//
// Thin local alias around the vendored zk-email RSA-PKCS#1 v1.5 verifier
// pinned to @zk-email/circuits 6.3.4 (upstream gitHead
// ccb6a79deba7963beb9abcdb8a3365cfa3b84435, MIT). See
// `vendor/zk-email/PROVENANCE.md` for source provenance and checksums.
//
// Constraints:
//  - Exponent fixed at 65537 (the only QES algo in Phase 1).
//  - For RSA-2048 we instantiate (n=121, k=17): 121-bit limbs, 17 limbs.
//
// Inputs (all in 121-bit chunks, little-endian, 17 chunks each):
//  - message  : sha256(signedAttrs) packed as bigint (high bytes zero-padded)
//  - signature: signature value as bigint (must satisfy s < modulus)
//  - modulus  : RSA modulus N

include "./vendor/zk-email/lib/rsa.circom";

template RsaPkcs1V15Verify2048() {
    var N_BITS = 121;
    var K_LIMBS = 17;

    signal input message[K_LIMBS];
    signal input signature[K_LIMBS];
    signal input modulus[K_LIMBS];

    component v = RSAVerifier65537(N_BITS, K_LIMBS);
    for (var i = 0; i < K_LIMBS; i++) {
        v.message[i] <== message[i];
        v.signature[i] <== signature[i];
        v.modulus[i] <== modulus[i];
    }
}

component main = RsaPkcs1V15Verify2048();
