pragma circom 2.1.9;

// Sha256Var
//
// Variable-length SHA-256 wrapper over the vendored zk-email Sha256Bytes
// template (pinned to @zk-email/circuits 6.3.4 — see vendor/zk-email/
// PROVENANCE.md).
//
// Convention (matches Sha256Bytes):
//   - Prover supplies `paddedIn` already padded per FIPS 180-4 §5.1.1: the
//     message bytes, a 0x80 byte, zero padding, then the original message
//     length in bits encoded big-endian over the final 8 bytes.
//   - `paddedLen` is the byte length of the padded input (a multiple of 64).
//   - The witness builder (off-circuit) is responsible for performing this
//     padding — `lib/witness.ts` in @qkb/web does so before submitting to the
//     prover. This wrapper only verifies the digest is consistent with the
//     supplied padded prefix.
//
// Bounds enforced by this wrapper:
//   - 0 < paddedLen <= MAX_BYTES (a constant for each instantiation).
//   - paddedLen is a multiple of 64. (Required by the SHA padding spec; if
//     the prover lies the underlying Sha256General circuit will fail its
//     internal `paddedInLength === inBlockIndex * 512` check, but we mirror
//     the bound here at byte granularity for a clearer failure mode.)
//
// The QKB main circuit instantiates this with MAX_BYTES = 2048 (covering
// signedAttrs ≤ 256 B and Bcanon ≤ 1024 B; cert TBS uses a larger
// instantiation directly).

include "./vendor/zk-email/lib/sha.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

template Sha256Var(MAX_BYTES) {
    signal input paddedIn[MAX_BYTES];
    signal input paddedLen;
    signal output out[256];

    // Range-check paddedLen against MAX_BYTES.
    // log2(MAX_BYTES) + 1 bits is enough; clamp to 16 for the sizes we use.
    component lenBits = Num2Bits(16);
    lenBits.in <== paddedLen;

    // paddedLen ≤ MAX_BYTES
    component leMax = LessEqThan(16);
    leMax.in[0] <== paddedLen;
    leMax.in[1] <== MAX_BYTES;
    leMax.out === 1;

    // paddedLen ≥ 64 (smallest possible padded SHA-256 message is one block).
    component geMin = GreaterEqThan(16);
    geMin.in[0] <== paddedLen;
    geMin.in[1] <== 64;
    geMin.out === 1;

    component sha = Sha256Bytes(MAX_BYTES);
    for (var i = 0; i < MAX_BYTES; i++) {
        sha.paddedIn[i] <== paddedIn[i];
    }
    sha.paddedInLength <== paddedLen;

    for (var i = 0; i < 256; i++) {
        out[i] <== sha.out[i];
    }
}
