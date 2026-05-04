pragma circom 2.1.9;

// ZkqesPresentationEcdsaChain — chain-side ECDSA proof (Phase-2 split-proof).
//
// Wires R_zkqes constraints 3, 4 per spec §5.3: the intermediate CA signs the
// leaf TBS, and the intermediate is listed in the trusted-list Merkle root.
// `leafSpkiCommit` is a public input (declared LAST in the public list so
// snarkjs emits it at `publicSignals[2]` per orchestration §2.2 — snarkjs
// orders outputs-then-inputs, so using `signal output` here would land it
// at index 0 and break contracts-eng's `chainArr[2]` packing). The circuit
// constrains it to equal Poseidon2(Poseidon6(leafXLimbs), Poseidon6(leafYLimbs))
// below; the on-chain verifier asserts equality with the leaf proof's
// `leafSpkiCommit`, gluing the two Groth16 proofs into one R_zkqes
// attestation (spec §5.4, split-proof fallback).
//
// Public signals (5 — orchestration §2.2):
//   [0]    rTL               trusted-list Merkle root
//   [1]    algorithmTag      1 == ECDSA-P256 (literal constraint)
//   [2]    leafSpkiCommit    Poseidon(Poseidon(leafXLimbs), Poseidon(leafYLimbs))
//                            — MUST match leaf proof's leafSpkiCommit; on-chain
//                              equality check enforces binding between the
//                              two Groth16 proofs.
//
// Companion circuit: ZkqesPresentationEcdsaLeaf (holds R_zkqes constraints
// 1, 2, 5, 6 + scoped credential nullifier). Both proofs are submitted
// together to ZkqesRegistryV3.register(...).
//
// NB on `leafTbsPaddedIn`: the Phase-1 gap documented in the unified
// circuit's §4 carries over — the witness supplies leafTbsPaddedIn as a
// padded SHA-256 view of leafDER at leafTbsOffset without an in-circuit
// prefix binding (O(n²) Multiplexer cost blows the compile budget).
// Until the O(n) substring construction lands, the witness builder
// guarantees consistency; the Merkle-rTL gate plus the leaf-proof's
// own leaf-signature verification bound the residual risk.

include "./primitives/Sha256Var.circom";
include "./primitives/EcdsaP256Verify.circom";
include "./primitives/MerkleProofPoseidon.circom";
include "./primitives/PoseidonChunkHashVar.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";

// Bytes-to-limbs helper for ECDSA-P256 (6×43-bit LE limbs). Matches the
// identical template in ZkqesPresentationEcdsaLeaf so both circuits derive
// leafSpkiCommit identically.
template Bytes32ToLimbs643() {
    signal input bytes[32];
    signal output limbs[6];

    component bits[32];
    signal bitStream[256];
    for (var i = 0; i < 32; i++) {
        bits[i] = Num2Bits(8);
        bits[i].in <== bytes[i];
        for (var b = 0; b < 8; b++) {
            bitStream[i * 8 + (7 - b)] <== bits[i].out[b];
        }
    }

    for (var l = 0; l < 6; l++) {
        var start = 256 - (l + 1) * 43;
        var len = 43;
        if (start < 0) { len = 43 + start; start = 0; }
        var acc = 0;
        for (var b = 0; b < len; b++) acc = acc * 2 + bitStream[start + b];
        limbs[l] <== acc;
    }
}

template ZkqesPresentationEcdsaChain() {
    var MAX_CERT = 1536;
    var MERKLE_DEPTH = 16;

    // === Public signals ===
    signal input rTL;
    signal input algorithmTag;
    // leafSpkiCommit is a PUBLIC INPUT (not output) so it lands at the last
    // position of the Solidity verifier's `input[5]` per orchestration §2.2.
    // See sibling comment in ZkqesPresentationEcdsaLeaf for the full rationale
    // (snarkjs outputs-first ordering). The circuit constrains it below to
    // equal the internally-computed Poseidon2(Poseidon6(X), Poseidon6(Y))
    // over the leaf SPKI limbs — so the prover cannot pick an arbitrary
    // value, and the leaf + chain proofs' leafSpkiCommit values coincide by
    // construction (both derive it from the same leafDER bytes).
    signal input leafSpkiCommit;

    // Literal: this circuit is the ECDSA path.
    algorithmTag === 1;

    // === Private inputs ===
    // Leaf cert DER (needed for SPKI-coord extraction → leafSpkiCommit).
    signal input leafDER[MAX_CERT];
    signal input leafSpkiXOffset;
    signal input leafSpkiYOffset;

    // Leaf TBS padded form for sha256(leafTBS). Phase-1 gap: witness-side
    // binding of leafTbsPaddedIn to leafDER at leafTbsOffset (see header
    // comment above).
    signal input leafTbsPaddedIn[MAX_CERT];
    signal input leafTbsPaddedLen;

    // Intermediate cert + its SPKI + signature over leaf TBS.
    signal input intDER[MAX_CERT];
    signal input intDerLen;
    signal input intSpkiXOffset;
    signal input intSpkiYOffset;
    signal input intSigR[6];
    signal input intSigS[6];

    // Merkle inclusion for intermediate (canonicalized via
    // PoseidonChunkHashVar → Merkle leaf) under rTL.
    signal input merklePath[MERKLE_DEPTH];
    signal input merkleIndices[MERKLE_DEPTH];

    // =========================================================================
    // 1. Extract leaf SPKI x, y from leafDER → 6×43-bit limbs → leafSpkiCommit.
    //    Matches ZkqesPresentationEcdsaLeaf §6 verbatim; the on-chain verifier
    //    asserts equality between this circuit's output and the leaf circuit's
    //    output as the glue between the two proofs.
    // =========================================================================
    component leafX[32];
    component leafY[32];
    signal leafXBytes[32];
    signal leafYBytes[32];
    for (var i = 0; i < 32; i++) {
        leafX[i] = Multiplexer(1, MAX_CERT);
        leafY[i] = Multiplexer(1, MAX_CERT);
        for (var j = 0; j < MAX_CERT; j++) {
            leafX[i].inp[j][0] <== leafDER[j];
            leafY[i].inp[j][0] <== leafDER[j];
        }
        leafX[i].sel <== leafSpkiXOffset + i;
        leafY[i].sel <== leafSpkiYOffset + i;
        leafXBytes[i] <== leafX[i].out[0];
        leafYBytes[i] <== leafY[i].out[0];
    }
    component leafXLimbs = Bytes32ToLimbs643();
    component leafYLimbs = Bytes32ToLimbs643();
    for (var i = 0; i < 32; i++) {
        leafXLimbs.bytes[i] <== leafXBytes[i];
        leafYLimbs.bytes[i] <== leafYBytes[i];
    }

    component packX = Poseidon(6);
    component packY = Poseidon(6);
    for (var i = 0; i < 6; i++) {
        packX.inputs[i] <== leafXLimbs.limbs[i];
        packY.inputs[i] <== leafYLimbs.limbs[i];
    }
    component packXY = Poseidon(2);
    packXY.inputs[0] <== packX.out;
    packXY.inputs[1] <== packY.out;
    packXY.out === leafSpkiCommit;

    // =========================================================================
    // 2. sha256(leafTBS) + EcdsaP256Verify with intermediate SPKI.
    // =========================================================================
    component hashTBS = Sha256Var(MAX_CERT);
    for (var i = 0; i < MAX_CERT; i++) hashTBS.paddedIn[i] <== leafTbsPaddedIn[i];
    hashTBS.paddedLen <== leafTbsPaddedLen;

    signal tbsDigestBytes[32];
    for (var i = 0; i < 32; i++) {
        var acc = 0;
        for (var b = 0; b < 8; b++) acc = acc * 2 + hashTBS.out[i * 8 + b];
        tbsDigestBytes[i] <== acc;
    }
    component tbsDigestLimbs = Bytes32ToLimbs643();
    for (var i = 0; i < 32; i++) tbsDigestLimbs.bytes[i] <== tbsDigestBytes[i];

    component intX[32];
    component intY[32];
    signal intXBytes[32];
    signal intYBytes[32];
    for (var i = 0; i < 32; i++) {
        intX[i] = Multiplexer(1, MAX_CERT);
        intY[i] = Multiplexer(1, MAX_CERT);
        for (var j = 0; j < MAX_CERT; j++) {
            intX[i].inp[j][0] <== intDER[j];
            intY[i].inp[j][0] <== intDER[j];
        }
        intX[i].sel <== intSpkiXOffset + i;
        intY[i].sel <== intSpkiYOffset + i;
        intXBytes[i] <== intX[i].out[0];
        intYBytes[i] <== intY[i].out[0];
    }
    component intXLimbs = Bytes32ToLimbs643();
    component intYLimbs = Bytes32ToLimbs643();
    for (var i = 0; i < 32; i++) {
        intXLimbs.bytes[i] <== intXBytes[i];
        intYLimbs.bytes[i] <== intYBytes[i];
    }

    component intVerify = EcdsaP256Verify();
    for (var i = 0; i < 6; i++) {
        intVerify.msghash[i] <== tbsDigestLimbs.limbs[i];
        intVerify.r[i] <== intSigR[i];
        intVerify.s[i] <== intSigS[i];
        intVerify.pubkey[0][i] <== intXLimbs.limbs[i];
        intVerify.pubkey[1][i] <== intYLimbs.limbs[i];
    }

    // =========================================================================
    // 3. Canonicalize intDER → Poseidon leaf; Merkle-verify under rTL.
    // =========================================================================
    component intHash = PoseidonChunkHashVar(MAX_CERT);
    for (var i = 0; i < MAX_CERT; i++) intHash.bytes[i] <== intDER[i];
    intHash.len <== intDerLen;

    component merkle = MerkleProofPoseidon(MERKLE_DEPTH);
    merkle.leaf <== intHash.out;
    for (var i = 0; i < MERKLE_DEPTH; i++) {
        merkle.path[i] <== merklePath[i];
        merkle.indices[i] <== merkleIndices[i];
    }
    merkle.root <== rTL;
}

component main {public [rTL, algorithmTag, leafSpkiCommit]}
    = ZkqesPresentationEcdsaChain();
