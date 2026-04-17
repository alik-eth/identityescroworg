pragma circom 2.1.9;

// QKBPresentationEcdsaLeaf — leaf-side ECDSA proof.
//
// Wires R_QKB constraints 1, 2, 5, 6 per spec §5.3 — the "binding proof"
// attesting that the user actually performed the QES over the binding
// statement committed to `pk`/context/declaration/timestamp. Chain-side
// constraints 3, 4 (intermediate signs leaf; intermediate in trusted list)
// are proved by a separate circuit QKBPresentationEcdsaChain and verified
// on-chain alongside this proof, per the §5.4 split-proof fallback (both
// verifies in one circuit exceed the 22 GB compile budget on dev HW).
//
// Public signals (subset of the full 13 — leaf proof doesn't need rTL or
// algorithmTag, both supplied by the chain proof's public signals):
//   [0..3]  pkX[4]
//   [4..7]  pkY[4]
//   [8]     ctxHash
//   [9]     declHash
//   [10]    timestamp
//   [11]    leafSpkiCommit   Poseidon(Poseidon(leafXLimbs), Poseidon(leafYLimbs))
//                            — binds this proof's leaf SPKI to the chain
//                              proof's leaf SPKI via an on-chain equality
//                              check between the two public signals.

include "./binding/BindingParseFull.circom";
include "./binding/DeclarationWhitelist.circom";
include "./primitives/Sha256Var.circom";
include "./primitives/EcdsaP256Verify.circom";
include "./primitives/PoseidonChunkHashVar.circom";
include "./secp/Secp256k1PkMatch.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";

// Bytes-to-limbs helper for ECDSA-P256 (6×43-bit LE limbs).
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

template Bits256ToField() {
    signal input digestBits[256];
    signal output packed;
    var acc = 0;
    for (var i = 0; i < 256; i++) acc = acc * 2 + digestBits[i];
    packed <== acc;
}

template QKBPresentationEcdsaLeaf() {
    var MAX_BCANON = 1024;
    var MAX_SA = 1536;
    var MAX_CERT = 1536;
    var MAX_CTX = 256;
    // MAX_DECL must satisfy declValueOffset + MAX_DECL ≤ MAX_BCANON so the
    // BPFSliceVar Multiplexer over the Bcanon buffer never overflows. Diia
    // admin binding places declaration at offset 31; UK is the longest
    // canonical declaration at 905 B. 960 gives ~25 B safety margin under
    // either ceiling.
    var MAX_DECL = 960;
    var MAX_TS_DIGITS = 20;

    // === Public ===
    signal input pkX[4];
    signal input pkY[4];
    signal input ctxHash;
    signal input declHash;
    signal input timestamp;
    signal output leafSpkiCommit;

    // === Private ===
    signal input Bcanon[MAX_BCANON];
    signal input BcanonLen;
    signal input BcanonPaddedIn[MAX_BCANON];
    signal input BcanonPaddedLen;
    signal input pkValueOffset;
    signal input schemeValueOffset;
    signal input ctxValueOffset;
    signal input ctxHexLen;
    signal input declValueOffset;
    signal input declValueLen;
    signal input tsValueOffset;
    signal input tsDigitCount;

    signal input declPaddedIn[MAX_DECL + 64];
    signal input declPaddedLen;

    signal input signedAttrs[MAX_SA];
    signal input signedAttrsLen;
    signal input signedAttrsPaddedIn[MAX_SA];
    signal input signedAttrsPaddedLen;
    signal input mdOffsetInSA;

    signal input leafDER[MAX_CERT];
    signal input leafSpkiXOffset;
    signal input leafSpkiYOffset;

    signal input leafSigR[6];
    signal input leafSigS[6];

    // =========================================================================
    // 1. Bcanon parse + pk limb match + timestamp match.
    // =========================================================================
    component parser = BindingParseFull(MAX_BCANON, MAX_CTX, MAX_DECL, MAX_TS_DIGITS);
    for (var i = 0; i < MAX_BCANON; i++) parser.bytes[i] <== Bcanon[i];
    parser.bcanonLen <== BcanonLen;
    parser.pkValueOffset <== pkValueOffset;
    parser.schemeValueOffset <== schemeValueOffset;
    parser.ctxValueOffset <== ctxValueOffset;
    parser.ctxHexLen <== ctxHexLen;
    parser.declValueOffset <== declValueOffset;
    parser.declValueLen <== declValueLen;
    parser.tsValueOffset <== tsValueOffset;
    parser.tsDigitCount <== tsDigitCount;

    component pkMatch = Secp256k1PkMatch();
    for (var i = 0; i < 65; i++) pkMatch.pkBytes[i] <== parser.pkBytes[i];
    for (var i = 0; i < 4; i++) {
        pkMatch.pkX[i] <== pkX[i];
        pkMatch.pkY[i] <== pkY[i];
    }

    parser.tsValue === timestamp;

    // =========================================================================
    // 2. sha256(Bcanon) == messageDigest inside signedAttrs at mdOffsetInSA.
    // =========================================================================
    component bcLt[MAX_BCANON];
    for (var i = 0; i < MAX_BCANON; i++) {
        bcLt[i] = LessThan(16);
        bcLt[i].in[0] <== i;
        bcLt[i].in[1] <== BcanonLen;
        bcLt[i].out * (BcanonPaddedIn[i] - Bcanon[i]) === 0;
    }
    component hashBcanon = Sha256Var(MAX_BCANON);
    for (var i = 0; i < MAX_BCANON; i++) hashBcanon.paddedIn[i] <== BcanonPaddedIn[i];
    hashBcanon.paddedLen <== BcanonPaddedLen;

    component mdPick[32];
    signal mdFromSA[32];
    for (var i = 0; i < 32; i++) {
        mdPick[i] = Multiplexer(1, MAX_SA);
        for (var j = 0; j < MAX_SA; j++) mdPick[i].inp[j][0] <== signedAttrs[j];
        mdPick[i].sel <== mdOffsetInSA + i;
        mdFromSA[i] <== mdPick[i].out[0];
    }

    signal bcanonDigestBytes[32];
    for (var i = 0; i < 32; i++) {
        var acc = 0;
        for (var b = 0; b < 8; b++) acc = acc * 2 + hashBcanon.out[i * 8 + b];
        bcanonDigestBytes[i] <== acc;
        bcanonDigestBytes[i] === mdFromSA[i];
    }

    // =========================================================================
    // 3. sha256(signedAttrs) + EcdsaP256Verify with leaf SPKI.
    // =========================================================================
    component saLt[MAX_SA];
    for (var i = 0; i < MAX_SA; i++) {
        saLt[i] = LessThan(16);
        saLt[i].in[0] <== i;
        saLt[i].in[1] <== signedAttrsLen;
        saLt[i].out * (signedAttrsPaddedIn[i] - signedAttrs[i]) === 0;
    }
    component hashSA = Sha256Var(MAX_SA);
    for (var i = 0; i < MAX_SA; i++) hashSA.paddedIn[i] <== signedAttrsPaddedIn[i];
    hashSA.paddedLen <== signedAttrsPaddedLen;

    signal saDigestBytes[32];
    for (var i = 0; i < 32; i++) {
        var acc = 0;
        for (var b = 0; b < 8; b++) acc = acc * 2 + hashSA.out[i * 8 + b];
        saDigestBytes[i] <== acc;
    }
    component saDigestLimbs = Bytes32ToLimbs643();
    for (var i = 0; i < 32; i++) saDigestLimbs.bytes[i] <== saDigestBytes[i];

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

    component leafVerify = EcdsaP256Verify();
    for (var i = 0; i < 6; i++) {
        leafVerify.msghash[i] <== saDigestLimbs.limbs[i];
        leafVerify.r[i] <== leafSigR[i];
        leafVerify.s[i] <== leafSigS[i];
        leafVerify.pubkey[0][i] <== leafXLimbs.limbs[i];
        leafVerify.pubkey[1][i] <== leafYLimbs.limbs[i];
    }

    // =========================================================================
    // 4. declHash + DeclarationWhitelist.
    // =========================================================================
    component declLt[MAX_DECL];
    for (var i = 0; i < MAX_DECL; i++) {
        declLt[i] = LessThan(16);
        declLt[i].in[0] <== i;
        declLt[i].in[1] <== declValueLen;
        declLt[i].out * (declPaddedIn[i] - parser.declBytes[i]) === 0;
    }
    component hashDecl = Sha256Var(MAX_DECL + 64);
    for (var i = 0; i < MAX_DECL + 64; i++) hashDecl.paddedIn[i] <== declPaddedIn[i];
    hashDecl.paddedLen <== declPaddedLen;

    component whitelist = DeclarationWhitelist();
    for (var i = 0; i < 256; i++) whitelist.digestBits[i] <== hashDecl.out[i];

    component declPack = Bits256ToField();
    for (var i = 0; i < 256; i++) declPack.digestBits[i] <== hashDecl.out[i];
    declPack.packed === declHash;

    // =========================================================================
    // 5. ctxHash: empty → 0, else PoseidonChunkHashVar(ctxBytes) = ctxHash.
    // =========================================================================
    component ctxIsEmpty = IsZero();
    ctxIsEmpty.in <== parser.ctxLen;

    component ctxHashVar = PoseidonChunkHashVar(MAX_CTX);
    for (var i = 0; i < MAX_CTX; i++) ctxHashVar.bytes[i] <== parser.ctxBytes[i];
    ctxHashVar.len <== parser.ctxLen;

    signal ctxEff;
    ctxEff <== (1 - ctxIsEmpty.out) * ctxHashVar.out;
    ctxEff === ctxHash;

    // =========================================================================
    // 6. leafSpkiCommit — Poseidon commitment to the leaf SPKI limbs. The
    //    chain-side proof exposes the same commitment; the on-chain verifier
    //    asserts equality to glue the two proofs.
    // =========================================================================
    component packX = Poseidon(6);
    component packY = Poseidon(6);
    for (var i = 0; i < 6; i++) {
        packX.inputs[i] <== leafXLimbs.limbs[i];
        packY.inputs[i] <== leafYLimbs.limbs[i];
    }
    component packXY = Poseidon(2);
    packXY.inputs[0] <== packX.out;
    packXY.inputs[1] <== packY.out;
    leafSpkiCommit <== packXY.out;
}

component main {public [pkX, pkY, ctxHash, declHash, timestamp]}
    = QKBPresentationEcdsaLeaf();
