pragma circom 2.1.9;

// QKBPresentationEcdsaLeafV4 — draft successor leaf circuit for `QKB/2.0`.
//
// This file is intentionally not wired into the live build / ceremony path.
// It exists to freeze the intended successor constraint surface:
//   - structured binding-core bytes instead of declaration prose
//   - policy-root inclusion instead of DeclarationWhitelist
//   - unchanged CMS verification, scoped nullifier, and leafSpkiCommit glue
//
// Public signals (14 total — draft successor order):
//   [0..3]  pkX[4]
//   [4..7]  pkY[4]
//   [8]     ctxHash
//   [9]     policyLeafHash
//   [10]    policyRoot
//   [11]    timestamp
//   [12]    nullifier
//   [13]    leafSpkiCommit
//
// `BindingParseV2Core` now pins the full machine-readable `bindingCoreV2(...)`
// surface. This circuit is still draft-only because it is not wired into the
// live proving / verifier / contract path, not because the core JSON shape is
// intentionally underconstrained.

include "./binding/BindingParseV2Core.circom";
include "./primitives/Sha256Var.circom";
include "./primitives/EcdsaP256Verify.circom";
include "./primitives/PoseidonChunkHashVar.circom";
include "./primitives/NullifierDerive.circom";
include "./primitives/X509SubjectSerial.circom";
include "./primitives/MerkleProofPoseidon.circom";
include "./secp/Secp256k1PkMatch.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";

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

template QKBPresentationEcdsaLeafV4() {
    var MAX_BCANON = 1024;
    var MAX_SA = 1536;
    var MAX_CERT = 1536;
    var MAX_CTX = 256;
    var MAX_TS_DIGITS = 20;
    var MERKLE_DEPTH = 16;

    // === Public ===
    signal input pkX[4];
    signal input pkY[4];
    signal input ctxHash;
    signal input policyLeafHash;
    signal input policyRoot;
    signal input timestamp;
    signal input nullifier;
    signal input leafSpkiCommit;

    // === Private (nullifier extraction) ===
    signal input subjectSerialValueOffset;
    signal input subjectSerialValueLength;

    // === Private (binding core parse) ===
    signal input bindingCore[MAX_BCANON];
    signal input bindingCoreLen;
    signal input bindingCorePaddedIn[MAX_BCANON];
    signal input bindingCorePaddedLen;
    signal input pkValueOffset;
    signal input schemeValueOffset;
    signal input assertionsValueOffset;
    signal input statementSchemaValueOffset;
    signal input nonceValueOffset;
    signal input ctxValueOffset;
    signal input ctxHexLen;
    signal input policyIdValueOffset;
    signal input policyIdLen;
    signal input policyLeafHashValueOffset;
    signal input policyBindingSchemaValueOffset;
    signal input policyVersionValueOffset;
    signal input policyVersionDigitCount;
    signal input tsValueOffset;
    signal input tsDigitCount;
    signal input versionValueOffset;
    signal input nonceBytes[32];
    signal input policyIdBytes[128];
    signal input policyVersion;

    // === Private (CMS signedAttrs + leaf signature) ===
    signal input signedAttrs[MAX_SA];
    signal input signedAttrsLen;
    signal input signedAttrsPaddedIn[MAX_SA];
    signal input signedAttrsPaddedLen;
    signal input mdOffsetInSA;

    // === Private (leaf certificate) ===
    signal input leafDER[MAX_CERT];
    signal input leafSpkiXOffset;
    signal input leafSpkiYOffset;
    signal input leafSigR[6];
    signal input leafSigS[6];

    // === Private (policy inclusion) ===
    signal input policyMerklePath[MERKLE_DEPTH];
    signal input policyMerkleIndices[MERKLE_DEPTH];

    // =========================================================================
    // 1. Binding core parse + pk limb match + timestamp match.
    // =========================================================================
    component parser = BindingParseV2Core(MAX_BCANON, MAX_CTX, MAX_TS_DIGITS);
    for (var i = 0; i < MAX_BCANON; i++) parser.bytes[i] <== bindingCore[i];
    parser.bcanonLen <== bindingCoreLen;
    parser.pkValueOffset <== pkValueOffset;
    parser.schemeValueOffset <== schemeValueOffset;
    parser.assertionsValueOffset <== assertionsValueOffset;
    parser.statementSchemaValueOffset <== statementSchemaValueOffset;
    parser.nonceValueOffset <== nonceValueOffset;
    parser.ctxValueOffset <== ctxValueOffset;
    parser.ctxHexLen <== ctxHexLen;
    parser.policyIdValueOffset <== policyIdValueOffset;
    parser.policyIdLen <== policyIdLen;
    parser.policyLeafHashValueOffset <== policyLeafHashValueOffset;
    parser.policyBindingSchemaValueOffset <== policyBindingSchemaValueOffset;
    parser.policyVersionValueOffset <== policyVersionValueOffset;
    parser.policyVersionDigitCount <== policyVersionDigitCount;
    parser.tsValueOffset <== tsValueOffset;
    parser.tsDigitCount <== tsDigitCount;
    parser.versionValueOffset <== versionValueOffset;
    for (var i = 0; i < 32; i++) parser.nonceBytesIn[i] <== nonceBytes[i];
    for (var i = 0; i < 128; i++) parser.policyIdBytesIn[i] <== policyIdBytes[i];
    parser.policyVersionIn <== policyVersion;

    component pkMatch = Secp256k1PkMatch();
    for (var i = 0; i < 65; i++) pkMatch.pkBytes[i] <== parser.pkBytes[i];
    for (var i = 0; i < 4; i++) {
        pkMatch.pkX[i] <== pkX[i];
        pkMatch.pkY[i] <== pkY[i];
    }

    parser.tsValue === timestamp;
    parser.policyLeafHash === policyLeafHash;

    // =========================================================================
    // 2. sha256(bindingCore) == messageDigest inside signedAttrs at mdOffsetInSA.
    // =========================================================================
    component bcLt[MAX_BCANON];
    for (var i = 0; i < MAX_BCANON; i++) {
        bcLt[i] = LessThan(16);
        bcLt[i].in[0] <== i;
        bcLt[i].in[1] <== bindingCoreLen;
        bcLt[i].out * (bindingCorePaddedIn[i] - bindingCore[i]) === 0;
    }
    component hashBcanon = Sha256Var(MAX_BCANON);
    for (var i = 0; i < MAX_BCANON; i++) hashBcanon.paddedIn[i] <== bindingCorePaddedIn[i];
    hashBcanon.paddedLen <== bindingCorePaddedLen;

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
    // 4. policyLeafHash ∈ policyRoot.
    // =========================================================================
    component merkle = MerkleProofPoseidon(MERKLE_DEPTH);
    merkle.leaf <== policyLeafHash;
    merkle.root <== policyRoot;
    for (var i = 0; i < MERKLE_DEPTH; i++) {
        merkle.path[i] <== policyMerklePath[i];
        merkle.indices[i] <== policyMerkleIndices[i];
    }

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
    // 6. leafSpkiCommit — Poseidon commitment to the leaf SPKI limbs.
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
    packXY.out === leafSpkiCommit;

    // =========================================================================
    // 7. Scoped credential nullifier.
    // =========================================================================
    component subjectSerial = X509SubjectSerial(MAX_CERT);
    for (var i = 0; i < MAX_CERT; i++) subjectSerial.leafDER[i] <== leafDER[i];
    subjectSerial.subjectSerialValueOffset <== subjectSerialValueOffset;
    subjectSerial.subjectSerialValueLength <== subjectSerialValueLength;

    component nullifierDerive = NullifierDerive();
    for (var i = 0; i < 4; i++) {
        nullifierDerive.subjectSerialLimbs[i] <== subjectSerial.subjectSerialLimbs[i];
    }
    nullifierDerive.subjectSerialLen <== subjectSerialValueLength;
    nullifierDerive.ctxHash <== ctxHash;

    nullifierDerive.nullifier === nullifier;
}

component main {public [pkX, pkY, ctxHash, policyLeafHash, policyRoot, timestamp, nullifier, leafSpkiCommit]}
    = QKBPresentationEcdsaLeafV4();
