pragma circom 2.1.9;

// ZkqesPresentationEcdsaLeafV4 — unified successor leaf circuit for `QKB/2.0`.
//
// Public signals (16 total):
//   [0..3]  pkX[4]
//   [4..7]  pkY[4]
//   [8]     ctxHash
//   [9]     policyLeafHash
//   [10]    policyRoot
//   [11]    timestamp
//   [12]    nullifier             (scoped credential, §14.4)
//   [13]    leafSpkiCommit        (glue to chain proof)
//   [14]    dobCommit             (dobSupported * Poseidon(dobYmd, dobSourceTag);
//                                  exactly 0 when dobSupported=0, per the gate
//                                  below — header contract is enforced in-
//                                  circuit, not left to extractor convention)
//   [15]    dobSupported          (0 or 1)
//
// Countries without DOB extraction link DobExtractorNull.circom, which emits
// dobSupported=0 and sourceTag=0 so the downstream Poseidon still produces a
// well-defined `dobCommit`. Registry reads `dobSupported` at age-proof time.
//
// This file is the generic template. Per-country compile is done via
// ZkqesPresentationEcdsaLeafV4_<CC>.circom wrappers that `include` the
// appropriate DOB extractor before including this template (see
// docs/superpowers/specs/2026-04-24-per-country-registries-design.md §Circuit
// family).

include "./binding/BindingParseV2CoreLegacy.circom";
include "./primitives/Sha256Var.circom";
include "./primitives/Sha256CanonPad.circom";
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

template ZkqesPresentationEcdsaLeafV4() {
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
    signal input dobCommit;
    signal input dobSupported;

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
    signal input leafDerLen;
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
    // Sha256CanonPad enforces FIPS 180-4 canonical padding on
    // bindingCorePaddedIn w.r.t. (bindingCore, bindingCoreLen, bindingCorePaddedLen)
    // so the digest committed to by this circuit really is
    // sha256(bindingCore[0..bindingCoreLen)).
    // =========================================================================
    component bcPad = Sha256CanonPad(MAX_BCANON);
    for (var i = 0; i < MAX_BCANON; i++) {
        bcPad.data[i] <== bindingCore[i];
        bcPad.paddedIn[i] <== bindingCorePaddedIn[i];
    }
    bcPad.dataLen <== bindingCoreLen;
    bcPad.paddedLen <== bindingCorePaddedLen;

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
    // 3. sha256(signedAttrs) + EcdsaP256Verify with leaf SPKI. Same canonical
    // padding enforcement as bindingCore above.
    // =========================================================================
    component saPad = Sha256CanonPad(MAX_SA);
    for (var i = 0; i < MAX_SA; i++) {
        saPad.data[i] <== signedAttrs[i];
        saPad.paddedIn[i] <== signedAttrsPaddedIn[i];
    }
    saPad.dataLen <== signedAttrsLen;
    saPad.paddedLen <== signedAttrsPaddedLen;

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

    // =========================================================================
    // 8. DOB extraction + commitment (pluggable per country via DobExtractor).
    // =========================================================================
    component dobExtractor = DobExtractor(MAX_CERT);
    for (var i = 0; i < MAX_CERT; i++) dobExtractor.leafDER[i] <== leafDER[i];
    dobExtractor.leafDerLen <== leafDerLen;

    component dobHash = Poseidon(2);
    dobHash.inputs[0] <== dobExtractor.dobYmd;
    dobHash.inputs[1] <== dobExtractor.sourceTag;

    // When dobSupported=0 the header promises dobCommit=0, but extractors
    // can keep a nonzero sourceTag in the unsupported path (DobExtractorDiiaUA
    // holds sourceTag=1 as a compile-time constant). Gate the commitment so
    // the public signal unambiguously encodes "no DOB" as 0 regardless of
    // per-extractor sourceTag conventions.
    signal dobCommitGated;
    dobCommitGated <== dobExtractor.dobSupported * dobHash.out;

    // Public signals 14 + 15 are wired as constrained inputs so their index
    // order in the public-signal vector follows the spec (inputs-only list on
    // `component main`). The extractor's computed commitment must equal the
    // caller-supplied public input.
    dobCommit    === dobCommitGated;
    dobSupported === dobExtractor.dobSupported;
}

component main {public [pkX, pkY, ctxHash, policyLeafHash, policyRoot, timestamp, nullifier, leafSpkiCommit, dobCommit, dobSupported]}
    = ZkqesPresentationEcdsaLeafV4();
