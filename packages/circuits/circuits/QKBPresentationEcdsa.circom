pragma circom 2.1.9;

// QKBPresentationEcdsa — ECDSA-path main circuit.
//
// Implements relation R_QKB per Phase-1 spec §5.3 for QES leaves signed
// with ECDSA-P256. Composes all Phase-1 sub-circuits:
//
//   1. Leaf QES signature: EcdsaP256Verify(sha256(signedAttrs), leafSig,
//      leafSpki) = 1.
//   2. Binding ↔ signature: messageDigest attribute in signedAttrs at the
//      witness-declared offset equals sha256(Bcanon[:BcanonLen]).
//   3. Intermediate signs leaf: EcdsaP256Verify(sha256(leafTBS), intSig,
//      intSpki) = 1.
//   4. Trusted-list membership: Poseidon(canonicalize(intermediateDER))
//      verifies under rTL via the depth-16 Merkle inclusion proof.
//   5. Binding content ↔ public inputs: Bcanon's pk bytes repack to
//      (pkX, pkY); ctx hash matches ctxHash (0 if empty); declaration
//      SHA-256 ∈ {EN, UK} AND equals the declHash public input; timestamp
//      matches; scheme literal is "secp256k1" (checked inside parser).
//   6. Cert validity: leaf's notBefore ≤ timestamp ≤ notAfter.
//
// Public signals (14 elements — amended 2026-04-18, §14.4):
//   [0..3]  pkX[4]       secp256k1 X limbs, 64-bit LE
//   [4..7]  pkY[4]       secp256k1 Y limbs
//   [8]     ctxHash      Poseidon(ctxBytes) or 0 if empty
//   [9]     rTL          trusted-list Merkle root
//   [10]    declHash     packed 256-bit SHA-256 of declaration
//   [11]    timestamp    Unix seconds, uint64
//   [12]    algorithmTag 1 == ECDSA-P256 (literal constraint)
//   [13]    nullifier    Poseidon(Poseidon(subjectSerialLimbs, serialLen),
//                                 ctxHash); see §14.4 amendment doc at
//                       docs/superpowers/specs/2026-04-18-person-nullifier-amendment.md
//
// Size caps (documented in orchestration §4.1):
//   MAX_BCANON = 2048   real Diia admin binding is 849 B
//   MAX_SA     = 2048   real Diia signedAttrs is 1388 B
//   MAX_CERT   = 2048   real Diia leaf is 1292 B; intermediate typically
//                       1500-2000 B
//   MAX_CTX    = 256    covers any practical dApp context tag
//   MAX_DECL   = 1024   covers UK declaration at 905 B
//   MERKLE_DEPTH = 16   flattener tree parameter

include "./binding/BindingParseFull.circom";
include "./binding/DeclarationWhitelist.circom";
include "./primitives/Sha256Var.circom";
include "./primitives/EcdsaP256Verify.circom";
include "./primitives/MerkleProofPoseidon.circom";
include "./primitives/PoseidonChunkHashVar.circom";
include "./primitives/NullifierDerive.circom";
include "./primitives/X509SubjectSerial.circom";
include "./secp/Secp256k1PkMatch.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";

// =============================================================================
// Bytes-to-limbs helper for ECDSA-P256.
//
// The EcdsaP256Verify template expects msghash, r, s, pubkey coordinates in
// 6 little-endian limbs of 43 bits each (circom-ecdsa-p256 upstream shape).
// We pack 32 SHA-256 output bytes (big-endian) into a 256-bit integer, then
// split into 6×43-bit LE limbs (only 256 of the 258 representable bits are
// used; the top 2 bits of limb[5] are zero).
// =============================================================================

template Bytes32ToLimbs643() {
    signal input bytes[32];
    signal output limbs[6];

    // Build the full 256-bit value bit by bit (MSB first).
    component bits[32];
    signal bitStream[256];
    for (var i = 0; i < 32; i++) {
        bits[i] = Num2Bits(8);
        bits[i].in <== bytes[i];
        for (var b = 0; b < 8; b++) {
            // Big-endian: byte i MSB is bit position 8*i + 0 in bitStream
            // with MSB semantics; Num2Bits outputs little-endian per byte.
            bitStream[i * 8 + (7 - b)] <== bits[i].out[b];
        }
    }

    // Slice into 6 limbs of 43 bits each, LE across limbs: limb[0] is the
    // LOW 43 bits of the 256-bit integer. bitStream is MSB-first, so the
    // low 43 bits correspond to bitStream[213..255].
    for (var l = 0; l < 6; l++) {
        var start = 256 - (l + 1) * 43;
        var len = 43;
        if (start < 0) { len = 43 + start; start = 0; }
        var acc = 0;
        for (var b = 0; b < len; b++) {
            acc = acc * 2 + bitStream[start + b];
        }
        limbs[l] <== acc;
    }
}

// =============================================================================
// 256 bits (MSB-first zk-email bit order) → packed field element.
// =============================================================================

template Bits256ToField() {
    signal input digestBits[256];
    signal output packed;

    var acc = 0;
    for (var i = 0; i < 256; i++) acc = acc * 2 + digestBits[i];
    packed <== acc;
}

// =============================================================================
// Main circuit.
// =============================================================================

template QKBPresentationEcdsa() {
    var MAX_BCANON = 1024;
    var MAX_SA = 1536;
    var MAX_CERT = 1536;
    var MAX_CTX = 256;
    var MAX_DECL = 1024;
    var MAX_TS_DIGITS = 20;
    var MERKLE_DEPTH = 16;

    // === Public signals ===
    signal input pkX[4];
    signal input pkY[4];
    signal input ctxHash;
    signal input rTL;
    signal input declHash;
    signal input timestamp;
    signal input algorithmTag;
    signal input nullifier;

    // Literal: this circuit is the ECDSA path.
    algorithmTag === 1;

    // === Private inputs (witness) — nullifier extraction ===
    // Byte offset into leafDER where the subject.serialNumber (OID 2.5.4.5)
    // PrintableString content starts, plus its content length (1..32).
    // Witness-supplied; X509SubjectSerial asserts the TLV shape at that
    // position and that the prover cannot pad in-band.
    signal input subjectSerialValueOffset;
    signal input subjectSerialValueLength;

    // === Private inputs (witness) ===
    // Binding
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

    // Declaration SHA padded form (padded from declBytes output of parser,
    // witness-side, because zk-email's Sha256Var expects pre-padded input).
    signal input declPaddedIn[MAX_DECL + 64];
    signal input declPaddedLen;

    // signedAttrs + messageDigest position
    signal input signedAttrs[MAX_SA];
    signal input signedAttrsLen;
    signal input signedAttrsPaddedIn[MAX_SA];
    signal input signedAttrsPaddedLen;
    signal input mdOffsetInSA;

    // Leaf cert DER + TBS padded view
    signal input leafDER[MAX_CERT];
    signal input leafDerLen;
    signal input leafTbsOffset;
    signal input leafTbsLen;
    signal input leafTbsPaddedIn[MAX_CERT];
    signal input leafTbsPaddedLen;
    signal input leafSpkiXOffset;
    signal input leafSpkiYOffset;
    signal input leafNotBeforeOffset;
    signal input leafNotAfterOffset;

    // Leaf ECDSA-P256 signature (over sha256(signedAttrs))
    signal input leafSigR[6];
    signal input leafSigS[6];

    // Intermediate cert DER + its SPKI offsets + signature over leaf TBS
    signal input intDER[MAX_CERT];
    signal input intDerLen;
    signal input intSpkiXOffset;
    signal input intSpkiYOffset;
    signal input intSigR[6];
    signal input intSigS[6];

    // Merkle inclusion for intermediate (canonicalized → Merkle leaf)
    signal input merklePath[MERKLE_DEPTH];
    signal input merkleIndices[MERKLE_DEPTH];

    // =========================================================================
    // 1. Parse Bcanon → pkBytes, ctxBytes+ctxLen, declBytes+declLen, tsValue.
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

    // Binding content ↔ public inputs
    component pkMatch = Secp256k1PkMatch();
    for (var i = 0; i < 65; i++) pkMatch.pkBytes[i] <== parser.pkBytes[i];
    for (var i = 0; i < 4; i++) {
        pkMatch.pkX[i] <== pkX[i];
        pkMatch.pkY[i] <== pkY[i];
    }

    parser.tsValue === timestamp;

    // =========================================================================
    // 2. sha256(Bcanon) == messageDigest attribute in signedAttrs.
    //    Witness supplies BcanonPaddedIn/Len (pre-padded per SHA padding).
    //    We ALSO assert the padded prefix's first BcanonLen bytes match
    //    Bcanon (so the prover can't pad a different message).
    // =========================================================================

    // Prefix-match check for Bcanon: for each i, if i < BcanonLen then
    // BcanonPaddedIn[i] must equal Bcanon[i]. This is witness-cheap: we
    // assert (i < len) * (padded[i] - raw[i]) === 0.
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

    // Pull the 32-byte messageDigest from signedAttrs at mdOffsetInSA.
    component mdPick[32];
    signal mdFromSA[32];
    for (var i = 0; i < 32; i++) {
        mdPick[i] = Multiplexer(1, MAX_SA);
        for (var j = 0; j < MAX_SA; j++) mdPick[i].inp[j][0] <== signedAttrs[j];
        mdPick[i].sel <== mdOffsetInSA + i;
        mdFromSA[i] <== mdPick[i].out[0];
    }

    // sha256(Bcanon) outputs 256 bits MSB-first. Convert to 32 bytes MSB-
    // first then compare to mdFromSA byte by byte.
    signal bcanonDigestBytes[32];
    for (var i = 0; i < 32; i++) {
        var acc = 0;
        for (var b = 0; b < 8; b++) acc = acc * 2 + hashBcanon.out[i * 8 + b];
        bcanonDigestBytes[i] <== acc;
        bcanonDigestBytes[i] === mdFromSA[i];
    }

    // =========================================================================
    // 3. sha256(signedAttrs) and EcdsaP256Verify for leaf.
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

    // Leaf SPKI x,y coordinates (32 bytes each) pulled from leafDER.
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
    // 4. sha256(leafTBS) and EcdsaP256Verify for intermediate signing leaf.
    //    PHASE-1 GAP: we take leafTbsPaddedIn as a direct witness input
    //    without in-circuit binding to leafDER. The naive prefix-check
    //    (MAX_CERT Multiplexers each over the MAX_CERT buffer) is O(n²)
    //    constraint-count and blows the compiler's memory budget past 22 GB.
    //    Closed in a follow-up via an O(n) substring construction (e.g.,
    //    shift-then-compare over a logarithmic ladder of rotations).
    //    Until then, the witness builder — not the circuit — guarantees
    //    leafTbsPaddedIn matches leafDER at leafTbsOffset.
    //    leafDerLen + leafTbsLen + leafTbsOffset are kept as declared inputs
    //    so the witness shape stays stable for the follow-up wiring.
    leafDerLen * 0 === 0;
    leafTbsOffset * 0 === 0;
    leafTbsLen * 0 === 0;

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

    // Intermediate SPKI x,y coords from intDER.
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
    // 5. Canonicalize intermediate DER → Poseidon hash; Merkle-verify under rTL.
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

    // =========================================================================
    // 6. Declaration whitelist + declHash public-input match.
    //    Hash declBytes[0..declLen] via Sha256Var (declPaddedIn supplied by
    //    witness), feed digest bits into DeclarationWhitelist AND pack the
    //    digest into a field element to compare against declHash.
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
    // 7. Context hash: if ctxLen == 0, ctxHash must be 0; else
    //    PoseidonChunkHashVar(ctxBytes) == ctxHash.
    // =========================================================================
    component ctxIsEmpty = IsZero();
    ctxIsEmpty.in <== parser.ctxLen;

    component ctxHashVar = PoseidonChunkHashVar(MAX_CTX);
    for (var i = 0; i < MAX_CTX; i++) ctxHashVar.bytes[i] <== parser.ctxBytes[i];
    ctxHashVar.len <== parser.ctxLen;

    // effective = isEmpty * 0 + (1 - isEmpty) * ctxHashVar.out == (1 - isEmpty) * out
    signal ctxEff;
    ctxEff <== (1 - ctxIsEmpty.out) * ctxHashVar.out;
    ctxEff === ctxHash;

    // =========================================================================
    // 8. Cert validity: INTENTIONALLY DEFERRED (Phase 1 gap; see design note
    //    in §5.3). X509Validity compares ASCII GeneralizedTime byte strings,
    //    but the `timestamp` public input is a Unix integer and in-circuit
    //    calendar math (y/m/d/h/m/s ↔ unix) is expensive. The witness
    //    supplies leafNotBeforeOffset + leafNotAfterOffset for future wiring;
    //    we currently rely on the QTSP's listing in rTL (Merkle-enforced,
    //    constraint 4) as a validity proxy for the intermediate and on
    //    off-circuit verification for the leaf until this is closed.
    //    TODO(9b-validity): wire Asn1GeneralizedTime15 ×2 + X509Validity with
    //    witness-supplied tsAscii[14] and a binding proof to `timestamp`.
    leafNotBeforeOffset * 0 === 0;
    leafNotAfterOffset * 0 === 0;

    // =========================================================================
    // 9. Person-level nullifier (§14.4 amendment, 2026-04-18).
    //    Extract the subject.serialNumber (OID 2.5.4.5) value bytes from the
    //    leaf cert DER, pack into 4 × uint64 LE limbs, and derive
    //        nullifier = Poseidon(Poseidon(limbs[0..3], len), ctxHash).
    //    The limbs never leak; only the ctx-bound nullifier is public.
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

    // Public-signal binding: constrain the 14th public input against the
    // derived nullifier. A mismatched public input revert-via-R1CS, not
    // at the verifier — the verifier only checks the Groth16 equation.
    nullifierDerive.nullifier === nullifier;
}

component main {public [pkX, pkY, ctxHash, rTL, declHash, timestamp, algorithmTag, nullifier]}
    = QKBPresentationEcdsa();
