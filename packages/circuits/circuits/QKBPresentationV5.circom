pragma circom 2.1.9;

include "./binding/BindingParseV2CoreFast.circom";
include "./primitives/Sha256Var.circom";
include "./primitives/Sha256CanonPad.circom";
include "./primitives/SignedAttrsParser.circom";
include "./primitives/X509SubjectSerial.circom";
include "./primitives/NullifierDerive.circom";
include "./primitives/PoseidonChunkHashVar.circom";
include "./primitives/Bytes32ToHiLo.circom";
include "./primitives/SpkiCommit.circom";
include "./secp/Secp256k1PkMatch.circom";

/// @title  QKBPresentationV5 — V5 single-circuit ZK presentation proof.
/// @notice Public-signal layout per V5 spec §0.1 (frozen 14 elements):
///         [0]  msgSender              ≤ 2^160
///         [1]  timestamp              ≤ 2^64
///         [2]  nullifier              Poseidon₂ output
///         [3]  ctxHashHi              uint128 — high 128 bits of SHA-256(ctxBytes)
///         [4]  ctxHashLo              uint128 — low  128 bits
///         [5]  bindingHashHi          uint128 — high 128 bits of SHA-256(bindingBytes)
///         [6]  bindingHashLo          uint128
///         [7]  signedAttrsHashHi      uint128 — high 128 bits of SHA-256(signedAttrs DER)
///         [8]  signedAttrsHashLo      uint128
///         [9]  leafTbsHashHi          uint128 — high 128 bits of SHA-256(leaf TBSCertificate)
///         [10] leafTbsHashLo          uint128
///         [11] policyLeafHash         field — uint256(sha256(JCS(policyLeafObject))) mod p
///         [12] leafSpkiCommit         field — SpkiCommit(leafSpki)
///         [13] intSpkiCommit          field — SpkiCommit(intSpki)
///
/// Layout MUST match arch-contracts QKBRegistryV5.PublicSignals struct
/// (commit confirmed 2026-04-29). Per CLAUDE.md invariant 8, ALL 14 are
/// declared as `signal input` so snarkjs's `[outputs..., public_inputs...]`
/// emission order places them in the canonical positions.
///
/// ctxHash domain note (lead-greenlit option A, 2026-04-29):
///   Public ctxHashHi/Lo is the SHA-256 of ctxBytes (hi/lo 128-bit split).
///   NullifierDerive's internal ctxHash input is PoseidonChunkHashVar(ctxBytes)
///   — a separate field-domain hash. The two hashes are computed independently
///   from the same witnessed ctxBytes; no cross-binding constraint needed.
template QKBPresentationV5() {
    // MAX bounds per V5 spec v5 §0.5. Two empirical bumps from the original
    // estimates (commit b8e0f74 / 139c475 in this worktree):
    //   MAX_SA     256 → 1536  (real Diia CAdES-X-L signedAttrs measured 1388 B)
    //   MAX_BCANON 768 → 1024  (real Diia binding measured 849 B, ~21% headroom)
    var MAX_BCANON   = 1024;
    var MAX_SA       = 1536;
    var MAX_LEAF_TBS = 1024;
    var MAX_CERT     = 2048;
    var MAX_CTX      = 256;
    var MAX_TS_DIGITS = 20;
    var MAX_POLICY_ID = 128;

    // ===== Public inputs (14 field elements, FROZEN order — see §0.1) =====
    signal input msgSender;
    signal input timestamp;
    signal input nullifier;
    signal input ctxHashHi;
    signal input ctxHashLo;
    signal input bindingHashHi;
    signal input bindingHashLo;
    signal input signedAttrsHashHi;
    signal input signedAttrsHashLo;
    signal input leafTbsHashHi;
    signal input leafTbsHashLo;
    signal input policyLeafHash;
    signal input leafSpkiCommit;
    signal input intSpkiCommit;

    // ===== Private witness inputs (variable-length data + offsets) =====
    // Canonical binding bytes + length (consumed by BindingParseV2Core +
    // Sha256Var(MAX_BCANON)).
    signal input bindingBytes[MAX_BCANON];
    signal input bindingLength;
    signal input bindingPaddedIn[MAX_BCANON];
    signal input bindingPaddedLen;

    // BindingParseV2Core offsets (one per parsed field — see V2Core's
    // `signal input` block for the canonical list).
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
    signal input nonceBytesIn[32];
    signal input policyIdBytesIn[MAX_POLICY_ID];
    signal input policyVersionIn;

    // Padded forms for the three SHA-256 inputs. Sha256Var consumes
    // MerkleDamgard-padded bytes + paddedLen; we keep the unpadded
    // counterparts for parser/walker consumption.
    signal input signedAttrsBytes[MAX_SA];
    signal input signedAttrsLength;
    signal input signedAttrsPaddedIn[MAX_SA];
    signal input signedAttrsPaddedLen;
    signal input mdAttrOffset; // SignedAttrsParser fixed-shape offset (§4)

    signal input leafTbsBytes[MAX_LEAF_TBS];
    signal input leafTbsLength;
    signal input leafTbsPaddedIn[MAX_LEAF_TBS];
    signal input leafTbsPaddedLen;

    // Leaf X.509 cert DER for subject-serial extraction (NullifierDerive input).
    signal input leafCertBytes[MAX_CERT];
    signal input subjectSerialValueOffset;
    signal input subjectSerialValueLength;

    // SPKI limbs for both leaf and intermediate (witness side; on-chain
    // P256Verify.spkiCommit recomputes the SAME value from calldata bytes).
    signal input leafXLimbs[6];
    signal input leafYLimbs[6];
    signal input intXLimbs[6];
    signal input intYLimbs[6];

    // secp256k1 wallet pk for msg.sender binding (Secp256k1PkMatch consumes
    // these against the binding's `pk` field).
    signal input pkX[4];
    signal input pkY[4];

    // ===== Body wiring =====
    // Tasks 6.2-6.10 wire the constraints in order:
    //   6.2 — BindingParseV2CoreFast: expose timestamp + policyLeafHash      ← THIS COMMIT
    //   6.3 — 3× Sha256Var (binding, signedAttrs, leafTBS) + Bytes32ToHiLo
    //   6.4 — SignedAttrsParser, messageDigest === bindingHash equality
    //   6.5 — 2× SpkiCommit (leaf + intermediate)
    //   6.6 — X509SubjectSerial + NullifierDerive (Poseidon-domain ctxHash)
    //   6.7 — Sha256Var(ctxBytes) + Bytes32ToHiLo for public ctxHashHi/Lo
    //   6.8 — Secp256k1PkMatch (msgSender ← pkX/pkY)
    //   6.9 — leafTBS bound to leaf-cert DER consistency
    //   6.10 — final E2E test on real Diia fixture

    // §6.2 — BindingParseV2CoreFast
    // Parses the JCS-canonicalized binding bytes, asserts every required
    // field-key prefix at its witnessed offset, and produces 8 outputs.
    // Two of those outputs are bound to public signals here (timestamp,
    // policyLeafHash); the rest (pkBytes, nonceBytes, ctxBytes, ctxLen,
    // policyIdBytes) are consumed by later wiring (Secp256k1PkMatch in §6.8,
    // ctx-domain hashes in §6.6/6.7).
    component parser = BindingParseV2CoreFast(MAX_BCANON, MAX_CTX, MAX_TS_DIGITS);
    for (var i = 0; i < MAX_BCANON; i++) parser.bytes[i] <== bindingBytes[i];
    parser.bcanonLen <== bindingLength;
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
    for (var i = 0; i < 32; i++) parser.nonceBytesIn[i] <== nonceBytesIn[i];
    for (var i = 0; i < MAX_POLICY_ID; i++) parser.policyIdBytesIn[i] <== policyIdBytesIn[i];
    parser.policyVersionIn <== policyVersionIn;

    // Public-signal binds:
    parser.tsValue       === timestamp;
    parser.policyLeafHash === policyLeafHash;

    // §6.3 — Three SHA-256 chains (binding, signedAttrs, leafTBS).
    // Each chain is identical in shape:
    //   1. Sha256CanonPad asserts that paddedIn is the FIPS-180-4 canonical
    //      padding of (data, dataLen). Without this the prover could supply
    //      a paddedIn whose unpadded prefix differs from `data` and the
    //      circuit would happily hash a different message.
    //   2. Sha256Var consumes the validated paddedIn → 256 output bits.
    //   3. We pack the 256 bits into 32 big-endian bytes (bit 0 = MSB of
    //      byte 0), then split into two 128-bit halves via Bytes32ToHiLo.
    //   4. The two halves bind to public signals at indices [5,6] (binding),
    //      [7,8] (signedAttrs), [9,10] (leafTBS) per V5 spec §0.1.
    //
    // The bindingDigestBytes signal is reused by §6.4 as the LHS of the
    // CAdES messageDigest equality (parser.tsValue and parser.policyLeafHash
    // were the only outputs needed off the parser; the binding-hash itself
    // is what closes the soundness loop with the cert chain).

    // --- binding ---
    component bcPad = Sha256CanonPad(MAX_BCANON);
    for (var i = 0; i < MAX_BCANON; i++) {
        bcPad.data[i]      <== bindingBytes[i];
        bcPad.paddedIn[i]  <== bindingPaddedIn[i];
    }
    bcPad.dataLen   <== bindingLength;
    bcPad.paddedLen <== bindingPaddedLen;

    component hashBinding = Sha256Var(MAX_BCANON);
    for (var i = 0; i < MAX_BCANON; i++) hashBinding.paddedIn[i] <== bindingPaddedIn[i];
    hashBinding.paddedLen <== bindingPaddedLen;

    signal bindingDigestBytes[32];
    for (var i = 0; i < 32; i++) {
        var acc = 0;
        for (var b = 0; b < 8; b++) acc = acc * 2 + hashBinding.out[i * 8 + b];
        bindingDigestBytes[i] <== acc;
    }
    component bindingHiLo = Bytes32ToHiLo();
    for (var i = 0; i < 32; i++) bindingHiLo.bytes[i] <== bindingDigestBytes[i];
    bindingHiLo.hi === bindingHashHi;
    bindingHiLo.lo === bindingHashLo;

    // --- signedAttrs ---
    component saPad = Sha256CanonPad(MAX_SA);
    for (var i = 0; i < MAX_SA; i++) {
        saPad.data[i]     <== signedAttrsBytes[i];
        saPad.paddedIn[i] <== signedAttrsPaddedIn[i];
    }
    saPad.dataLen   <== signedAttrsLength;
    saPad.paddedLen <== signedAttrsPaddedLen;

    component hashSignedAttrs = Sha256Var(MAX_SA);
    for (var i = 0; i < MAX_SA; i++) hashSignedAttrs.paddedIn[i] <== signedAttrsPaddedIn[i];
    hashSignedAttrs.paddedLen <== signedAttrsPaddedLen;

    signal signedAttrsDigestBytes[32];
    for (var i = 0; i < 32; i++) {
        var acc = 0;
        for (var b = 0; b < 8; b++) acc = acc * 2 + hashSignedAttrs.out[i * 8 + b];
        signedAttrsDigestBytes[i] <== acc;
    }
    component signedAttrsHiLo = Bytes32ToHiLo();
    for (var i = 0; i < 32; i++) signedAttrsHiLo.bytes[i] <== signedAttrsDigestBytes[i];
    signedAttrsHiLo.hi === signedAttrsHashHi;
    signedAttrsHiLo.lo === signedAttrsHashLo;

    // --- leafTBS ---
    component leafTbsPad = Sha256CanonPad(MAX_LEAF_TBS);
    for (var i = 0; i < MAX_LEAF_TBS; i++) {
        leafTbsPad.data[i]     <== leafTbsBytes[i];
        leafTbsPad.paddedIn[i] <== leafTbsPaddedIn[i];
    }
    leafTbsPad.dataLen   <== leafTbsLength;
    leafTbsPad.paddedLen <== leafTbsPaddedLen;

    component hashLeafTbs = Sha256Var(MAX_LEAF_TBS);
    for (var i = 0; i < MAX_LEAF_TBS; i++) hashLeafTbs.paddedIn[i] <== leafTbsPaddedIn[i];
    hashLeafTbs.paddedLen <== leafTbsPaddedLen;

    signal leafTbsDigestBytes[32];
    for (var i = 0; i < 32; i++) {
        var acc = 0;
        for (var b = 0; b < 8; b++) acc = acc * 2 + hashLeafTbs.out[i * 8 + b];
        leafTbsDigestBytes[i] <== acc;
    }
    component leafTbsHiLo = Bytes32ToHiLo();
    for (var i = 0; i < 32; i++) leafTbsHiLo.bytes[i] <== leafTbsDigestBytes[i];
    leafTbsHiLo.hi === leafTbsHashHi;
    leafTbsHiLo.lo === leafTbsHashLo;

    // §6.4 — SignedAttrsParser + CAdES messageDigest equality.
    //
    // Soundness chain (the load-bearing invariant for the whole V5 design):
    //   sha256(bindingBytes)   = bindingDigestBytes      (§6.3 above)
    //   bindingDigestBytes     = signedAttrsParser.messageDigestBytes  (here)
    //   signedAttrsParser only verifies a fixed-shape 17-byte CAdES prefix
    //     at mdAttrOffset, but that's sound BECAUSE signedAttrsBytes is
    //     elsewhere bound to the leaf cert via ECDSA (§6.9 leafTBS bind +
    //     EIP-7212 on-chain verification). If §6.9 ever weakens the
    //     leafCert ↔ signedAttrs binding, the §4 fixed-shape walker
    //     becomes insufficient and must be replaced by a position-agnostic
    //     SET OF walker. Auditors will look for this; do NOT relax.
    component saParser = SignedAttrsParser(MAX_SA);
    for (var i = 0; i < MAX_SA; i++) saParser.bytes[i] <== signedAttrsBytes[i];
    saParser.length       <== signedAttrsLength;
    saParser.mdAttrOffset <== mdAttrOffset;

    for (var i = 0; i < 32; i++) {
        bindingDigestBytes[i] === saParser.messageDigestBytes[i];
    }

    // §6.5 — Two SpkiCommit instances (leaf + intermediate).
    //
    // Each commits Poseidon₂(Poseidon₆(xLimbs), Poseidon₆(yLimbs)) over the
    // 6×43-bit LE limb decomposition of the P-256 affine point. The same
    // construction is computed contract-side from the calldata-supplied DER
    // SPKI bytes (P256Verify.spkiCommit, parity-fixture-gated at §9.1).
    // Public signals at indices [12] and [13] per V5 spec §0.1.
    component leafSpki = SpkiCommit();
    for (var i = 0; i < 6; i++) {
        leafSpki.xLimbs[i] <== leafXLimbs[i];
        leafSpki.yLimbs[i] <== leafYLimbs[i];
    }
    leafSpki.commit === leafSpkiCommit;

    component intSpki = SpkiCommit();
    for (var i = 0; i < 6; i++) {
        intSpki.xLimbs[i] <== intXLimbs[i];
        intSpki.yLimbs[i] <== intYLimbs[i];
    }
    intSpki.commit === intSpkiCommit;

    // §6.6 — X509SubjectSerial + NullifierDerive.
    //
    // X509SubjectSerial(MAX_CERT) reads the leaf-cert DER at the witnessed
    // (subjectSerialValueOffset, subjectSerialValueLength) — pointing at the
    // VALUE bytes of the OID 2.5.4.5 (subject serial) RDN attribute — and
    // packs up to 32 content bytes into 4 × uint64 LE limbs. Length is
    // constrained ∈ [1, 32]; positions ≥ length are masked to zero before
    // packing, so DER-tail bytes can never leak into the limbs. The
    // (offset, length) pair is bound to the cert's TBS via leafTbsBytes
    // ↔ leafCertBytes byte-equality (deferred to §6.9).
    //
    // PoseidonChunkHashVar(MAX_CTX) computes the FIELD-DOMAIN ctxHash over
    // parser.ctxBytes / parser.ctxLen. This is INDEPENDENT of the public
    // ctxHashHi/Lo signal pair (which is the byte-domain SHA-256 of the
    // same ctxBytes; that wiring lands in §6.7). Both hashes are computed
    // from the same parser-output ctxBytes/ctxLen, so no cross-binding
    // constraint is required — see header note "ctxHash domain" above.
    //
    // NullifierDerive: Poseidon-5(limbs[0..3], len) → secret;
    //                  Poseidon-2(secret, ctxHash) → nullifier.
    component subjectSerial = X509SubjectSerial(MAX_CERT);
    for (var i = 0; i < MAX_CERT; i++) subjectSerial.leafDER[i] <== leafCertBytes[i];
    subjectSerial.subjectSerialValueOffset <== subjectSerialValueOffset;
    subjectSerial.subjectSerialValueLength <== subjectSerialValueLength;

    component ctxFieldHash = PoseidonChunkHashVar(MAX_CTX);
    for (var i = 0; i < MAX_CTX; i++) ctxFieldHash.bytes[i] <== parser.ctxBytes[i];
    ctxFieldHash.len <== parser.ctxLen;

    component nullifierDer = NullifierDerive();
    for (var i = 0; i < 4; i++) {
        nullifierDer.subjectSerialLimbs[i] <== subjectSerial.subjectSerialLimbs[i];
    }
    nullifierDer.subjectSerialLen <== subjectSerialValueLength;
    nullifierDer.ctxHash          <== ctxFieldHash.out;

    nullifierDer.nullifier === nullifier;

    // Witness-anchor for the still-unwired public signals (§6.7-§6.10 will
    // replace this with real constraints; for now the sum keeps each signal
    // syntactically used so circom doesn't strip-prune the public-input
    // declarations from `component main { public [...] }`).
    //
    // Now constrained for real (removed from the sum):
    //   timestamp, policyLeafHash (§6.2)
    //   bindingHashHi/Lo, signedAttrsHashHi/Lo, leafTbsHashHi/Lo (§6.3)
    //   leafSpkiCommit, intSpkiCommit (§6.5)
    //   nullifier (§6.6)
    signal _unusedHash;
    _unusedHash <== msgSender
                 + ctxHashHi + ctxHashLo;
}

component main { public [
    msgSender,
    timestamp,
    nullifier,
    ctxHashHi,
    ctxHashLo,
    bindingHashHi,
    bindingHashLo,
    signedAttrsHashHi,
    signedAttrsHashLo,
    leafTbsHashHi,
    leafTbsHashLo,
    policyLeafHash,
    leafSpkiCommit,
    intSpkiCommit
] } = QKBPresentationV5();
