pragma circom 2.1.9;

include "./binding/BindingParseV2CoreFast.circom";
include "./primitives/Sha256Var.circom";
include "./primitives/Sha256CanonPad.circom";
include "./primitives/SignedAttrsParser.circom";
include "./primitives/X509SubjectSerial.circom";
// V5 NullifierDerive primitive replaced inline by V5.1 wallet-bound construction
// (Poseidon₂(walletSecret, ctxFieldHash)) — see header docstring + §6.6 wiring.
include "./primitives/PoseidonChunkHashVar.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "./primitives/Bytes32ToHiLo.circom";
include "./primitives/SpkiCommit.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";
// V5.2: dropped Secp256k1PkMatch + Secp256k1AddressDerive (§6.8 keccak-on-chain
// amendment, 2026-05-01). The wallet-pk → msg.sender keccak gate now fires in
// the contract layer; circuit just emits the binding's claimed pk as 4 ×
// 128-bit limbs (bindingPkXHi/Lo, bindingPkYHi/Lo) for the contract to keccak.

/// @title  ZkqesPresentationV5 — V5.2 single-circuit ZK presentation proof.
/// @notice Public-signal layout per V5.2 keccak-on-chain amendment
///         (`docs/superpowers/specs/2026-05-01-keccak-on-chain-amendment.md`,
///         pending user-review at v0.4) layered on V5.1 wallet-bound nullifier
///         (`docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md`,
///         user-approved at `df203b8` on 2026-04-30) — frozen 22 elements:
///         [0]  timestamp              ≤ 2^64
///         [1]  nullifier              Poseidon₂(walletSecret, ctxFieldHash) — V5.1 construction
///         [2]  ctxHashHi              uint128 — high 128 bits of SHA-256(ctxBytes)
///         [3]  ctxHashLo              uint128 — low  128 bits
///         [4]  bindingHashHi          uint128 — high 128 bits of SHA-256(bindingBytes)
///         [5]  bindingHashLo          uint128
///         [6]  signedAttrsHashHi      uint128 — high 128 bits of SHA-256(signedAttrs DER)
///         [7]  signedAttrsHashLo      uint128
///         [8]  leafTbsHashHi          uint128 — high 128 bits of SHA-256(leaf TBSCertificate)
///         [9]  leafTbsHashLo          uint128
///         [10] policyLeafHash         field — uint256(sha256(JCS(policyLeafObject))) mod p
///         [11] leafSpkiCommit         field — SpkiCommit(leafSpki)
///         [12] intSpkiCommit          field — SpkiCommit(intSpki)
///         [13] identityFingerprint    field — Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)  ← V5.1
///         [14] identityCommitment     field — Poseidon₂(subjectSerialPacked, walletSecret)        ← V5.1
///         [15] rotationMode           bool — 0 = register, 1 = rotateWallet                        ← V5.1
///         [16] rotationOldCommitment  field — under register: == identityCommitment;
///                                              under rotate:   prior commitment from chain        ← V5.1
///         [17] rotationNewWallet      field — register: == msg.sender (CONTRACT-enforced in V5.2);
///                                              rotate:   new-wallet address (≤2^160)              ← V5.1
///         [18] bindingPkXHi           uint128 — upper 128 bits of binding-attested wallet pkX     ← V5.2 NEW
///         [19] bindingPkXLo           uint128 — lower 128 bits of binding-attested wallet pkX     ← V5.2 NEW
///         [20] bindingPkYHi           uint128 — upper 128 bits of binding-attested wallet pkY     ← V5.2 NEW
///         [21] bindingPkYLo           uint128 — lower 128 bits of binding-attested wallet pkY     ← V5.2 NEW
///
/// V5.2 amendment summary (2026-05-01): the V5.1 in-circuit Keccak-256 +
/// Secp256k1PkMatch chain that derived `msgSender` from the binding's pk
/// (~200K constraints) is REMOVED. The 4 new public signals 18-21 carry
/// the binding's claimed pubkey directly; the contract reconstructs the
/// 64-byte uncompressed pk and runs `address(uint160(uint256(keccak256(
/// uncompressedPk)))) == msg.sender` natively (~5K gas vs ~200K
/// constraints). This unlocks Groth16-zkey portability across all
/// EVM-family chains with EIP-7212 P256Verify (mainnet, Base, Optimism
/// post-Pectra; Arbitrum / Polygon zkEVM blocked on P256). Non-EVM
/// chains (Solana, Cosmos, Aptos, Sui) need a chain-specific auth-shim
/// before V5.2 deploys there.
///
/// Layout MUST match arch-contracts ZkqesRegistryV5_2.PublicSignalsV52 struct
/// (frozen by V5.2 spec §"Public-signal layout V5.1 (19) → V5.2 (22)"). All
/// 22 are declared as `signal input` so snarkjs's
/// `[outputs..., public_inputs...]` emission order places them in the
/// canonical positions.
///
/// ctxHash domain note (lead-greenlit option A, 2026-04-29):
///   Public ctxHashHi/Lo is the SHA-256 of ctxBytes (hi/lo 128-bit split).
///   The internal ctxHash used by the V5.1 nullifier construction is
///   PoseidonChunkHashVar(ctxBytes) — a separate field-domain hash. The two
///   hashes are computed independently from the same witnessed ctxBytes; no
///   cross-binding constraint needed.
///
/// V5.1 wallet-bound nullifier construction (replaces V5 NullifierDerive):
///   subjectSerialPacked  = Poseidon₅(subjectSerialLimbs[0..3], subjectSerialLen)
///   identityFingerprint  = Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)
///   identityCommitment   = Poseidon₂(subjectSerialPacked, walletSecret)
///   nullifier            = Poseidon₂(walletSecret, ctxFieldHash)
///
/// `walletSecret` is a private 254-bit input. Off-circuit derivation per spec:
///   EOA path: HKDF-SHA256(personal_sign(walletPriv, "qkb-personal-secret-v1" || subjectSerial))  // frozen protocol byte strings; see specs/2026-05-03-zkqes-rename-design.md §3
///   SCW path: Argon2id(passphrase, salt="qkb-walletsecret-v1" || walletAddr)  // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
/// then truncated/reduced mod the BN254 scalar field. Circuit treats it as
/// an opaque field element with a 254-bit range check (Num2Bits) for safety.
///
/// rotation_mode no-op binding (under rotationMode == 0 register path):
///   rotationOldCommitment === identityCommitment  (free under rotation mode)
///   rotationNewWallet     === msg.sender          (CONTRACT-enforced in V5.2;
///                                                  was circuit-enforced in V5.1
///                                                  via ForceEqualIfEnabled(=msgSender);
///                                                  moved on-chain because msgSender
///                                                  is no longer a circuit public signal)
/// rotationOldCommitment no-op still implemented via
/// `ForceEqualIfEnabled(enabled = 1 - rotationMode, ...)`. rotationMode itself
/// is boolean-range-checked (`rm * (rm - 1) === 0`).
template ZkqesPresentationV5() {
    // MAX bounds per V5 spec v5 §0.5. Two empirical bumps from the original
    // estimates (commit b8e0f74 / 139c475 in this worktree):
    //   MAX_SA     256 → 1536  (real Diia CAdES-X-L signedAttrs measured 1388 B)
    //   MAX_BCANON 768 → 1024  (real Diia binding measured 849 B, ~21% headroom)
    var MAX_BCANON   = 1024;
    var MAX_SA       = 1536;
    // MAX_LEAF_TBS 1024→1408 (empirical bump 2026-04-30): real Diia
    // admin-ecdsa leaf TBS measures 1203 bytes (paddedLen 1216), exceeding
    // the spec's "~700-900 bytes" assumption. Bump to 1408 = 22 SHA blocks
    // gives ~17% headroom over the 1216 padded-length floor — matches the
    // spec convention of ~20% (MAX_BCANON 1024 over real 849, MAX_SA 1536
    // over real 1388). Cost delta versus 1024 is +6 SHA blocks worth of
    // Sha256Var + Sha256CanonPad, ~+330K constraints projected.
    var MAX_LEAF_TBS = 1408;
    var MAX_CERT     = 2048;
    var MAX_CTX      = 256;
    // Sha256CanonPad needs MAX_BYTES ≥ ⌈(MAX_CTX + 9) / 64⌉ × 64 = 320 to
    // safely hold the canonical FIPS-180-4 padding for any honest ctxLen
    // up to MAX_CTX. The parser only emits ctxBytes[MAX_CTX]; we extend by
    // zero in the wiring below so the SHA chain operates on a 320-slot
    // padded view. (parser.ctxLen ≤ MAX_CTX is enforced by the parser.)
    var MAX_CTX_PADDED = 320;
    var MAX_TS_DIGITS = 20;
    var MAX_POLICY_ID = 128;

    // ===== Public inputs (22 field elements, FROZEN order — see header §0.1 V5.2) =====
    // V5.2 amendment (2026-05-01): msgSender removed from public signals (the
    // keccak-derived address is now reconstructed contract-side); 4 new
    // wallet-pk limbs appended at slots 18-21 for that contract-side derivation.
    // Slots 0-13 reshuffled DOWN BY ONE from V5.1 to fill the freed slot 0.
    signal input timestamp;               // [0]
    signal input nullifier;               // [1]
    signal input ctxHashHi;               // [2]
    signal input ctxHashLo;               // [3]
    signal input bindingHashHi;           // [4]
    signal input bindingHashLo;           // [5]
    signal input signedAttrsHashHi;       // [6]
    signal input signedAttrsHashLo;       // [7]
    signal input leafTbsHashHi;           // [8]
    signal input leafTbsHashLo;           // [9]
    signal input policyLeafHash;          // [10]
    signal input leafSpkiCommit;          // [11]
    signal input intSpkiCommit;           // [12]
    // ----- V5.1 amendment additions (slots 13-17 in V5.2 numbering) -----
    signal input identityFingerprint;     // [13]
    signal input identityCommitment;      // [14]
    signal input rotationMode;            // [15] 0 = register, 1 = rotateWallet
    signal input rotationOldCommitment;   // [16] register: == identityCommitment (no-op);
                                          //      rotate:   prior commitment from chain
    signal input rotationNewWallet;       // [17] register: == msg.sender (contract-enforced
                                          //      in V5.2; was circuit-enforced in V5.1)
                                          //      rotate:   new-wallet address (≤2^160)
    // ----- V5.2 amendment additions (slots 18-21) — wallet-pk limbs for on-chain keccak -----
    // Each pk coordinate (X, Y) is 256 bits = 2 × 128-bit limbs, big-endian
    // (Hi = leftmost 16 bytes, Lo = rightmost 16 bytes). The contract
    // reconstructs the 64-byte uncompressed pubkey by concatenating
    // (Hi << 128 | Lo) for each coordinate, then keccak256 + low-160-bit
    // cast → asserts == msg.sender (register mode) or == identityWallets[fp]
    // (rotate mode, defense-in-depth per contracts-eng v0.4 review).
    signal input bindingPkXHi;            // [18]
    signal input bindingPkXLo;            // [19]
    signal input bindingPkYHi;            // [20]
    signal input bindingPkYLo;            // [21]

    // FINGERPRINT_DOMAIN — fixed compile-time constant for identity-fingerprint domain
    // separation. Field-element encoding of the ASCII string "qkb-id-fingerprint-v1"
    // (frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3)
    // (21 bytes, big-endian-packed). Verified: 0x71='q', 0x6b='k', 0x62='b', 0x2d='-',
    // 0x69='i', 0x64='d', 0x2d='-', 0x66='f', 0x69='i', 0x6e='n', 0x67='g', 0x65='e',
    // 0x72='r', 0x70='p', 0x72='r', 0x69='i', 0x6e='n', 0x74='t', 0x2d='-', 0x76='v',
    // 0x31='1' = 168 bits. Well below the BN254 scalar field (~254 bits).
    var FINGERPRINT_DOMAIN = 0x716b622d69642d66696e6765727072696e742d7631;

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

    // ctxBytes SHA chain (§6.7). The unpadded ctxBytes come from the parser
    // (parser.ctxBytes / parser.ctxLen), so only the canonical-pad witness
    // form is exposed here. MAX_CTX_PADDED = 320 covers MAX_CTX = 256 + 64
    // padding overhead.
    signal input ctxPaddedIn[MAX_CTX_PADDED];
    signal input ctxPaddedLen;

    // Leaf X.509 cert DER for subject-serial extraction (NullifierDerive input).
    signal input leafCertBytes[MAX_CERT];
    signal input subjectSerialValueOffset;
    signal input subjectSerialValueLength;
    // §6.9 — offset of the SAME subject-serial VALUE bytes inside leafTbs
    // (= subjectSerialValueOffset minus the in-cert TBSCertificate offset).
    // Witness-supplied; the byte-equality gate in §6.9 binds the leafCert
    // bytes consumed by X509SubjectSerial to the leafTbs bytes hashed by
    // Sha256Var(MAX_LEAF_TBS), closing the soundness loop that pins the
    // subject-serial extraction to the intermediate-signed TBSCertificate.
    signal input subjectSerialValueOffsetInTbs;

    // V5.3 F1 — OID-anchor offset.  Byte offset (inside leafTbs) of
    // the leading `06 03 55 04 05` DER bytes for the
    // `AttributeTypeAndValue { type=OID 2.5.4.5 (id-at-serialNumber),
    // value=DirectoryString }` ASN.1 frame.  The §6.9b gate below
    // anchors subjectSerialValueOffsetInTbs to this offset + 7,
    // closing the V5.2 Sybil vector where a malicious prover could
    // point the value-offset at any 32-byte window in the signed
    // TBS that happens to look serial-number-shaped.  See V5.3 spec
    // §F1.2 for the full attack analysis.
    signal input subjectSerialOidOffsetInTbs;

    // SPKI limbs for both leaf and intermediate (witness side; on-chain
    // P256Verify.spkiCommit recomputes the SAME value from calldata bytes).
    signal input leafXLimbs[6];
    signal input leafYLimbs[6];
    signal input intXLimbs[6];
    signal input intYLimbs[6];

    // V5.2: pkX[4] / pkY[4] limb inputs from V5.1 are removed. The on-chain
    // keccak gate operates on the 4 public-signal limbs (bindingPkX/Y Hi/Lo)
    // which are packed directly from `parser.pkBytes[1..65]` via Bits2Num —
    // no separate witness-side limb decomposition needed.

    // V5.1 wallet-bound nullifier secret. Off-circuit derivation:
    //   EOA: walletSecret = HKDF-SHA256(personal_sign(walletPriv, "qkb-personal-secret-v1"
    //                                   // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
    //                                              || subjectSerialPacked.bytes))
    //                       reduced/truncated to fit the BN254 scalar field.
    //   SCW: walletSecret = Argon2id(passphrase, salt="qkb-walletsecret-v1" || walletAddr)
    //                       // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
    //                       same field reduction.
    // Circuit treats it as an opaque field element + applies a 254-bit range check
    // (Num2Bits below) so an adversary witness cannot supply a value ≥ p that
    // wraps to a colliding value mod p with a different on-chain commitment.
    //
    // V5.3 F3 — walletSecret ↔ msgSender binding is INTENTIONALLY
    // CONTRACT-SIDE, not circuit-side.  walletSecret is bound to the
    // holder's identity in-circuit via:
    //   nullifier            = Poseidon₂(walletSecret, ctxFieldHash)        — §6.7
    //   identityCommitment   = Poseidon₂(subjectSerialPacked, walletSecret) — §V5.1
    // But the circuit cannot prove "the prover holds the wallet at
    // msg.sender" because the wallet-pubkey ↔ msg.sender relation
    // requires the contract's storage gate at `identityWallets[fp]`
    // (V5.1 invariant #2 — wallet-uniqueness; reads ALL prior
    // identities for the same fingerprint, requiring on-chain
    // storage that the circuit cannot see).
    //
    // See `docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md`
    // §"Wallet-uniqueness gate location" for the full rationale.
    //
    // Future contributors: do NOT add a circuit-side check on
    // msgSender's relation to walletSecret.  V5.2 dropped msgSender
    // as a public signal entirely (see §6.8 wallet-pk limb packing
    // for the keccak-on-chain construction); a circuit-side
    // walletSecret↔msgSender binding would either be ineffective or
    // break the rotation-mode storage semantics that V5.1 set up.
    signal input walletSecret;

    // V5.1 rotation-mode old-wallet-secret witness (private input). Required when
    // rotationMode == 1 — the user proves knowledge of the OLD wallet's walletSecret
    // by supplying the value that produces the prior commitment (verified by the
    // ForceEqualIfEnabled gate below). Under rotationMode == 0 (register mode) this
    // signal is unconstrained — the witness builder defaults it to `walletSecret`
    // for fixture stability, but the value doesn't matter (its constraint is gated
    // OFF). Per spec §"Rotation-mode constraints" v0.6.
    signal input oldWalletSecret;

    // ===== Body wiring =====
    // Tasks 6.2-6.10 wire the constraints in order:
    //   6.2 — BindingParseV2CoreFast: expose timestamp + policyLeafHash      ← THIS COMMIT
    //   6.3 — 3× Sha256Var (binding, signedAttrs, leafTBS) + Bytes32ToHiLo
    //   6.4 — SignedAttrsParser, messageDigest === bindingHash equality
    //   6.5 — 2× SpkiCommit (leaf + intermediate)
    //   6.6 — X509SubjectSerial + NullifierDerive (Poseidon-domain ctxHash)
    //   6.7 — Sha256Var(ctxBytes) + Bytes32ToHiLo for public ctxHashHi/Lo
    //   6.8 — V5.2 wallet-pk limb packing (Bits2Num → 4 public signals; keccak gate moved on-chain)
    //   6.9 — leafTBS bound to leaf-cert DER consistency
    //   6.10 — final E2E test on real Diia fixture

    // §6.2 — BindingParseV2CoreFast
    // Parses the JCS-canonicalized binding bytes, asserts every required
    // field-key prefix at its witnessed offset, and produces 8 outputs.
    // Two of those outputs are bound to public signals here (timestamp,
    // policyLeafHash); the rest (pkBytes, nonceBytes, ctxBytes, ctxLen,
    // policyIdBytes) are consumed by later wiring (Bits2Num pk-limb packing in §6.8,
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

    // ===== V5.1 wallet-bound nullifier construction (replaces V5 NullifierDerive) =====
    //
    // Three Poseidon₂ outputs share `subjectPack.out` (the existing Poseidon₅ pack of
    // serialLimbs+len) — saves 2 redundant packs vs. computing from scratch each time.
    //
    //   subjectPack.out      = Poseidon₅(subjectSerialLimbs[0..3], subjectSerialLen)  — internal
    //   identityFingerprint  = Poseidon₂(subjectPack.out, FINGERPRINT_DOMAIN)         — public[14]
    //   identityCommitment   = Poseidon₂(subjectPack.out, walletSecret)               — public[15]
    //   nullifier            = Poseidon₂(walletSecret, ctxFieldHash.out)              — public[2]
    //
    // walletSecret is range-checked to 254 bits to prevent a malicious prover from
    // submitting two distinct >p values that reduce to the same field element on-chain
    // (potential equivocation against the contract's identityCommitments mapping).

    component walletSecretBits = Num2Bits(254);
    walletSecretBits.in <== walletSecret;

    // Same range check on the rotation-mode old-wallet-secret witness — prevents
    // a malicious prover from supplying a value ≥ p that wraps mod p to satisfy
    // the rotateOldCommitGate below for an unrelated commitment opening.
    component oldWalletSecretBits = Num2Bits(254);
    oldWalletSecretBits.in <== oldWalletSecret;

    component subjectPack = Poseidon(5);
    for (var i = 0; i < 4; i++) subjectPack.inputs[i] <== subjectSerial.subjectSerialLimbs[i];
    subjectPack.inputs[4] <== subjectSerialValueLength;

    component fpHash = Poseidon(2);
    fpHash.inputs[0] <== subjectPack.out;
    fpHash.inputs[1] <== FINGERPRINT_DOMAIN;
    fpHash.out === identityFingerprint;

    component commitHash = Poseidon(2);
    commitHash.inputs[0] <== subjectPack.out;
    commitHash.inputs[1] <== walletSecret;
    commitHash.out === identityCommitment;

    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== walletSecret;
    nullifierHash.inputs[1] <== ctxFieldHash.out;
    nullifierHash.out === nullifier;

    // ===== Rotation-mode gates =====
    //
    // rotationMode is boolean. Under register (rotationMode == 0), the no-op
    // slot 16 (`rotationOldCommitment`) must equal `identityCommitment` —
    // preventing a register-mode caller from passing arbitrary garbage in
    // that public slot. Under rotate (rotationMode == 1), that constraint
    // releases and the contract takes over by gating
    // `rotationOldCommitment == identityCommitments[fp]` and binding
    // `rotationNewWallet` against tx semantics.
    //
    // V5.2 amendment (2026-05-01): the V5.1 register-mode no-op gate
    // `rotationNewWallet === msgSender` MOVES TO CONTRACT because
    // `msgSender` is no longer a circuit public signal. Contract-side, the
    // 5-gate `register()` body now reconstructs the address from
    // `bindingPkX/Y` limbs and asserts both
    //   address(uint160(uint256(keccak256(uncompressedPk)))) == msg.sender
    //   rotationNewWallet                                    == msg.sender
    // before letting the proof through. See spec §"Construction delta —
    // Contract changes" of `2026-05-01-keccak-on-chain-amendment.md`.

    rotationMode * (rotationMode - 1) === 0;     // boolean range check

    // V5.3 F2 — rotationNewWallet 160-bit range check (defense-in-depth).
    //
    // V5.2 left rotationNewWallet as a free 254-bit field element on
    // the public-signal slot 17.  The contract enforces "fits in
    // 160 bits" via address-cast equality (`uint256(uint160(slot17))
    // == slot17`), so the runtime is safe — but the circuit's own
    // statement of correctness was silent on the bound.  V5.3 adds
    // a Num2Bits(160) at the circuit boundary so the proof
    // ATTESTS to a valid Ethereum-address-shaped value, not just a
    // field element the contract happens to mask.
    //
    // Fires UNCONDITIONALLY (both register and rotate modes).  In
    // register mode the contract will additionally enforce
    // `rotationNewWallet == msg.sender`, also a 160-bit value.
    // In rotate mode the contract enforces `derivedAddr ==
    // identityWallets[fp]`, again 160 bits.  Both modes have
    // 160-bit semantics; range-checking unconditionally is
    // simpler and safer.
    //
    // Cost: ~480 constraints (Num2Bits + 160 parent-level boolean
    // constraints + 1 sum-equality).
    //
    // **circom -O1 optimizer note** (caught during V5.3 T2 cold-compile):
    // both bare `Num2Bits(160).in <== rotationNewWallet` AND
    // `LessThan(161)` against rotationNewWallet leave the constraint
    // count flat, even though the latter reads its output bit.
    // The optimizer prunes the lower-bit constraints inside Num2Bits
    // because they're "unused observable" — the lc1 === in chain is
    // satisfiable by free lower bits.
    //
    // Defeat the prune by re-asserting EACH bit's boolean range at
    // the parent-template level + re-summing them and asserting
    // equality with the public input.  Both checks are duplicates
    // of Num2Bits's internal constraints, but at the parent level
    // they reference parent-scope signals (rotationNewWallet,
    // rotationNewWalletBits.out[i]) and can't be eliminated.
    component rotationNewWalletBits = Num2Bits(160);
    rotationNewWalletBits.in <== rotationNewWallet;
    var rotationBitWeightedSum = 0;
    for (var rnb = 0; rnb < 160; rnb++) {
        // Boolean range check on each bit (parent-level dup of
        // Num2Bits internal — keeps each bit observable).
        rotationNewWalletBits.out[rnb] * (rotationNewWalletBits.out[rnb] - 1) === 0;
        rotationBitWeightedSum += rotationNewWalletBits.out[rnb] * (1 << rnb);
    }
    // Sum equality: bit-decomposition reconstructs the public input.
    // With each bit ∈ {0,1} (asserted above) AND the sum equal to
    // rotationNewWallet, the value is forced to fit in 160 bits.
    rotationBitWeightedSum === rotationNewWallet;

    // Register-mode (rotationMode == 0): rotation slot 16
    // (`rotationOldCommitment`) is no-op, pinned to `identityCommitment` so
    // the public-signal slot can't carry garbage.
    component oldCommitNoOp = ForceEqualIfEnabled();
    oldCommitNoOp.enabled <== 1 - rotationMode;
    oldCommitNoOp.in[0]   <== rotationOldCommitment;
    oldCommitNoOp.in[1]   <== identityCommitment;

    // Rotate-mode (rotationMode == 1) SOUNDNESS: prove ownership of the OLD
    // wallet by opening the prior on-chain commitment. The user must supply
    // `oldWalletSecret` such that:
    //   rotationOldCommitment === Poseidon₂(subjectPack, oldWalletSecret)
    // Without this gate, a rotation proof carries NO binding to the prior
    // wallet — anyone with the cert + the on-chain `identityCommitments[fp]`
    // value could craft a valid proof, defeating the rotation auth model.
    // Per spec v0.6 §"Rotation-mode constraints" + invariant #2 (Wallet-to-
    // identity binding) + codex review pass 3 [P2] (2026-04-30).
    component oldCommitOpen = Poseidon(2);
    oldCommitOpen.inputs[0] <== subjectPack.out;
    oldCommitOpen.inputs[1] <== oldWalletSecret;

    component rotateOldCommitGate = ForceEqualIfEnabled();
    rotateOldCommitGate.enabled <== rotationMode;     // active when mode == 1
    rotateOldCommitGate.in[0]   <== oldCommitOpen.out;
    rotateOldCommitGate.in[1]   <== rotationOldCommitment;

    // V5.2: V5.1's register-mode `newWalletNoOp` gate
    // (`rotationNewWallet === msgSender`) is REMOVED — `msgSender` is no
    // longer a circuit public signal.  The contract enforces both branches:
    //   register: assert rotationNewWallet == msg.sender
    //   rotate:   assert rotationNewWallet == new-wallet-from-tx
    // V5.2 spec §"Construction delta — Contract changes" + contracts-eng
    // v0.4 review.

    // §6.7 — Byte-domain SHA chain over ctxBytes → ctxHashHi / ctxHashLo.
    //
    // Symmetric to the §6.3 pattern (bindingBytes / signedAttrs / leafTBS):
    //   1. Sha256CanonPad asserts ctxPaddedIn is the FIPS-180-4 canonical
    //      padding of (parser.ctxBytes[0..parser.ctxLen]). The parser-output
    //      ctxBytes is extended by zero past index MAX_CTX up to
    //      MAX_CTX_PADDED so a single Sha256CanonPad instance covers any
    //      honest ctxLen ∈ [0, MAX_CTX].
    //   2. Sha256Var(MAX_CTX_PADDED) consumes the validated paddedIn → 256
    //      output bits.
    //   3. Bytes32ToHiLo splits the 32-byte digest into two 128-bit halves
    //      bound to public signals ctxHashHi (index [3]) and ctxHashLo
    //      (index [4]) per V5 spec §0.1.
    //
    // INDEPENDENT of the field-domain ctxHash already wired in §6.6 (used
    // for nullifier derivation): both hashes consume the same parser-output
    // ctxBytes/ctxLen but live in different hash domains (SHA-256 here vs.
    // PoseidonChunkHashVar there) and feed different downstream consumers
    // (public hi/lo signal pair here vs. NullifierDerive's ctxHash input
    // there). No cross-binding constraint is required because tampering
    // with ctxBytes simultaneously breaks BOTH derivations against their
    // respective public-signal commitments (ctxHashHi/Lo here, nullifier
    // there).
    component ctxPad = Sha256CanonPad(MAX_CTX_PADDED);
    for (var i = 0; i < MAX_CTX; i++) ctxPad.data[i] <== parser.ctxBytes[i];
    for (var i = MAX_CTX; i < MAX_CTX_PADDED; i++) ctxPad.data[i] <== 0;
    for (var i = 0; i < MAX_CTX_PADDED; i++) ctxPad.paddedIn[i] <== ctxPaddedIn[i];
    ctxPad.dataLen   <== parser.ctxLen;
    ctxPad.paddedLen <== ctxPaddedLen;

    component hashCtx = Sha256Var(MAX_CTX_PADDED);
    for (var i = 0; i < MAX_CTX_PADDED; i++) hashCtx.paddedIn[i] <== ctxPaddedIn[i];
    hashCtx.paddedLen <== ctxPaddedLen;

    signal ctxDigestBytes[32];
    for (var i = 0; i < 32; i++) {
        var acc = 0;
        for (var b = 0; b < 8; b++) acc = acc * 2 + hashCtx.out[i * 8 + b];
        ctxDigestBytes[i] <== acc;
    }
    component ctxHiLo = Bytes32ToHiLo();
    for (var i = 0; i < 32; i++) ctxHiLo.bytes[i] <== ctxDigestBytes[i];
    ctxHiLo.hi === ctxHashHi;
    ctxHiLo.lo === ctxHashLo;

    // §6.9 — leafTbs ↔ leafCert byte-consistency.
    //
    // Soundness goal: pin the subject-serial bytes that NullifierDerive
    // consumes to the intermediate-signed TBSCertificate. Without this
    // gate, an attacker could pair a real Diia leafTbs (which hashes to
    // a real-cert leafTbsHash and verifies against intSpki on chain)
    // with a forged leafCertBytes that contains a DIFFERENT subject
    // serial at subjectSerialValueOffset — deriving an attacker-chosen
    // nullifier from a victim's ECDSA chain. That breaks per-person-per
    // -ctx Sybil resistance.
    //
    // Bridge: assert that the MAX_SERIAL=32 bytes X509SubjectSerial reads
    // from leafCertBytes at subjectSerialValueOffset are byte-identical
    // to the leafTbs bytes at subjectSerialValueOffsetInTbs (witnessed
    // independently). leafTbsBytes is pinned to a real cert via the §6.3
    // SHA chain → leafTbsHash → on-chain intSig P256Verify, so any byte
    // in leafTbsBytes is forced to match the genuine cert's TBS at that
    // offset. Cross-checking the 32-byte serial window therefore forces
    // leafCertBytes to carry the genuine subject serial — a forged
    // leafCertBytes whose bytes elsewhere differ from the real cert is
    // still acceptable, but the serial extraction is locked.
    //
    // Cost model: 32 × Multiplexer(1, MAX_LEAF_TBS) for the leafTbs side
    // (~33K constraints); leafCert side reuses subjectSerial.rawBytes
    // (X509SubjectSerial's pre-mask Multiplexer outputs, exposed 2026-04-30
    // for this gate). Total ~33-50K — well inside the spec's 100-300K
    // budget line item for "leafTbs ↔ leafCert byte-consistency".
    var MAX_SERIAL = 32;

    // Range pin: the cross-checked window must lie inside leafTbs.
    component endLeqTbs = LessEqThan(16);
    endLeqTbs.in[0] <== subjectSerialValueOffsetInTbs + subjectSerialValueLength;
    endLeqTbs.in[1] <== leafTbsLength;
    endLeqTbs.out === 1;

    component leafTbsByte[MAX_SERIAL];
    component activeMask69[MAX_SERIAL];
    for (var i = 0; i < MAX_SERIAL; i++) {
        leafTbsByte[i] = Multiplexer(1, MAX_LEAF_TBS);
        for (var j = 0; j < MAX_LEAF_TBS; j++) {
            leafTbsByte[i].inp[j][0] <== leafTbsBytes[j];
        }
        leafTbsByte[i].sel <== subjectSerialValueOffsetInTbs + i;

        activeMask69[i] = LessThan(8);
        activeMask69[i].in[0] <== i;
        activeMask69[i].in[1] <== subjectSerialValueLength;

        // Compare ONLY under active mask (positions ≥ length are
        // unconstrained — the X509SubjectSerial template masks those to
        // zero before packing into limbs anyway).
        activeMask69[i].out * (leafTbsByte[i].out[0] - subjectSerial.rawBytes[i]) === 0;
    }

    // §6.9b — V5.3 F1 — OID-anchor for subject-serial offset.
    //
    // The §6.9 gate above pins the 32 bytes at
    // subjectSerialValueOffsetInTbs (in leafTbs) to the same bytes at
    // subjectSerialValueOffset (in leafCertBytes), but BOTH offsets
    // were witness-supplied — nothing constrained them to point at
    // an actual `subject.serialNumber` attribute.  A malicious prover
    // could pick any 32-byte window in the signed TBS that happened
    // to look serial-number-shaped (length 1-32, all bytes 0-255 —
    // vacuous), combine with rotateWallet's slot-clear, and mint
    // multiple identities from one cert (V5.2 spec §F1).
    //
    // V5.3 closes this by anchoring the value-offset to the actual
    // ASN.1 frame at subjectSerialOidOffsetInTbs:
    //   leafTbs[oid+0..oid+4] === 06 03 55 04 05    (DER OID 2.5.4.5)
    //   leafTbs[oid+5]        ∈ {0x13 PrintableString, 0x0c UTF8String}
    //   leafTbs[oid+6]        === subjectSerialValueLength
    //   subjectSerialValueOffsetInTbs === subjectSerialOidOffsetInTbs + 7
    //
    // After these, the value-offset is fully determined by the
    // OID-offset, and the OID-offset must point at a real
    // `06 03 55 04 05 <13|0c> NN` attribute frame.  QTSP-issued
    // production certs have ONE such attribute per cert (per X.520
    // + ETSI EN 319 412-1 namespace conventions), so the prover's
    // freedom collapses to "the actual subject.serialNumber."
    //
    // The stronger F1.4 variant (subject-DN bounds) is deferred to
    // V5.4 — see V5.3 spec §F1.5 for the cost-benefit analysis.
    //
    // Cost: 7 × Multiplexer(1, MAX_LEAF_TBS=1408) + IsEqual sum +
    // byte-eq + offset-eq.  Measured V5.3 minimal landed at +19.9K
    // constraints over V5.2 (vs spec's ~10K projection — circomlib
    // Multiplexer's per-mux cost is ~2.8K not 1.4K linear; spec
    // estimate was off by 2x but the cap is still met with 7.1%
    // headroom).

    // Range pin: the OID frame must lie inside leafTbs.  The 7 bytes
    // we read are at offset OID, OID+1, …, OID+6 — the leftmost is
    // OID and the rightmost is OID+6, so we need
    // OID + 6 < leafTbsLength, i.e. OID + 7 <= leafTbsLength.
    component oidEndLeqTbs = LessEqThan(16);
    oidEndLeqTbs.in[0] <== subjectSerialOidOffsetInTbs + 7;
    oidEndLeqTbs.in[1] <== leafTbsLength;
    oidEndLeqTbs.out === 1;

    var EXPECTED_OID[5] = [0x06, 0x03, 0x55, 0x04, 0x05];

    component oidByte[5];
    for (var oi = 0; oi < 5; oi++) {
        oidByte[oi] = Multiplexer(1, MAX_LEAF_TBS);
        for (var oj = 0; oj < MAX_LEAF_TBS; oj++) {
            oidByte[oi].inp[oj][0] <== leafTbsBytes[oj];
        }
        oidByte[oi].sel <== subjectSerialOidOffsetInTbs + oi;
        oidByte[oi].out[0] === EXPECTED_OID[oi];
    }

    // String-tag: PrintableString (0x13) OR UTF8String (0x0c).  Sum
    // of two IsEqual outputs must be exactly 1 — exactly one tag
    // matches.  IsEqual returns 0/1, sum constraint forces XOR.
    component stringTagByte = Multiplexer(1, MAX_LEAF_TBS);
    for (var sj = 0; sj < MAX_LEAF_TBS; sj++) {
        stringTagByte.inp[sj][0] <== leafTbsBytes[sj];
    }
    stringTagByte.sel <== subjectSerialOidOffsetInTbs + 5;
    component isPrintable = IsEqual();
    isPrintable.in[0] <== stringTagByte.out[0];
    isPrintable.in[1] <== 0x13;
    component isUtf8 = IsEqual();
    isUtf8.in[0] <== stringTagByte.out[0];
    isUtf8.in[1] <== 0x0c;
    isPrintable.out + isUtf8.out === 1;

    // Length byte equals subjectSerialValueLength (which X509SubjectSerial
    // already range-checks to [1, 32]).
    component oidLenByte = Multiplexer(1, MAX_LEAF_TBS);
    for (var lj = 0; lj < MAX_LEAF_TBS; lj++) {
        oidLenByte.inp[lj][0] <== leafTbsBytes[lj];
    }
    oidLenByte.sel <== subjectSerialOidOffsetInTbs + 6;
    oidLenByte.out[0] === subjectSerialValueLength;

    // Value-offset is OID-offset + 7 (5 OID bytes + 1 string-tag + 1 length).
    subjectSerialValueOffsetInTbs === subjectSerialOidOffsetInTbs + 7;

    // §6.8 — V5.2 wallet-pk limb packing for on-chain keccak gate.
    //
    // V5.1 ran Secp256k1PkMatch (~50K) + Secp256k1AddressDerive (~150K
    // Keccak_256_bytes(64)) IN-CIRCUIT to derive msgSender from the
    // binding's claimed wallet pk.  V5.2 moves that keccak gate to the
    // contract layer (`address(uint160(uint256(keccak256(uncompressedPk))))
    // == msg.sender`), unlocking cross-chain portability of the Groth16
    // zkey and saving ~200K constraints.
    //
    // What the circuit must still do:
    //   (a) Assert the binding's pk has the SEC1-uncompressed prefix
    //       (`parser.pkBytes[0] === 4`) — cheap (1 constraint), retained
    //       so the proof's attestation about the binding-pk ENCODING
    //       remains intact (codex pass 1 [P2] caught this in spec v0.1).
    //   (b) Pack `parser.pkBytes[1..33]` and `parser.pkBytes[33..65]` —
    //       the 64 bytes of the uncompressed (X || Y) pubkey — into 4 ×
    //       128-bit field elements (bindingPkXHi/Lo, bindingPkYHi/Lo).
    //       Each 16-byte slice fits comfortably in BN254's ~254-bit
    //       field. Big-endian packing matches Ethereum's natural pk
    //       serialization.
    //   (c) Equality-bind those packings to the 4 V5.2 public-signal
    //       slots (18-21), which the contract reads off the
    //       Groth16 verifier output.
    //
    // Cost: ~3 (SEC1 prefix) + 4 × ~128 (Bits2Num packing per limb) ≈
    // ~515 constraints. Net delta from V5.1 §6.8: -200K + 515 ≈ -199.5K.
    // Per spec §"Construction delta — Circuit changes" + §"Cost
    // estimate" of `2026-05-01-keccak-on-chain-amendment.md`.

    // (a) SEC1 uncompressed-prefix assertion — single equality.
    parser.pkBytes[0] === 4;

    // (b) Pack the 64 raw uncompressed-pk bytes into 4 × 128-bit field
    //     elements via Bits2Num. Each byte at parser.pkBytes[i+1] is
    //     already constrained to [0, 255] by BindingParseV2CoreFast.
    //     Big-endian:
    //       pkXHi = sum_{j=0..15}  parser.pkBytes[1+j]   << ((15-j)*8)
    //       pkXLo = sum_{j=0..15}  parser.pkBytes[17+j]  << ((15-j)*8)
    //       pkYHi = sum_{j=0..15}  parser.pkBytes[33+j]  << ((15-j)*8)
    //       pkYLo = sum_{j=0..15}  parser.pkBytes[49+j]  << ((15-j)*8)
    var bindingPkXHiAcc = 0;
    var bindingPkXLoAcc = 0;
    var bindingPkYHiAcc = 0;
    var bindingPkYLoAcc = 0;
    for (var j = 0; j < 16; j++) {
        bindingPkXHiAcc += parser.pkBytes[1  + j] * (256 ** (15 - j));
        bindingPkXLoAcc += parser.pkBytes[17 + j] * (256 ** (15 - j));
        bindingPkYHiAcc += parser.pkBytes[33 + j] * (256 ** (15 - j));
        bindingPkYLoAcc += parser.pkBytes[49 + j] * (256 ** (15 - j));
    }
    bindingPkXHi === bindingPkXHiAcc;
    bindingPkXLo === bindingPkXLoAcc;
    bindingPkYHi === bindingPkYHiAcc;
    bindingPkYLo === bindingPkYLoAcc;

    // After §6.8 (V5.2), every public signal is bound to a
    // circuit-computed value:
    //   timestamp                 (§6.2) ← parser.tsValue
    //   nullifier                 (§6.6) ← Poseidon₂(walletSecret, ctxHashField)
    //   ctxHashHi, ctxHashLo      (§6.7) ← Bytes32ToHiLo(sha256(parser.ctxBytes))
    //   bindingHashHi, bindingHashLo (§6.3) ← Bytes32ToHiLo(sha256(bindingBytes))
    //   signedAttrsHashHi, signedAttrsHashLo (§6.3) ← Bytes32ToHiLo(sha256(signedAttrsBytes))
    //   leafTbsHashHi, leafTbsHashLo (§6.3) ← Bytes32ToHiLo(sha256(leafTbsBytes))
    //   policyLeafHash            (§6.2) ← parser.policyLeafHash
    //   leafSpkiCommit            (§6.5) ← SpkiCommit(leafXLimbs, leafYLimbs)
    //   intSpkiCommit             (§6.5) ← SpkiCommit(intXLimbs, intYLimbs)
    //   identityFingerprint       (V5.1) ← Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)
    //   identityCommitment        (V5.1) ← Poseidon₂(subjectSerialPacked, walletSecret)
    //   rotationMode              (V5.1) ← witness, boolean range-checked
    //   rotationOldCommitment     (V5.1) ← register: == identityCommitment
    //                                      rotate:   == Poseidon₂(subjectPack, oldWalletSecret)
    //   rotationNewWallet         (V5.1) ← witness; CONTRACT-enforced in V5.2
    //   bindingPkXHi/Lo, PkYHi/Lo (V5.2) ← Bits2Num packing of parser.pkBytes[1..65]
    //
    // (§6.9 closes the leafTbs ↔ leafCert byte-equality gate as an
    // internal-soundness invariant — doesn't bind a public signal.)
}

component main { public [
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
    intSpkiCommit,
    identityFingerprint,
    identityCommitment,
    rotationMode,
    rotationOldCommitment,
    rotationNewWallet,
    bindingPkXHi,
    bindingPkXLo,
    bindingPkYHi,
    bindingPkYLo
] } = ZkqesPresentationV5();
