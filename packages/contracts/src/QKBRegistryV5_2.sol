// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {IQKBRegistry} from "./IdentityEscrowNFT.sol";
import {Poseidon} from "./libs/Poseidon.sol";
import {PoseidonBytecode} from "./libs/PoseidonBytecode.sol";
import {P256Verify} from "./libs/P256Verify.sol";
import {PoseidonMerkle} from "./libs/PoseidonMerkle.sol";

/// @notice The V5.2 Groth16 verifier interface — exposed so the registry can
///         bind to the placeholder, the V5.2 stub, OR the post-Phase-B real
///         ceremony output without a source change. snarkjs auto-generated
///         verifiers match this signature when the circuit emits 22 public
///         signals (V5.2 layout per amendment §"Public-signal layout").
///
///         V5.2 differs from V5.1's verifier interface (uint[19]) by:
///           - Dropping slot [0] msgSender (no longer circuit-emitted; the
///             contract derives it on-chain via keccak256 over the new
///             bindingPkX/Y limb pair). V5.1 slots 1..18 shift down to V5.2
///             slots 0..17.
///           - Appending 4 new slots [18..21]: bindingPkXHi, bindingPkXLo,
///             bindingPkYHi, bindingPkYLo. Each 128-bit Bits2Num-packed from
///             parser.pkBytes[1..65] — the binding's secp256k1 wallet pk
///             (sans the SEC1 0x04 prefix), big-endian convention.
interface IGroth16VerifierV5_2 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[22] calldata input
    ) external view returns (bool);
}

/// @title  QKBRegistryV5_2 — V5.2 binding registry with on-chain keccak gate.
/// @notice Implements `IQKBRegistry` (ABI-stable across V4↔V5↔V5.1↔V5.2;
///         downstream SDK consumers + IdentityEscrowNFT work unchanged).
///         V5.2 moves the wallet-pubkey-to-msg.sender keccak gate from the
///         circuit (V5.1 §6.8 in-circuit `Secp256k1AddressDerive`) to the
///         contract layer. The circuit now emits the wallet pubkey as 4
///         × 128-bit limbs (bindingPkXHi/Lo, bindingPkYHi/Lo); the contract
///         reconstructs the 64-byte uncompressed pk and runs keccak256 to
///         derive the msg.sender address natively.
///
///         Wins: -100K to -200K constraints (pot22 fits, vs V5.1's pot23);
///         Groth16 zkey portability across BN254-Groth16 chains (the keccak
///         step is host-native rather than baked into the circuit). End-to-
///         end deployment portability is bounded by the V5 architecture's
///         OTHER chain dependencies — `register()` still requires (a) a
///         P-256 ECDSA precompile (RIP-7212 / EIP-7951) for leaf +
///         intermediate cert verification, currently shipped on Base + OP
///         per V5/V5.1 deployment posture, and (b) the host's caller-auth
///         model to be EVM-style (`address = keccak(secp256k1_pubkey)[12:32]`)
///         so the on-chain `derivedAddr == msg.sender` check makes sense.
///         Non-EVM caller-auth models (Solana ed25519, Cosmos bech32,
///         Aptos/Sui Move) need a per-chain auth-shim; those are out of
///         V5.2 scope.
///
///         The 5-gate `register()` body adds ONE new gate (Gate 2a-prime,
///         the on-chain keccak-derive + sender bind) and folds V5.1's
///         `BadSender` slot-[0] check into it. The register-mode rotation
///         no-op gate `rotationNewWallet === msgSender` (V5.1 in-circuit
///         ForceEqualIfEnabled) also moves to the contract; the paired
///         `rotationOldCommitment === identityCommitment` no-op stays
///         in-circuit because it doesn't reference msgSender.
///
/// @dev    Constructor side-effects (unchanged from V5.1):
///           - CREATE-deploy PoseidonT3 (~9.8K bytes) and PoseidonT7
///             (~23.6K bytes); cached as immutables for cheap reads.
///           - Set admin + initial trustedListRoot + initial policyRoot.
///         The contract is NOT upgradeable — V5.1 → V5.2 is a fresh deploy
///         with a holder re-registration flow.
contract QKBRegistryV5_2 is IQKBRegistry {
    /* ---------- immutables ---------- */

    /// Groth16 verifier (stub now, real ceremony output post-Phase-B).
    IGroth16VerifierV5_2 public immutable groth16Verifier;

    /// Deployed Poseidon contract addresses, used by P256Verify.spkiCommit
    /// and PoseidonMerkle.verify staticcalls inside register().
    address public immutable poseidonT3;
    address public immutable poseidonT7;

    /* ---------- state ---------- */

    address public admin;

    /// Merkle root of the qualified-trust-list. Leaves = `SpkiCommit(intSpki)`
    /// per V5 spec §0.5. Rotated by admin when flattener-eng emits a fresh
    /// snapshot from the country's TSL.
    bytes32 public override trustedListRoot;

    /// Merkle root of the qualified-policy-list. Leaves = `policyLeafHash`
    /// (already field-domain Poseidon commitments to the QKB binding).
    bytes32 public policyRoot;

    /// Maximum age of a binding before it's considered stale. The proof
    /// commits to a `timestamp` public signal (signal[1]); register() rejects
    /// proofs where (block.timestamp - timestamp) > MAX_BINDING_AGE.
    /// 1 hour is the operational window we expect between signedAttrs
    /// generation in the QES signing flow and on-chain submission.
    uint256 public constant MAX_BINDING_AGE = 1 hours;

    /// Per-holder nullifier — non-zero iff the holder has registered.
    /// Drives both `isVerified()` (boolean) and `nullifierOf()` (raw value).
    /// V5.1 invariant 4: write-once on first-claim only — `register()`
    /// repeat-claim path (same wallet, same identity, fresh ctx) does NOT
    /// overwrite. This preserves the bytes32 type + non-zero-iff-registered
    /// semantics that `IdentityEscrowNFT` and `IQKBRegistry.isVerified()`
    /// consumers rely on.
    mapping(address => bytes32) public override nullifierOf;

    /* ---------- V5.1 wallet-bound identity escrow (per orchestration §1.4) --- */

    /// fingerprint → identity commitment. Written once per identity on the
    /// first-claim register; subsequent claims must match. The fingerprint is
    /// `Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)` (issuer-blind
    /// person identifier) and the commitment is
    /// `Poseidon₂(subjectSerialPacked, walletSecret)` (wallet-bound escrow).
    mapping(bytes32 => bytes32) public identityCommitments;

    /// fingerprint → bound wallet. The wallet that holds the identity is
    /// the only one allowed to register against new ctxs (repeat-claim) or
    /// initiate a `rotateWallet()`. Updated atomically by `rotateWallet()`.
    mapping(bytes32 => address) public identityWallets;

    /// fingerprint → ctxKey → used. Per-(identity, ctx) anti-Sybil gate.
    /// Monotonic — once true, never cleared. Carries forward across
    /// `rotateWallet()` (V5.1 invariant 3); any future V6 reset path MUST
    /// preserve these flags.
    mapping(bytes32 => mapping(bytes32 => bool)) public usedCtx;

    /* ---------- events ---------- */

    event Registered(address indexed holder, bytes32 indexed nullifier, uint256 timestamp);
    event TrustedListRootRotated(bytes32 indexed previous, bytes32 indexed current, address admin);
    event PolicyRootRotated(bytes32 indexed previous, bytes32 indexed current, address admin);
    event AdminTransferred(address indexed previous, address indexed current);

    /// @dev V5.1 wallet rotation event. Emitted by `rotateWallet()` after the
    ///      identity binding is moved from `oldWallet` to `newWallet`.
    ///      Indexed fields: fingerprint (primary lookup key), oldWallet,
    ///      newWallet (both watched by indexers / wallet-rotation UX).
    ///      `usedCtx[fingerprint][*]` flags persist across rotation per
    ///      V5.1 invariant 3 — anti-Sybil unaffected.
    event WalletRotated(
        bytes32 indexed fingerprint,
        address indexed oldWallet,
        address indexed newWallet,
        bytes32 newCommitment
    );

    /* ---------- errors ---------- */

    error OnlyAdmin();
    error ZeroAddress();
    error PoseidonDeployFailed();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert OnlyAdmin();
        _;
    }

    /* ---------- constructor ---------- */

    constructor(
        IGroth16VerifierV5_2 _verifier,
        address _admin,
        bytes32 _initialTrustedListRoot,
        bytes32 _initialPolicyRoot
    ) {
        if (address(_verifier) == address(0)) revert ZeroAddress();
        if (_admin == address(0)) revert ZeroAddress();
        groth16Verifier = _verifier;
        admin = _admin;
        trustedListRoot = _initialTrustedListRoot;
        policyRoot = _initialPolicyRoot;

        // CREATE-deploy the Poseidon T3 + T7 contracts. Their bytecode is
        // emitted by `script/generate-poseidon-bytecode.ts` and pinned at
        // `src/libs/PoseidonBytecode.sol` (drift-asserted by
        // `script/check-poseidon-reproducibility.ts`).
        poseidonT3 = Poseidon.deploy(PoseidonBytecode.t3Initcode());
        poseidonT7 = Poseidon.deploy(PoseidonBytecode.t7Initcode());
    }

    /* ---------- IQKBRegistry view fns ---------- */

    function isVerified(address holder) external view override returns (bool) {
        return nullifierOf[holder] != bytes32(0);
    }

    /// @dev `nullifierOf` and `trustedListRoot` use the auto-generated
    ///       getters (declared above with `public override`).

    /* ---------- admin ---------- */

    function setTrustedListRoot(bytes32 newRoot) external onlyAdmin {
        emit TrustedListRootRotated(trustedListRoot, newRoot, msg.sender);
        trustedListRoot = newRoot;
    }

    function setPolicyRoot(bytes32 newRoot) external onlyAdmin {
        emit PolicyRootRotated(policyRoot, newRoot, msg.sender);
        policyRoot = newRoot;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    /* ---------- register() — frozen ABI per orchestration §0.3 ---------- */

    /// 22 BN254 field-element public signals — order is FROZEN per V5.2
    /// amendment §"Public-signal layout". Slots [0..16] preserve the V5.1
    /// semantics for slots [1..17] (V5.1's slot [0] msgSender DROPPED;
    /// remainder shift down by 1). Slots [17..21] are the rotation-circuit
    /// + V5.2 keccak-on-chain additions; slot [17] (rotationNewWallet)
    /// becomes the register-mode no-op gate the contract enforces (since
    /// the V5.1 in-circuit `rotationNewWallet === msgSender` constraint
    /// can no longer reference an absent msgSender slot).
    struct PublicSignals {
        uint256 timestamp;            // [0]   V5.1 slot 1; ≤ 2^64
        uint256 nullifier;            // [1]   V5.1 slot 2; Poseidon₂(walletSecret, ctxHash)
        uint256 ctxHashHi;            // [2]   V5.1 slot 3
        uint256 ctxHashLo;            // [3]   V5.1 slot 4
        uint256 bindingHashHi;        // [4]   V5.1 slot 5
        uint256 bindingHashLo;        // [5]   V5.1 slot 6
        uint256 signedAttrsHashHi;    // [6]   V5.1 slot 7
        uint256 signedAttrsHashLo;    // [7]   V5.1 slot 8
        uint256 leafTbsHashHi;        // [8]   V5.1 slot 9
        uint256 leafTbsHashLo;        // [9]   V5.1 slot 10
        uint256 policyLeafHash;       // [10]  V5.1 slot 11
        uint256 leafSpkiCommit;       // [11]  V5.1 slot 12
        uint256 intSpkiCommit;        // [12]  V5.1 slot 13
        uint256 identityFingerprint;  // [13]  V5.1 slot 14; Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)
        uint256 identityCommitment;   // [14]  V5.1 slot 15; Poseidon₂(subjectSerialPacked, walletSecret)
        uint256 rotationMode;         // [15]  V5.1 slot 16; 0 = register, 1 = rotateWallet
        uint256 rotationOldCommitment;// [16]  V5.1 slot 17; register-mode no-op (== identityCommitment, gated in-circuit); rotate-mode prior commitment
        uint256 rotationNewWallet;    // [17]  V5.1 slot 18; register-mode no-op (== uint160(msg.sender), gated ON-CHAIN under V5.2 — see WrongRegisterModeNoOp); rotate-mode new wallet
        // V5.2 keccak-on-chain amendment — bindingPk* limbs replace V5.1's
        // in-circuit `Secp256k1AddressDerive` (msgSender = keccak(parser.pkBytes)
        // gate that fired at V5.1 §6.8). Each is Bits2Num(128)-packed from
        // 16 bytes of parser.pkBytes (the binding's secp256k1 wallet pk
        // sans the SEC1 0x04 prefix), big-endian convention:
        //   pkXHi = sum_{i=0..15}  parser.pkBytes[i+1]  * 256^(15-i)
        //   pkXLo = sum_{i=16..31} parser.pkBytes[i+1]  * 256^(31-i)
        //   pkYHi = sum_{i=0..15}  parser.pkBytes[i+33] * 256^(15-i)
        //   pkYLo = sum_{i=16..31} parser.pkBytes[i+33] * 256^(31-i)
        uint256 bindingPkXHi;         // [18] V5.2 NEW
        uint256 bindingPkXLo;         // [19] V5.2 NEW
        uint256 bindingPkYHi;         // [20] V5.2 NEW
        uint256 bindingPkYLo;         // [21] V5.2 NEW
    }

    struct Groth16Proof {
        uint256[2]    a;
        uint256[2][2] b;
        uint256[2]    c;
    }

    /* ---------- register() errors (one per gate, named for diagnostics) ---------- */

    error BadProof();        // Gate 1:  Groth16 verifier returned false.
    error BadSignedAttrsHi();// Gate 2a: sha256(signedAttrs) hi-half ≠ sig.signedAttrsHashHi.
    error BadSignedAttrsLo();// Gate 2a: sha256(signedAttrs) lo-half ≠ sig.signedAttrsHashLo.
    error BadLeafSpki();     // Gate 2a: SpkiCommit(leafSpki) ≠ sig.leafSpkiCommit.
    error BadIntSpki();      // Gate 2a: SpkiCommit(intSpki) ≠ sig.intSpkiCommit.
    error BadLeafSig();      // Gate 2b: leaf P-256 over sha256(signedAttrs) failed.
    error BadIntSig();       // Gate 2b: intermediate P-256 over leafTbsHash failed.
    error BadTrustList();    // Gate 3:  intSpkiCommit ∉ trustedListRoot Merkle tree.
    error BadPolicy();       // Gate 4:  policyLeafHash ∉ policyRoot Merkle tree.
    error StaleBinding();    // Gate 5:  block.timestamp - sig.timestamp > MAX_BINDING_AGE.
    error FutureBinding();   // Gate 5:  sig.timestamp > block.timestamp (clock-skew defensive).
    error AlreadyRegistered();// Gate 5: this wallet already has a nullifier on file.

    /* ---------- V5.2 errors (replace V5.1 BadSender; add register-mode no-op) ---------- */

    /// @dev V5.2 Gate 2a-prime: keccak-derived address from bindingPkX/Y
    ///      limbs ≠ msg.sender. Folds in V5.1's `BadSender` semantics —
    ///      V5.1 checked `sig.msgSender == uint160(msg.sender)` against a
    ///      circuit-emitted msgSender; V5.2 derives msgSender on-chain via
    ///      keccak256 over the 64-byte uncompressed pk reconstructed from
    ///      bindingPkX/Y limbs.
    error WalletDerivationMismatch();

    /// @dev V5.2 register-mode rotation no-op gate. Replaces V5.1's circuit-
    ///      side `ForceEqualIfEnabled` constraint
    ///      `(1 - rotationMode) * (rotationNewWallet - msgSender) === 0`,
    ///      which can no longer reference msgSender (now contract-derived).
    ///      Under register mode (rotationMode == 0), `sig.rotationNewWallet`
    ///      MUST equal `uint160(msg.sender)`. The paired
    ///      `rotationOldCommitment === identityCommitment` no-op stays
    ///      in-circuit (doesn't reference msgSender, so V5.1 ForceEqualIfEnabled
    ///      survives unmodified).
    error WrongRegisterModeNoOp();

    /// @dev V5.2 limb range check: reverts if any of bindingPkXHi/Lo,
    ///      bindingPkYHi/Lo exceeds 2^128 - 1. Defense-in-depth — the
    ///      circuit's Bits2Num(128) constraint should ensure this; the
    ///      contract gate surfaces a hypothetical circuit bug as a
    ///      diagnosable revert instead of silent truncation.
    error BindingPkLimbOutOfRange();
    // V5.1: NullifierUsed dropped — anti-Sybil migrated to usedCtx[fp][ctxKey].
    // The reverse `registrantOf[nullifier] → wallet` mapping was redundant
    // once the nullifier became per-(walletSecret, ctxHash) and the per-
    // (identity, ctx) uniqueness moved into the new usedCtx gate.

    /* ---------- V5.1 errors ---------- */
    error WrongMode();             // Gate 6: rotationMode != 0 in register() entry point.
    error CommitmentMismatch();    // Gate 6: repeat-claim commitment ≠ stored commitment.
    error WalletNotBound();        // Gate 6: repeat-claim msg.sender ≠ identityWallets[fp] (stale-bind).
    error CtxAlreadyUsed();        // Gate 7: usedCtx[fp][ctxKey] already true.
    error UnknownIdentity();       // rotateWallet: identityCommitments[fp] == 0 (no prior register).
    error InvalidNewWallet();      // rotateWallet: newWallet == 0 || == oldWallet || != msg.sender.
    error InvalidRotationAuth();   // rotateWallet: ECDSA recovery from oldWalletAuthSig ≠ identityWallets[fp].
    // V5.1 register-mode no-op invariants: the proof's slots [17]/[18] under
    // rotationMode==0 must equal identityCommitment / msgSender respectively.
    // The fold-in circuit's ForceEqualIfEnabled gates already enforce these
    // (per orchestration §1.1 + spec §"Rotation circuit ceremony") — contract
    // does not duplicate the check. If circuits-eng's stub regression catches
    // a circuit-side miss, we add explicit on-chain gates here.

    /// @notice 6-gate registration (V5.2 vs V5.1's 5+rotation-no-op):
    ///   Gate 0:        mode gate (rotationMode == 0).
    ///   Gate 1:        Groth16 verify.
    ///   Gate 2a-prime: V5.2 NEW — keccak-derive msg.sender from
    ///                  bindingPkX/Y limbs + sender bind + register-mode
    ///                  rotation-no-op gate. Replaces V5.1 BadSender +
    ///                  V5.1 in-circuit ForceEqualIfEnabled.
    ///   Gate 2a:       bind public-input commits to calldata
    ///                  (sha256/spkiCommit checks unchanged from V5.1).
    ///   Gate 2b:       2× P256Verify (leaf + intermediate).
    ///   Gate 3:        trust-list Merkle proof.
    ///   Gate 4:        policy-list Merkle proof.
    ///   Gate 5:        timing + replay (V5.1's `BadSender` step is gone —
    ///                  folded into Gate 2a-prime).
    ///   Gate 6/7:      identity escrow + per-(identity, ctx) anti-Sybil
    ///                  (V5.1 unchanged — write-out path).
    /// @dev    Calldata layout per orchestration §0.3 (unchanged from V5.1):
    ///         (proof, sig, leafSpki, intSpki, signedAttrs, leafSig, intSig,
    ///          trustMerklePath, trustMerklePathBits,
    ///          policyMerklePath, policyMerklePathBits)
    ///         The `sig` struct's PublicSignals tuple shape changed (22
    ///         fields vs V5.1's 19) — see PublicSignals docstring.
    function register(
        Groth16Proof   calldata proof,
        PublicSignals  calldata sig,
        bytes          calldata leafSpki,
        bytes          calldata intSpki,
        bytes          calldata signedAttrs,
        bytes32[2]     calldata leafSig,
        bytes32[2]     calldata intSig,
        bytes32[16]    calldata trustMerklePath,
        uint256                 trustMerklePathBits,
        bytes32[16]    calldata policyMerklePath,
        uint256                 policyMerklePathBits
    ) external {
        // No deferred params remaining; all 11 calldata fields are live.

        /* ===== Gate 0 (V5.1): mode gate ===== */
        // Reject rotation-mode proofs at the register() entry point.
        // rotateWallet() is the dual entry point and enforces mode == 1.
        // The fold-in circuit emits the mode bit at slot [15] (V5.2 layout —
        // V5.1 was slot [16] before the msgSender drop).
        if (sig.rotationMode != 0) revert WrongMode();

        /* ===== Gate 2a-prime (V5.2 NEW): keccak-derive msg.sender ===== */
        // Replaces V5.1's `Secp256k1AddressDerive` in-circuit keccak gate +
        // `BadSender` contract check. The contract reconstructs the 64-byte
        // uncompressed secp256k1 wallet pubkey from the 4 × 128-bit limbs
        // bindingPkXHi/Lo, bindingPkYHi/Lo (Bits2Num-packed in-circuit from
        // parser.pkBytes[1..65], big-endian convention) and runs keccak256
        // to derive an Ethereum-style address. The caller MUST be that
        // address — same security property as V5.1's slot-[0] msgSender +
        // sender-bind, just with the keccak step moved on-chain.
        //
        // Yul-friendly: the pure-Solidity Option I path here is on the
        // order of a few hundred gas (precise number deferred to T8
        // forge snapshot baseline); an `assembly("memory-safe")` Option
        // II variant would save a small amount more (see contract review
        // §2.1). Sticking with Option I for clarity.
        address derivedAddr = _deriveAddrFromBindingLimbs(sig);
        if (derivedAddr != msg.sender) revert WalletDerivationMismatch();

        // V5.2 register-mode rotation no-op gate. V5.1 enforced this
        // in-circuit via ForceEqualIfEnabled(`(1 - rotationMode) *
        // (rotationNewWallet - msgSender) === 0`). With msgSender no
        // longer in the public-signal vector, the constraint cannot
        // reference it; it moves to the contract. The paired
        // `rotationOldCommitment === identityCommitment` no-op stays
        // in-circuit (no msgSender dependency).
        if (sig.rotationNewWallet != uint256(uint160(msg.sender))) {
            revert WrongRegisterModeNoOp();
        }

        /* ===== Gate 1: Groth16 verify ===== */
        // Pack the 22-signal public-input array. Order MUST match V5.2
        // amendment §"Public-signal layout" exactly; the auto-generated
        // snarkjs verifier consumes `uint[22]`.
        uint256[22] memory input = _packPublicSignalsV52(sig);
        if (!groth16Verifier.verifyProof(proof.a, proof.b, proof.c, input)) {
            revert BadProof();
        }

        /* ===== Gate 2a (§6.3): bind public-input commits to calldata ===== */
        // Hi/Lo split convention: hi = top 16 bytes of the 32-byte hash,
        // lo = bottom 16 bytes. Each half fits in a BN254 field element
        // (each is 128 bits ≪ ~254-bit field size). This matches the
        // circuit's witness-side packing — circuits-eng emits the same
        // halves into signals [7..10].
        {
            bytes32 saHash = sha256(signedAttrs);
            uint256 saHi = uint256(saHash) >> 128;
            uint256 saLo = uint256(saHash) & ((uint256(1) << 128) - 1);
            if (saHi != sig.signedAttrsHashHi) revert BadSignedAttrsHi();
            if (saLo != sig.signedAttrsHashLo) revert BadSignedAttrsLo();
        }

        // SpkiCommit binding — both leaf and intermediate must match the
        // commitments the prover used inside the circuit. spkiCommit also
        // structurally validates the SPKI (parseSpki gates length=91 and
        // the canonical 27-byte DER prefix), so any malformed SPKI
        // bytes also fail here.
        if (P256Verify.spkiCommit(leafSpki, poseidonT3, poseidonT7) != sig.leafSpkiCommit) {
            revert BadLeafSpki();
        }
        if (P256Verify.spkiCommit(intSpki, poseidonT3, poseidonT7) != sig.intSpkiCommit) {
            revert BadIntSpki();
        }

        /* ===== Gate 2b (§6.4): 2× P256Verify (leaf + intermediate) ===== */
        // Leaf signature is over the digest of signedAttrs (the canonical
        // CMS / CAdES SignerInfo signature), signed by the leaf certificate's
        // public key. Gate 2a already proved sha256(signedAttrs) matches
        // sig.signedAttrsHashHi/Lo, so we hash signedAttrs again here for
        // the precompile (cheaper than reconstructing the digest from the
        // hi/lo halves; sha256 of a memory blob is one EVM op).
        if (!P256Verify.verifyWithSpki(leafSpki, sha256(signedAttrs), leafSig)) {
            revert BadLeafSig();
        }

        // Intermediate signature is over the leaf's TBS bytes (the issuer
        // signed those when issuing the leaf cert). The proof commits to
        // the digest in signals [9..10] as Hi/Lo halves; reassemble the
        // 32-byte hash to feed the precompile.
        bytes32 leafTbsHash = bytes32(
            (sig.leafTbsHashHi << 128) | sig.leafTbsHashLo
        );
        if (!P256Verify.verifyWithSpki(intSpki, leafTbsHash, intSig)) {
            revert BadIntSig();
        }

        /* ===== Gate 3 (§6.5): trust-list Merkle membership ===== */
        // Leaf = SpkiCommit(intSpki) — the same commitment Gate 2a just
        // verified against sig.intSpkiCommit. We re-cast it to bytes32 to
        // match PoseidonMerkle.verify's leaf type. The leaf bit-pattern
        // is identical: bytes32(uint256) preserves the field-element value.
        if (!PoseidonMerkle.verify(
            poseidonT3,
            bytes32(sig.intSpkiCommit),
            trustMerklePath,
            trustMerklePathBits,
            trustedListRoot
        )) {
            revert BadTrustList();
        }

        /* ===== Gate 4 (§6.6): policy-list Merkle membership ===== */
        // Leaf = sig.policyLeafHash (already field-domain Poseidon
        // commitment per spec §0.5; no SpkiCommit step needed). The policy
        // tree contains all currently-accepted QKB binding policies; admin
        // rotates the root when the policy fleet changes.
        if (!PoseidonMerkle.verify(
            poseidonT3,
            bytes32(sig.policyLeafHash),
            policyMerklePath,
            policyMerklePathBits,
            policyRoot
        )) {
            revert BadPolicy();
        }

        /* ===== Gate 5: timing + replay ===== */
        // Timing: the proof's sig.timestamp must be within the
        // [block.timestamp - MAX_BINDING_AGE, block.timestamp] window.
        // Future-dated timestamps fail FutureBinding (defensive — should
        // never happen in practice but cheap to gate). Stale timestamps
        // fail StaleBinding (the proof was generated too long ago).
        if (sig.timestamp > block.timestamp) revert FutureBinding();
        if (block.timestamp - sig.timestamp > MAX_BINDING_AGE) revert StaleBinding();

        // V5.2: the V5.1 `BadSender` step (`sig.msgSender != uint160(msg.sender)`)
        // is REMOVED — folded into Gate 2a-prime above (`derivedAddr != msg.sender`).
        // The msgSender slot itself is no longer in the public-signal vector;
        // the wallet binding is established by the keccak-derived address.

        /* ===== Gate 6/7 (V5.1): identity escrow + per-(identity, ctx) anti-Sybil ===== */
        // ctxKey: the 32-byte SHA-256(ctxBytes) reassembled from the hi/lo
        // halves at slots [3..4]. Per V5.1 contract review #2 — natural
        // bit-shift reassembly, no keccak round-trip needed.
        bytes32 ctxKey = bytes32((uint256(sig.ctxHashHi) << 128) | uint256(sig.ctxHashLo));
        bytes32 fingerprint = bytes32(sig.identityFingerprint);
        bytes32 commitment  = bytes32(sig.identityCommitment);
        bytes32 nullifierBytes = bytes32(sig.nullifier);

        // Discriminator: identityWallets[fp] == address(0) iff fingerprint
        // is unclaimed. We pivot on the wallet binding, not the commitment,
        // so a (cosmologically improbable but not zero-probability) Poseidon₂
        // output of zero cannot misroute a legitimate repeat-claim back into
        // the first-claim branch. address(0) is structurally unreachable as
        // a legitimate msg.sender (no private key), so the sentinel is sound
        // for all valid registrations. Per codex review on d12822d (P2 fix).
        if (identityWallets[fingerprint] == address(0)) {
            // ----- First claim path -----
            // Wallet uniqueness: this wallet must not already hold ANY
            // identity (V5.1 invariant 5). Without this gate one wallet
            // could open multiple identityCommitments by registering with
            // different fingerprints — explicitly NOT supported.
            if (nullifierOf[msg.sender] != bytes32(0)) revert AlreadyRegistered();

            // Bind: identity → commitment + wallet, plus mark this ctx used.
            identityCommitments[fingerprint] = commitment;
            identityWallets[fingerprint]     = msg.sender;
            usedCtx[fingerprint][ctxKey]     = true;

            // V5.1 invariant 4: nullifierOf is write-once on first-claim only.
            nullifierOf[msg.sender] = nullifierBytes;
        } else {
            // ----- Repeat-claim path -----
            // Stale-bind FIRST (V5.1 invariant 2): only the wallet currently
            // bound to this fingerprint may register fresh ctxs.
            if (identityWallets[fingerprint] != msg.sender) revert WalletNotBound();

            // Commitment must match the originally-stored value. The wallet
            // proves consistent (subjectSerial, walletSecret) → same Poseidon₂
            // commitment.
            bytes32 storedCommit = identityCommitments[fingerprint];
            if (storedCommit != commitment) revert CommitmentMismatch();

            // Per-(identity, ctx) anti-Sybil (V5.1 invariant 3, monotonic).
            if (usedCtx[fingerprint][ctxKey]) revert CtxAlreadyUsed();
            usedCtx[fingerprint][ctxKey] = true;

            // DO NOT touch nullifierOf — write-once on first-claim per
            // invariant 4. The V5.1 nullifier is per-(walletSecret, ctxHash)
            // so it changes per ctx; downstream Verified-modifier consumers
            // only need "non-zero iff registered ≥ once", which the original
            // first-claim value satisfies.
        }

        emit Registered(msg.sender, nullifierBytes, sig.timestamp);
    }

    /* ---------- rotateWallet() — V5.1 wallet rotation entry point ---------- */

    /// @notice Rotate the wallet bound to an existing identity fingerprint.
    ///         Caller is the NEW wallet; the OLD wallet authorizes the
    ///         rotation by signing an EIP-191 message off-chain.
    ///
    /// @dev    Three-layer authorization (any one failure aborts atomically):
    ///           1. Groth16 proof committing to (fingerprint, oldCommitment,
    ///              newCommitment, newWallet) under rotationMode == 1.
    ///              Proves the prover knows BOTH oldWalletSecret (opens
    ///              oldCommitment) AND newWalletSecret (opens newCommitment)
    ///              for the SAME subjectSerial — circuits-eng's rotation
    ///              circuit enforces this via Poseidon₂ openings + the
    ///              `ForceEqualIfEnabled` mode-flag gates.
    ///           2. ECDSA signature from the old wallet over a domain-tagged
    ///              hash binding (fingerprint, newWallet). Raises the bar
    ///              against tx-only compromise: an attacker who tricks the
    ///              user into signing a rotation tx (UI deception) doesn't
    ///              automatically have a personal_sign of the rotation
    ///              authorization payload.
    ///           3. State invariants: identityCommitments[fp] == oldCommit,
    ///              newWallet == msg.sender, newWallet != oldWallet,
    ///              nullifierOf[newWallet] == 0 (V5.1 invariant 5 —
    ///              wallet uniqueness across rotation).
    ///
    /// @dev    State updates atomically:
    ///           - identityCommitments[fp] = newCommitment
    ///           - identityWallets[fp]     = newWallet (= msg.sender)
    ///           - nullifierOf migrates: newWallet inherits the FIRST-claim
    ///             nullifier; oldWallet's slot is cleared (storage refund).
    ///           - usedCtx[fp][*] is NEVER touched (V5.1 invariant 3 —
    ///             monotonic; carries forward across rotation).
    ///
    /// @dev    NFT contract is NOT touched per user directive 2026-04-30
    ///         ("nft is optional. if this works without nft its fine").
    ///         Users transfer their IdentityEscrowNFT via standard ERC-721
    ///         independently of this rotation.
    ///
    /// @param  proof              Groth16 proof for the rotation circuit.
    /// @param  sig                22-field public signals; rotationMode==1.
    /// @param  oldWalletAuthSig   65-byte ECDSA signature (r || s || v) from
    ///                            the old wallet over the EIP-191 personal-
    ///                            message hash of
    ///                            `keccak256("qkb-rotate-auth-v1" || fp || newWallet)`.
    /// @dev    V5.2 deliberately does NOT add a contract-side keccak gate
    ///         here. The contract makes NO check on `bindingPkX/Y` under
    ///         rotate mode — those slots are witnessed-public values whose
    ///         only on-chain consumer is the verifier's IC linear combination.
    ///         A candidate `derivedAddr == identityWallets[fp]` gate was
    ///         considered but rejected: it would force the proof's binding
    ///         pk to match the originally-registered wallet, breaking
    ///         flexibility V5.1 intentionally supports (e.g., rotating with
    ///         a fresh QES whose binding declares a different wallet pk).
    ///         The rotation auth ECDSA sig from oldWallet's privkey
    ///         (recovered via ecrecover, must match identityWallets[fp])
    ///         is the load-bearing on-chain binding to the original holder.
    ///         (See contract review §3.2 for the withdrawn-recommendation
    ///         rationale.)
    function rotateWallet(
        Groth16Proof   calldata proof,
        PublicSignals  calldata sig,
        bytes          calldata oldWalletAuthSig
    ) external {
        // ----- Mode gate -----
        if (sig.rotationMode != 1) revert WrongMode();

        // ----- V5.3 F2: rotationNewWallet 160-bit range check -----
        // Closes a silent-truncation vector at the `address(uint160(sig.
        // rotationNewWallet))` cast below: without this gate, a malicious
        // prover can submit a `rotationNewWallet` value with high bits
        // (>= 2^160) set; the cast at line below would discard the upper
        // 96 bits, yielding a 160-bit address the prover controls (e.g.,
        // msg.sender) — passing the `newWallet != msg.sender` check
        // downstream while the proof's public signal carries an
        // arbitrarily-shaped 254-bit field element. This range check
        // forces `sig.rotationNewWallet` to be a true Ethereum-address-
        // shaped value, eliminating the truncation surface.
        //
        // Defense-in-depth: pairs with circuits-eng's V5.3 in-circuit
        // `Num2Bits(160)` constraint over `rotationNewWallet`. Either
        // alone is sufficient for the 160-bit gate; both together are
        // the load-bearing-on-each-other discipline.
        //
        // Cost: ~50 gas (single uint256↔uint160 round-trip + comparison +
        // SLOAD-free conditional revert). Fires early (before Groth16
        // verify) so malformed inputs don't pay the ~400K verifier cost.
        //
        // Note on register(): the V5.2 register() flow's `WrongRegisterModeNoOp`
        // gate already enforces `sig.rotationNewWallet == uint256(uint160(
        // msg.sender))`, which is structurally < 2^160 (any uint160 cast
        // produces a value bounded by 2^160). So register() is already
        // safe against this vector via the existing gate; the F2 check
        // is added only to rotateWallet() where the silent-truncation
        // surface actually exists. (Surfaced to team-lead with the T4
        // commit; spec §F2.2 mentions adding to both flows for symmetry,
        // but the contract-side scope is rotateWallet-only per the load-
        // bearing-vector analysis.)
        if (sig.rotationNewWallet != uint256(uint160(sig.rotationNewWallet))) {
            revert InvalidNewWallet();
        }

        // ----- Groth16 verify (mode-flag enforced inside circuit too) -----
        // V5.2: 22-element public-signal vector (V5.1 was 19). Same helper
        // backs both register() and rotateWallet().
        uint256[22] memory input = _packPublicSignalsV52(sig);
        if (!groth16Verifier.verifyProof(proof.a, proof.b, proof.c, input)) {
            revert BadProof();
        }

        // ----- Unpack rotation fields -----
        bytes32 fingerprint   = bytes32(sig.identityFingerprint);
        bytes32 newCommitment = bytes32(sig.identityCommitment);
        bytes32 oldCommitment = bytes32(sig.rotationOldCommitment);
        address newWallet     = address(uint160(sig.rotationNewWallet));

        // ----- Validate rotation invariants -----
        // Identity must be claimed (this is NOT a first-claim path).
        address oldWallet = identityWallets[fingerprint];
        if (oldWallet == address(0))                  revert UnknownIdentity();
        // Stored commitment must match the proof's `rotationOldCommitment`.
        if (identityCommitments[fingerprint] != oldCommitment) revert CommitmentMismatch();
        // newWallet must be the caller, non-zero, and distinct from oldWallet.
        if (newWallet != msg.sender)                  revert InvalidNewWallet();
        if (newWallet == oldWallet)                   revert InvalidNewWallet();
        // V5.1 invariant 5: newWallet must not already hold ANY identity.
        // Guards against a wallet collapse where rotation could merge two
        // identities into one wallet, breaking the per-wallet uniqueness
        // that IdentityEscrowNFT.isVerified() consumers rely on.
        if (nullifierOf[newWallet] != bytes32(0))     revert AlreadyRegistered();

        // ----- Verify old-wallet authorization signature (ECDSA recover) -----
        // Domain tag binds this signature to the rotation use case + this
        // exact registry deployment, preventing replay across:
        //   - other QKB / DApp signing flows ("qkb-rotate-auth-v1" tag)
        //   - other chains where the same registry source might deploy
        //     (block.chainid)
        //   - other registry instances on the same chain, e.g. an upgrade
        //     redeploy or per-country registry (address(this))
        //   - other (fingerprint, newWallet) rotations (fingerprint, newWallet)
        // Per codex review on Task 3 ([P2] cross-deployment-replay).
        bytes32 authPayload = keccak256(
            abi.encodePacked(
                "qkb-rotate-auth-v1",
                block.chainid,
                address(this),
                fingerprint,
                newWallet
            )
        );
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", authPayload)
        );
        address recovered = _recoverSigner(ethSignedHash, oldWalletAuthSig);
        if (recovered != oldWallet) revert InvalidRotationAuth();

        // ----- Atomic state update -----
        identityCommitments[fingerprint] = newCommitment;
        identityWallets[fingerprint]     = newWallet;

        // nullifierOf migration (recommended in spec Q4): preserves the
        // first-claim nullifier value on the new wallet so IQKBRegistry
        // consumers (IdentityEscrowNFT, Verified-modifier) keep returning
        // a non-zero value for the active wallet. Old wallet's slot
        // cleared (refund).
        nullifierOf[newWallet] = nullifierOf[oldWallet];
        delete nullifierOf[oldWallet];

        // V5.1 invariant 3: usedCtx[fp][*] persists. Anti-Sybil intact.

        emit WalletRotated(fingerprint, oldWallet, newWallet, newCommitment);
    }

    /// @dev Recover an ECDSA signer address from a 65-byte (r || s || v)
    ///      signature over `hash`. Reverts (returns address(0) effectively)
    ///      on s-malleability or wrong length; the caller's downstream
    ///      `recovered != oldWallet` check turns those into
    ///      `InvalidRotationAuth`. Mirrors the OpenZeppelin ECDSA pattern
    ///      without pulling the full lib in — we only need this one path.
    function _recoverSigner(bytes32 hash, bytes calldata signature)
        internal pure returns (address)
    {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8   v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
        // EIP-2 / SEC 1: reject high-s to prevent malleability.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        if (v != 27 && v != 28) return address(0);
        return ecrecover(hash, v, r, s);
    }

    /// @dev Pack PublicSignals into the 22-element array the V5.2 verifier
    ///      consumes. Extracted into a helper so `register()` and
    ///      `rotateWallet()` share the same source-of-truth ordering —
    ///      drift would mean the on-chain pack disagreed with the circuit's
    ///      emitted public-input layout (FROZEN per V5.2 amendment
    ///      §"Public-signal layout").
    /// @dev Field-by-field assignment is deliberate: 22 storage SLOADs in a
    ///      single struct-literal expression overflow the Yul-IR stack
    ///      ("Cannot swap _3 with _N: too deep by 1 slots"). Sequential
    ///      mstore lets the optimizer reuse stack slots between fields.
    ///      V5.1 already paid this lesson at uint[19] (commit `04b4a71`);
    ///      uint[22] hits it harder.
    function _packPublicSignalsV52(PublicSignals calldata sig)
        internal pure returns (uint256[22] memory input)
    {
        input[0]  = sig.timestamp;
        input[1]  = sig.nullifier;
        input[2]  = sig.ctxHashHi;
        input[3]  = sig.ctxHashLo;
        input[4]  = sig.bindingHashHi;
        input[5]  = sig.bindingHashLo;
        input[6]  = sig.signedAttrsHashHi;
        input[7]  = sig.signedAttrsHashLo;
        input[8]  = sig.leafTbsHashHi;
        input[9]  = sig.leafTbsHashLo;
        input[10] = sig.policyLeafHash;
        input[11] = sig.leafSpkiCommit;
        input[12] = sig.intSpkiCommit;
        input[13] = sig.identityFingerprint;
        input[14] = sig.identityCommitment;
        input[15] = sig.rotationMode;
        input[16] = sig.rotationOldCommitment;
        input[17] = sig.rotationNewWallet;
        input[18] = sig.bindingPkXHi;
        input[19] = sig.bindingPkXLo;
        input[20] = sig.bindingPkYHi;
        input[21] = sig.bindingPkYLo;
    }

    /// @dev V5.2 NEW — derive an Ethereum-style address from the binding's
    ///      secp256k1 wallet pubkey, supplied as 4 × 128-bit limbs (Hi/Lo
    ///      pairs for X and Y). Reconstructs the 64-byte uncompressed pk
    ///      and runs keccak256, then extracts the low 160 bits per the
    ///      Ethereum address rule.
    ///
    ///      Endianness alignment with the circuit's Bits2Num packing:
    ///        - bindingPkXHi = sum_{i=0..15}  parser.pkBytes[i+1]  * 256^(15-i)
    ///        - bindingPkXLo = sum_{i=16..31} parser.pkBytes[i+1]  * 256^(31-i)
    ///        - bindingPkYHi = sum_{i=0..15}  parser.pkBytes[i+33] * 256^(15-i)
    ///        - bindingPkYLo = sum_{i=16..31} parser.pkBytes[i+33] * 256^(31-i)
    ///      So the high byte of each Hi/Lo limb is parser.pkBytes[1] /
    ///      pkBytes[17] / pkBytes[33] / pkBytes[49] respectively.
    ///      `bytes16(uint128(...))` casts a 128-bit numeric to a left-aligned
    ///      bytes16, putting that high byte at byte 0 of the bytes16. The
    ///      concatenated 64 bytes reproduce parser.pkBytes[1..65] in the
    ///      same byte order V5.1's in-circuit keccak consumed. Soundness
    ///      equivalence at the keccak input boundary is exact.
    ///
    ///      Defense-in-depth on the limb range: the contract REVERTS if any
    ///      limb is ≥ 2^128 (per BindingPkLimbOutOfRange below). The
    ///      circuit's Bits2Num(128) constraint should already enforce this,
    ///      but explicit on-chain rejection (rather than silent truncation
    ///      via `uint128(...)` cast) surfaces a circuit bug as a
    ///      diagnosable revert instead of masking it as a different
    ///      keccak input. ~30 gas total for the 4 range checks.
    function _deriveAddrFromBindingLimbs(PublicSignals calldata sig)
        internal pure returns (address)
    {
        // Range checks — reject any limb that doesn't fit in 128 bits.
        // The circuit's Bits2Num(128) constraint ensures this for valid
        // proofs; the contract gate is for diagnosability under a
        // hypothetical circuit bug.
        uint256 maxLimb = type(uint128).max;
        if (sig.bindingPkXHi > maxLimb) revert BindingPkLimbOutOfRange();
        if (sig.bindingPkXLo > maxLimb) revert BindingPkLimbOutOfRange();
        if (sig.bindingPkYHi > maxLimb) revert BindingPkLimbOutOfRange();
        if (sig.bindingPkYLo > maxLimb) revert BindingPkLimbOutOfRange();

        bytes memory pk = abi.encodePacked(
            bytes16(uint128(sig.bindingPkXHi)),
            bytes16(uint128(sig.bindingPkXLo)),
            bytes16(uint128(sig.bindingPkYHi)),
            bytes16(uint128(sig.bindingPkYLo))
        );
        return address(uint160(uint256(keccak256(pk))));
    }
}
