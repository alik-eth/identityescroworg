// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {IQKBRegistry} from "./IdentityEscrowNFT.sol";
import {Poseidon} from "./libs/Poseidon.sol";
import {PoseidonBytecode} from "./libs/PoseidonBytecode.sol";
import {P256Verify} from "./libs/P256Verify.sol";
import {PoseidonMerkle} from "./libs/PoseidonMerkle.sol";

/// @notice The Groth16 verifier interface — exposed so the registry can
///         bind to either the §5 stub OR the real ceremony output without
///         a source change. snarkjs auto-generated verifiers already match
///         this signature.
interface IGroth16VerifierV5 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[14] calldata input
    ) external view returns (bool);
}

/// @title  QKBRegistryV5 — V5 binding registry (5-gate `register()`).
/// @notice Implements `IQKBRegistry` (ABI-stable across V4↔V5; downstream
///         SDK consumers + IdentityEscrowNFT work unchanged). The V5
///         architecture moves all P-256 ECDSA verification on-chain via
///         EIP-7212 (RIP-7212 P256VERIFY at `0x100`), with a Groth16 proof
///         binding the wallet caller, the nullifier, and the calldata
///         pre-images for the leaf SPKI / intermediate SPKI / signedAttrs /
///         leaf TBS / policy commitment.
///
///         §6.1 skeleton: state, events, view fns, admin surface. The full
///         5-gate `register()` body lands in §6.2-§6.7. Each gate ships in
///         its own commit with a dedicated negative test — Gate 1 Groth16,
///         Gate 2a calldata-binding, Gate 2b 2× P256, Gate 3 trust Merkle,
///         Gate 4 policy Merkle, Gate 5 timing/sender/replay.
///
/// @dev    Constructor side-effects:
///           - CREATE-deploy PoseidonT3 (35K bytecode → ~9.8K bytes contract)
///             and PoseidonT7 (~23.6K bytes contract). Their addresses are
///             cached as immutables for cheap reads inside register().
///           - Set admin + initial trustedListRoot + initial policyRoot.
///         The contract is NOT upgradeable — V4 → V5 is a fresh deploy with
///         a holder re-registration flow per orchestration §8.
contract QKBRegistryV5 is IQKBRegistry {
    /* ---------- immutables ---------- */

    /// Groth16 verifier (stub now, real ceremony output post-§14).
    IGroth16VerifierV5 public immutable groth16Verifier;

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
    mapping(address => bytes32) public override nullifierOf;

    /// Reverse: nullifier → holder. Catches "two wallets, same nullifier"
    /// (Sybil-by-multi-wallet) — register() reverts on collision.
    mapping(bytes32 => address) public registrantOf;

    /* ---------- events ---------- */

    event Registered(address indexed holder, bytes32 indexed nullifier, uint256 timestamp);
    event TrustedListRootRotated(bytes32 indexed previous, bytes32 indexed current, address admin);
    event PolicyRootRotated(bytes32 indexed previous, bytes32 indexed current, address admin);
    event AdminTransferred(address indexed previous, address indexed current);

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
        IGroth16VerifierV5 _verifier,
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

    /// 14 BN254 field-element public signals — order is FROZEN.
    struct PublicSignals {
        uint256 msgSender;          // [0]  ≤ 2^160
        uint256 timestamp;          // [1]  ≤ 2^64
        uint256 nullifier;          // [2]  Poseidon₂ output
        uint256 ctxHashHi;          // [3]
        uint256 ctxHashLo;          // [4]
        uint256 bindingHashHi;      // [5]
        uint256 bindingHashLo;      // [6]
        uint256 signedAttrsHashHi;  // [7]
        uint256 signedAttrsHashLo;  // [8]
        uint256 leafTbsHashHi;      // [9]
        uint256 leafTbsHashLo;      // [10]
        uint256 policyLeafHash;     // [11]
        uint256 leafSpkiCommit;     // [12]
        uint256 intSpkiCommit;      // [13]
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

    /// @notice 5-gate registration. Gates land incrementally:
    ///   Gate 1 (this commit, §6.2): Groth16 verify call.
    ///   Gate 2a (§6.3): bind public-input commits to calldata.
    ///   Gate 2b (§6.4): 2× P256Verify (leaf + intermediate).
    ///   Gate 3 (§6.5):  trust-list Merkle proof.
    ///   Gate 4 (§6.6):  policy-list Merkle proof.
    ///   Gate 5 (§6.7):  timing + sender + replay (write-out path).
    /// @dev    Calldata layout per orchestration §0.3:
    ///         (proof, sig, leafSpki, intSpki, signedAttrs, leafSig, intSig,
    ///          trustMerklePath, trustMerklePathBits,
    ///          policyMerklePath, policyMerklePathBits)
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
        // No more deferred params — Gates 4 and 5 (replay/timing/sender)
        // are the remaining unimplemented gates after this commit.

        /* ===== Gate 1 (§6.2): Groth16 verify ===== */
        // Pack the 14-signal public-input array. Order MUST match V5 spec
        // §0.1 exactly; auto-generated snarkjs verifiers consume `uint[14]`.
        uint256[14] memory input = [
            sig.msgSender,
            sig.timestamp,
            sig.nullifier,
            sig.ctxHashHi,
            sig.ctxHashLo,
            sig.bindingHashHi,
            sig.bindingHashLo,
            sig.signedAttrsHashHi,
            sig.signedAttrsHashLo,
            sig.leafTbsHashHi,
            sig.leafTbsHashLo,
            sig.policyLeafHash,
            sig.leafSpkiCommit,
            sig.intSpkiCommit
        ];
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

        // Gate 5 lands in §6.7 — timing + sender + replay (write-out path).
    }
}
