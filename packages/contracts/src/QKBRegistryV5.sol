// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {IQKBRegistry} from "./IdentityEscrowNFT.sol";
import {Poseidon} from "./libs/Poseidon.sol";
import {PoseidonBytecode} from "./libs/PoseidonBytecode.sol";

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

    /* ---------- register() — body lands in §6.2..§6.7 ---------- */
    // function register(...) external { ... }
}
