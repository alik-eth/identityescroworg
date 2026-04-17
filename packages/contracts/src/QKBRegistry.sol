// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { QKBVerifier, IGroth16Verifier } from "./QKBVerifier.sol";

/// @notice Reference register-then-authenticate registry for QKB-bound
///         secp256k1 keys. State + admin only at this stage; register/expire/
///         isActiveAt arrive in Tasks 6–9.
contract QKBRegistry {
    enum Status {
        NONE,
        ACTIVE,
        EXPIRED
    }

    struct Binding {
        Status status;
        uint64 boundAt;
        uint64 expiredAt;
        bytes32 ctxHash;
        bytes32 declHash;
    }

    /// @dev Maximum age of a binding proof, measured against `i.timestamp` at
    ///      `register` time. Per spec §6.2.
    uint64 public constant MAX_AGE = 90 days;

    IGroth16Verifier public immutable verifier;
    bytes32 public trustedListRoot;
    address public admin;
    mapping(address => Binding) public bindings;

    event BindingRegistered(address indexed pkAddr, bytes32 ctxHash, bytes32 declHash);
    event BindingExpired(address indexed pkAddr);
    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    error RootMismatch();
    error AlreadyBound();
    error BindingTooOld();
    error BindingFromFuture();
    error InvalidProof();
    error NotBound();
    error BadExpireSig();
    error NotAdmin();
    error ZeroAddress();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(IGroth16Verifier verifier_, bytes32 initialRoot, address initialAdmin) {
        if (address(verifier_) == address(0)) revert ZeroAddress();
        if (initialAdmin == address(0)) revert ZeroAddress();
        verifier = verifier_;
        trustedListRoot = initialRoot;
        admin = initialAdmin;
        emit AdminTransferred(address(0), initialAdmin);
        emit TrustedListRootUpdated(bytes32(0), initialRoot);
    }

    /// @notice Register a fresh QKB binding. See spec §6.2 steps 1–7.
    function register(QKBVerifier.Proof calldata p, QKBVerifier.Inputs calldata i) external {
        if (!QKBVerifier.verify(verifier, p, i)) revert InvalidProof();
        if (i.rTL != trustedListRoot) revert RootMismatch();
        if (i.timestamp > block.timestamp) revert BindingFromFuture();
        if (block.timestamp > uint256(i.timestamp) + MAX_AGE) revert BindingTooOld();

        address pkAddr = QKBVerifier.toPkAddress(i.pkX, i.pkY);
        if (bindings[pkAddr].status != Status.NONE) revert AlreadyBound();

        bindings[pkAddr] = Binding({
            status: Status.ACTIVE,
            boundAt: uint64(block.timestamp),
            expiredAt: 0,
            ctxHash: i.ctxHash,
            declHash: i.declHash
        });
        emit BindingRegistered(pkAddr, i.ctxHash, i.declHash);
    }

    function updateTrustedListRoot(bytes32 newRoot) external onlyAdmin {
        bytes32 old = trustedListRoot;
        trustedListRoot = newRoot;
        emit TrustedListRootUpdated(old, newRoot);
    }

    function setAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        address old = admin;
        admin = newAdmin;
        emit AdminTransferred(old, newAdmin);
    }
}
