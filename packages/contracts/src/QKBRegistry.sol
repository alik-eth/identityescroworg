// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { QKBVerifier, IGroth16Verifier } from "./QKBVerifier.sol";

/// @notice Reference register-then-authenticate registry for QKB-bound
///         secp256k1 keys. Phase 1 ships the ECDSA-leaf variant only; both
///         the RSA variant and the chain-side proof (which would pin rTL
///         on-chain) are deferred to Phase 2 per spec §5.4.
///
///         `trustedListRoot` is still held as admin-rotatable state so
///         downstream consumers have a single source of truth, but the
///         `register` flow does NOT check it against the proof in Phase 1
///         — the leaf proof does not expose rTL. Admins vet the LOTL
///         freshness off-chain until the chain proof lands.
contract QKBRegistry {
    /// @dev Domain string for the `expire` signature digest. Must stay in
    ///      lock-step with `test/helpers/SignatureHelpers.sol::EXPIRE_DOMAIN`.
    string private constant EXPIRE_DOMAIN = "QKB_EXPIRE_V1";

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

    IGroth16Verifier public verifier;
    bytes32 public trustedListRoot;
    address public admin;
    mapping(address => Binding) public bindings;

    event BindingRegistered(address indexed pkAddr, bytes32 ctxHash, bytes32 declHash);
    event BindingExpired(address indexed pkAddr);
    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event VerifierUpdated(address oldVerifier, address newVerifier);

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
        emit VerifierUpdated(address(0), address(verifier_));
    }

    /// @notice Register a fresh QKB binding. See spec §6.2 steps 1–7.
    ///         Phase 1 deviation: no on-chain rTL equality check (the leaf
    ///         proof doesn't carry rTL). admin multisig enforces trusted-list
    ///         freshness off-chain until the chain proof lands.
    function register(QKBVerifier.Proof calldata p, QKBVerifier.Inputs calldata i) external {
        if (!QKBVerifier.verify(verifier, p, i)) revert InvalidProof();
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

    /// @notice Tear down a binding. `sig` must be a secp256k1 signature by
    ///         the bound key over `keccak256(abi.encode(EXPIRE_DOMAIN,
    ///         pkAddr, block.chainid, boundAt))`. Already-expired and never-
    ///         bound entries both revert with `NotBound`.
    function expire(address pkAddr, bytes calldata sig) external {
        Binding storage b = bindings[pkAddr];
        if (b.status != Status.ACTIVE) revert NotBound();

        bytes32 digest = keccak256(abi.encode(EXPIRE_DOMAIN, pkAddr, block.chainid, b.boundAt));
        address recovered = _recover(digest, sig);
        if (recovered != pkAddr) revert BadExpireSig();

        b.status = Status.EXPIRED;
        b.expiredAt = uint64(block.timestamp);
        emit BindingExpired(pkAddr);
    }

    function _recover(bytes32 digest, bytes calldata sig) private pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
            v := byte(0, calldataload(add(sig.offset, 0x40)))
        }
        return ecrecover(digest, v, r, s);
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

    /// @notice True iff the binding for `pkAddr` was active at time `t`.
    ///         Pre-bind (`t < boundAt`) and post-expire (`t >= expiredAt`)
    ///         both return false. Unknown bindings return false.
    function isActiveAt(address pkAddr, uint64 t) external view returns (bool) {
        Binding storage b = bindings[pkAddr];
        if (b.status == Status.NONE) return false;
        if (t < b.boundAt) return false;
        if (b.status == Status.ACTIVE) return true;
        return t < b.expiredAt;
    }

    function setVerifier(IGroth16Verifier newVerifier) external onlyAdmin {
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        address old = address(verifier);
        verifier = newVerifier;
        emit VerifierUpdated(old, address(newVerifier));
    }
}
