// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { QKBVerifier, IGroth16Verifier } from "./QKBVerifier.sol";

/// @notice Reference register-then-authenticate registry for QKB-bound
///         secp256k1 keys. Bindings are created via `register` (proof-gated,
///         dispatched to either the RSA-PKCS#1 v1.5 or ECDSA P-256 Groth16
///         verifier per `i.algorithmTag` — orchestration §2.0) and torn down
///         via `expire` (signed by the bound key).
contract QKBRegistry {
    /// @dev Domain string for the `expire` signature digest. Must stay in
    ///      lock-step with `test/helpers/SignatureHelpers.sol::EXPIRE_DOMAIN`.
    string private constant EXPIRE_DOMAIN = "QKB_EXPIRE_V1";

    uint8 internal constant ALG_RSA = 0;
    uint8 internal constant ALG_ECDSA = 1;

    enum Status {
        NONE,
        ACTIVE,
        EXPIRED
    }

    struct Binding {
        Status status;
        uint64 boundAt;
        uint64 expiredAt;
        uint8 algorithmTag;
        bytes32 ctxHash;
        bytes32 declHash;
    }

    /// @dev Maximum age of a binding proof, measured against `i.timestamp` at
    ///      `register` time. Per spec §6.2.
    uint64 public constant MAX_AGE = 90 days;

    IGroth16Verifier public rsaVerifier;
    IGroth16Verifier public ecdsaVerifier;
    bytes32 public trustedListRoot;
    address public admin;
    mapping(address => Binding) public bindings;

    event BindingRegistered(address indexed pkAddr, bytes32 ctxHash, bytes32 declHash, uint8 algorithmTag);
    event BindingExpired(address indexed pkAddr);
    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event VerifierUpdated(uint8 indexed algorithmTag, address oldVerifier, address newVerifier);

    error RootMismatch();
    error AlreadyBound();
    error BindingTooOld();
    error BindingFromFuture();
    error InvalidProof();
    error NotBound();
    error BadExpireSig();
    error NotAdmin();
    error ZeroAddress();
    error UnknownAlgorithm();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(
        IGroth16Verifier rsa_,
        IGroth16Verifier ecdsa_,
        bytes32 initialRoot,
        address initialAdmin
    ) {
        if (address(rsa_) == address(0)) revert ZeroAddress();
        if (address(ecdsa_) == address(0)) revert ZeroAddress();
        if (initialAdmin == address(0)) revert ZeroAddress();
        rsaVerifier = rsa_;
        ecdsaVerifier = ecdsa_;
        trustedListRoot = initialRoot;
        admin = initialAdmin;
        emit AdminTransferred(address(0), initialAdmin);
        emit TrustedListRootUpdated(bytes32(0), initialRoot);
        emit VerifierUpdated(ALG_RSA, address(0), address(rsa_));
        emit VerifierUpdated(ALG_ECDSA, address(0), address(ecdsa_));
    }

    /// @notice Register a fresh QKB binding. See spec §6.2 steps 1–7;
    ///         dispatch added per orchestration §2.0.
    function register(QKBVerifier.Proof calldata p, QKBVerifier.Inputs calldata i) external {
        IGroth16Verifier v;
        if (i.algorithmTag == ALG_RSA) {
            v = rsaVerifier;
        } else if (i.algorithmTag == ALG_ECDSA) {
            v = ecdsaVerifier;
        } else {
            revert UnknownAlgorithm();
        }

        if (!QKBVerifier.verify(v, p, i)) revert InvalidProof();
        if (i.rTL != trustedListRoot) revert RootMismatch();
        if (i.timestamp > block.timestamp) revert BindingFromFuture();
        if (block.timestamp > uint256(i.timestamp) + MAX_AGE) revert BindingTooOld();

        address pkAddr = QKBVerifier.toPkAddress(i.pkX, i.pkY);
        if (bindings[pkAddr].status != Status.NONE) revert AlreadyBound();

        bindings[pkAddr] = Binding({
            status: Status.ACTIVE,
            boundAt: uint64(block.timestamp),
            expiredAt: 0,
            algorithmTag: i.algorithmTag,
            ctxHash: i.ctxHash,
            declHash: i.declHash
        });
        emit BindingRegistered(pkAddr, i.ctxHash, i.declHash, i.algorithmTag);
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

    function setRsaVerifier(IGroth16Verifier newVerifier) external onlyAdmin {
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        address old = address(rsaVerifier);
        rsaVerifier = newVerifier;
        emit VerifierUpdated(ALG_RSA, old, address(newVerifier));
    }

    function setEcdsaVerifier(IGroth16Verifier newVerifier) external onlyAdmin {
        if (address(newVerifier) == address(0)) revert ZeroAddress();
        address old = address(ecdsaVerifier);
        ecdsaVerifier = newVerifier;
        emit VerifierUpdated(ALG_ECDSA, old, address(newVerifier));
    }
}
