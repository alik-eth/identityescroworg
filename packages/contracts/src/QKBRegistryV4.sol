// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {
    IGroth16LeafVerifierV4,
    IGroth16ChainVerifierV4,
    IGroth16AgeVerifierV4
} from "./QKBVerifierV4Draft.sol";

/// @notice Per-country QKB/2 registry. Constructor-frozen country tag; admin-
///         rotatable trust roots + verifier addresses.
contract QKBRegistryV4 {
    string public constant VERSION = "QKB/2.0";
    string public country;

    bytes32 public trustedListRoot;
    bytes32 public policyRoot;

    IGroth16LeafVerifierV4  public leafVerifier;
    IGroth16ChainVerifierV4 public chainVerifier;
    IGroth16AgeVerifierV4   public ageVerifier;

    address public admin;

    error OnlyAdmin();

    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event PolicyRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event VerifierUpdated(bytes32 indexed kind, address oldV, address newV);
    event AdminTransferred(address oldAdmin, address newAdmin);

    bytes32 private constant _LEAF  = keccak256("leaf");
    bytes32 private constant _CHAIN = keccak256("chain");
    bytes32 private constant _AGE   = keccak256("age");

    modifier onlyAdmin() {
        if (msg.sender != admin) revert OnlyAdmin();
        _;
    }

    constructor(
        string memory country_,
        bytes32 trustedListRoot_,
        bytes32 policyRoot_,
        address leafVerifier_,
        address chainVerifier_,
        address ageVerifier_,
        address admin_
    ) {
        country         = country_;
        trustedListRoot = trustedListRoot_;
        policyRoot      = policyRoot_;
        leafVerifier    = IGroth16LeafVerifierV4(leafVerifier_);
        chainVerifier   = IGroth16ChainVerifierV4(chainVerifier_);
        ageVerifier     = IGroth16AgeVerifierV4(ageVerifier_);
        admin           = admin_;
    }

    function setTrustedListRoot(bytes32 newRoot) external onlyAdmin {
        emit TrustedListRootUpdated(trustedListRoot, newRoot);
        trustedListRoot = newRoot;
    }

    function setPolicyRoot(bytes32 newRoot) external onlyAdmin {
        emit PolicyRootUpdated(policyRoot, newRoot);
        policyRoot = newRoot;
    }

    function setLeafVerifier(address v) external onlyAdmin {
        emit VerifierUpdated(_LEAF, address(leafVerifier), v);
        leafVerifier = IGroth16LeafVerifierV4(v);
    }

    function setChainVerifier(address v) external onlyAdmin {
        emit VerifierUpdated(_CHAIN, address(chainVerifier), v);
        chainVerifier = IGroth16ChainVerifierV4(v);
    }

    function setAgeVerifier(address v) external onlyAdmin {
        emit VerifierUpdated(_AGE, address(ageVerifier), v);
        ageVerifier = IGroth16AgeVerifierV4(v);
    }

    function setAdmin(address newAdmin) external onlyAdmin {
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }
}
