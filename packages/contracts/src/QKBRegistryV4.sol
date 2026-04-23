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
}
