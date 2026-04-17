// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @notice Test-only stand-in for the snarkjs-generated Groth16 verifier.
///         Returns a configurable bool from `verifyProof`, ignoring all proof
///         and public-input arguments. Replaced by the real
///         `QKBGroth16Verifier` once circuits-eng ships it (Task 10).
contract StubGroth16Verifier {
    bool public accept = true;

    function setAccept(bool v) external {
        accept = v;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[13] calldata
    ) external view returns (bool) {
        return accept;
    }
}
