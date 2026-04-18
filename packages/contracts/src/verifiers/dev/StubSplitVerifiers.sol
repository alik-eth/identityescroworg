// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @notice DEV-ONLY stub for the split-proof leaf verifier (13 public
///         signals). Ignores the proof + public inputs and always
///         returns `accept` (default true).
///
///         NEVER deploy to a chain users will rely on. `Deploy*.s.sol`
///         uses these as anvil / CI fallbacks only, guarded by
///         `USE_STUB_VERIFIER`. Production slots require the snarkjs-
///         generated real verifiers pumped from the circuits package.
contract StubGroth16LeafVerifier {
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

/// @notice DEV-ONLY stub for the split-proof **chain** verifier (5 public
///         signals). See `StubGroth16LeafVerifier` for the deployment
///         warning — identical policy.
contract StubGroth16ChainVerifier {
    bool public accept = true;

    function setAccept(bool v) external {
        accept = v;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[5] calldata
    ) external view returns (bool) {
        return accept;
    }
}
