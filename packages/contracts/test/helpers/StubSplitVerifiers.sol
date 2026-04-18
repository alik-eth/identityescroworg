// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @notice Test-only 13-signal stand-in for the snarkjs-generated split-
///         proof **leaf** verifier. Ignores the proof + public inputs and
///         returns a configurable bool.
///
///         The canonical (snarkjs-generated) stubs pumped from
///         `circuits-eng` will live under `src/verifiers/` and land in K2;
///         this helper exists so the V3 registry tests can exercise the
///         dispatch + verify + commit-glue logic before that pump.
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

/// @notice Test-only 5-signal stand-in for the snarkjs-generated split-
///         proof **chain** verifier. See `StubGroth16LeafVerifier` for
///         rationale.
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
