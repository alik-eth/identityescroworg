// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Poseidon} from "./Poseidon.sol";

/// @title  PoseidonMerkle — depth-16 Merkle membership verification.
/// @notice V5 spec §0.5 — used for both trust-list (intSpki commitment in
///         trustedListRoot) and policy-list (policyLeafHash in policyRoot)
///         membership proofs inside register().
/// @dev    Internal-node hash: Poseidon₂(left, right) over BN254 Fr,
///         computed by staticcall to the Poseidon T3 contract whose address
///         is supplied per call. The library is stateless. Empty leaves are
///         conventionally Poseidon₁(0); see test/fixtures/v5/merkle.json
///         `emptySubtreeRoots` for the per-level pre-hashed empties.
library PoseidonMerkle {
    /// Tree depth — frozen at 16 by orchestration §2.2 (matches V4
    /// trust-list and the V5 policy-list/trust-list conventions).
    uint256 internal constant DEPTH = 16;

    /// @notice Verify a depth-16 Merkle membership proof.
    /// @param  t3       Address of the deployed Poseidon T3 contract.
    /// @param  leaf     The claimed leaf value.
    /// @param  path     Sibling hashes at each of the 16 levels (index 0
    ///                  = nearest to leaf).
    /// @param  pathBits Bit i = 0 means the current node is the LEFT child
    ///                  at level i (so the sibling goes on the RIGHT);
    ///                  bit i = 1 means the current node is the RIGHT
    ///                  child (sibling on the LEFT). Bits above index 15
    ///                  are ignored.
    /// @param  root     Expected Merkle root.
    /// @return ok       True iff applying Poseidon₂ up the path produces
    ///                  the given root.
    function verify(
        address t3,
        bytes32 leaf,
        bytes32[16] memory path,
        uint256 pathBits,
        bytes32 root
    ) internal view returns (bool ok) {
        uint256 cur = uint256(leaf);
        for (uint256 i = 0; i < DEPTH; i++) {
            uint256 sibling = uint256(path[i]);
            uint256[2] memory pair = ((pathBits >> i) & 1) == 0
                ? [cur, sibling]
                : [sibling, cur];
            cur = Poseidon.hashT3(t3, pair);
        }
        return cur == uint256(root);
    }
}
