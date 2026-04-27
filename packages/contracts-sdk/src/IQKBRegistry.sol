// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IQKBRegistry — minimal read interface for QKB-verified identity gating.
/// @notice Implemented by `QKBRegistryV4`. Third-party contracts depend only on
///         this interface.
interface IQKBRegistry {
    /// @notice True iff `holder` has registered a verified Ukrainian nullifier.
    function isVerified(address holder) external view returns (bool);

    /// @notice Returns the nullifier bound to `holder`, or 0 if not registered.
    function nullifierOf(address holder) external view returns (bytes32);

    /// @notice Current trusted-list Merkle root (eIDAS chain anchor).
    function trustedListRoot() external view returns (bytes32);
}
