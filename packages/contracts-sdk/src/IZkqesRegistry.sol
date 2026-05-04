// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IZkqesRegistry — minimal read interface for zkqes-verified identity gating.
/// @notice Implemented by `ZkqesRegistryV4`, `ZkqesRegistryV5` (incl. V5.1
///         wallet-bound amendment), and `ZkqesRegistryV5_2` (keccak-on-chain
///         amendment). Third-party contracts depend only on this read
///         interface — selectors and return types are stable across the
///         V4 → V5 → V5.1 → V5.2 evolution.
///
/// @dev    V5.1 invariant 4 (semantic shift, not ABI): `nullifierOf` is
///         WRITE-ONCE on first-claim. Repeat-claim register() against a
///         new ctx (V5.1 only) does NOT overwrite the stored value. This
///         preserves the "non-zero iff registered" invariant that
///         `ZkqesCertificate.isVerified()` and `Verified` modifier
///         consumers rely on, while letting the V5.1 nullifier vary
///         per (walletSecret, ctxHash) on the wire. After
///         `rotateWallet()`, the FIRST-claim nullifier value migrates
///         atomically to the new wallet's slot; the old wallet's slot
///         is cleared. So `nullifierOf(activeWallet) != 0` continues
///         to hold for any user with an active V5.1 binding.
interface IZkqesRegistry {
    /// @notice True iff `holder` has at least one verified registration on
    ///         file. Across V4 → V5 → V5.1 the underlying logic is
    ///         "`nullifierOf(holder) != 0`" — V5.1 invariant 4 keeps
    ///         this consistent across repeat-claim and rotateWallet().
    function isVerified(address holder) external view returns (bool);

    /// @notice Returns the nullifier bound to `holder`, or 0 if not
    ///         registered. V5.1 semantic: this is the FIRST-claim
    ///         nullifier value (not the most-recent). Migrates to the
    ///         new wallet's slot atomically on rotateWallet().
    function nullifierOf(address holder) external view returns (bytes32);

    /// @notice Current trusted-list Merkle root (eIDAS chain anchor).
    function trustedListRoot() external view returns (bytes32);
}
