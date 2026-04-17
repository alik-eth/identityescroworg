// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @notice Canonical interface every QIE arbitrator implements.
///         The off-chain unlock evaluator subscribes to the `Unlock(bytes32,bytes)`
///         event across all registered arbitrators and treats a single emission
///         as authorisation to release the Holder's share of `k_esc` to the
///         decoded `recipientHybridPk`. The event topic is therefore a
///         frozen cross-package invariant (orchestration §2.3).
interface IArbitrator {
    event Unlock(bytes32 indexed escrowId, bytes recipientHybridPk);
}
