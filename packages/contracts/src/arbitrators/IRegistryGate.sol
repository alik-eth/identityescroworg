// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @notice The minimal registry surface an arbitrator calls into while
///         driving the release state machine. Implemented by QKBRegistry.
///
///         Split from the full registry ABI so arbitrators (and mocks) can
///         depend only on the hooks they actually need — the rest of the
///         registry's surface is immaterial to the release flow.
///
///         State transitions driven through this interface (MVP refinement §0.3):
///           ACTIVE           -> RELEASE_PENDING  via notifyReleasePending
///           RELEASE_PENDING  -> RELEASED         via finalizeRelease
///         `finalizeRelease` must gate on the Holder's cancellation window
///         (`RELEASE_TIMEOUT`) in the registry implementation.
interface IRegistryGate {
    function notifyReleasePending(bytes32 escrowId) external;
    function finalizeRelease(bytes32 escrowId) external;
}
