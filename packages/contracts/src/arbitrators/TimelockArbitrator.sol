// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { IArbitrator } from "./IArbitrator.sol";

/// @notice DEFERRED post-MVP per
///         docs/superpowers/specs/2026-04-17-qie-mvp-refinement.md §3.2.
///
///         Kept in-tree as an interface placeholder so external references
///         (deploy scripts, type imports in downstream packages) don't break
///         while we prove the notary-assisted path with a real pilot. Any
///         invocation reverts `Deferred()`. The full dead-man-switch
///         implementation will be restored once the MVP window clears.
contract TimelockArbitrator is IArbitrator {
    error Deferred();

    function requestUnlock(bytes32, bytes calldata) external pure {
        revert Deferred();
    }
}
