// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { IArbitrator } from "./IArbitrator.sol";

/// @notice Dead-man switch arbitrator. Emits `Unlock` iff the designated
///         holder has not `ping()`-ed for at least `timeoutSeconds`.
///
///         Lifecycle:
///           - Deployer sets `holderPing` + `timeoutSeconds`; `lastPing`
///             initialised to `block.timestamp` (grace period of the full
///             timeout before the first possible unlock).
///           - Holder calls `ping()` at intervals < `timeoutSeconds`.
///           - If the holder disappears for at least `timeoutSeconds`,
///             anyone can call `requestUnlock(escrowId, recipientHybridPk)`
///             and the event fires.
///           - Per-escrowId one-shot: `unlocked[escrowId]` guards against
///             duplicate emission for the same escrow.
contract TimelockArbitrator is IArbitrator {
    address public immutable holderPing;
    uint256 public immutable timeoutSeconds;
    uint256 public lastPing;
    mapping(bytes32 => bool) public unlocked;

    constructor(address _holderPing, uint256 _timeoutSeconds) {
        require(_holderPing != address(0), "TimelockArbitrator: zero holder");
        require(_timeoutSeconds > 0, "TimelockArbitrator: zero timeout");
        holderPing = _holderPing;
        timeoutSeconds = _timeoutSeconds;
        lastPing = block.timestamp;
    }

    function ping() external {
        require(msg.sender == holderPing, "TimelockArbitrator: not holder");
        lastPing = block.timestamp;
    }

    function requestUnlock(bytes32 escrowId, bytes calldata recipientHybridPk) external {
        require(block.timestamp >= lastPing + timeoutSeconds, "TimelockArbitrator: timeout not elapsed");
        require(!unlocked[escrowId], "TimelockArbitrator: already unlocked");
        unlocked[escrowId] = true;
        emit Unlock(escrowId, recipientHybridPk);
    }
}
