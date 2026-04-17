// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { IArbitrator } from "../src/arbitrators/IArbitrator.sol";

/// @notice Sanity that the `Unlock` event topic matches the off-chain
///         evaluator's expected constant. If this ever breaks it means the
///         event signature drifted and the off-chain agent will stop seeing
///         unlocks — a silent failure mode we refuse to ship.
contract ArbitratorEventTest is Test {
    function test_unlockTopicMatchesCanonicalSignature() public pure {
        bytes32 expected = keccak256("Unlock(bytes32,bytes)");
        assertEq(expected, IArbitrator.Unlock.selector);
    }
}
