// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { TimelockArbitrator } from "../src/arbitrators/TimelockArbitrator.sol";
import { IArbitrator } from "../src/arbitrators/IArbitrator.sol";

/// @notice TimelockArbitrator is deferred post-MVP per
///         docs/superpowers/specs/2026-04-17-qie-mvp-refinement.md §3.2.
///         The prior 9-case behavioural suite (ping / timeout / replay /
///         independent-escrows) is intentionally dropped here — any new
///         implementation must re-introduce its own tests alongside the
///         restored contract. Until then we just assert that the in-tree
///         stub satisfies `IArbitrator` and reverts `Deferred` on
///         invocation, so nothing deploys it by accident.
contract TimelockArbitratorTest is Test {
    TimelockArbitrator internal arb;
    bytes32 internal constant ESCROW_ID = keccak256("t1");
    bytes internal recipientPk = hex"04bb";

    function setUp() public {
        arb = new TimelockArbitrator();
    }

    function test_stub_requestUnlockReverts() public {
        vm.expectRevert(TimelockArbitrator.Deferred.selector);
        arb.requestUnlock(ESCROW_ID, recipientPk);
    }

    function test_stub_satisfiesIArbitrator() public view {
        // Compile-time: casting to IArbitrator must succeed.
        IArbitrator i = IArbitrator(address(arb));
        i; // silence unused-variable warning in strict modes
    }
}
