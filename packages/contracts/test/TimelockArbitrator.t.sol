// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { TimelockArbitrator } from "../src/arbitrators/TimelockArbitrator.sol";
import { IArbitrator } from "../src/arbitrators/IArbitrator.sol";

contract TimelockArbitratorTest is Test {
    TimelockArbitrator internal arb;
    address internal constant HOLDER = address(0xABCD);
    uint256 internal constant TIMEOUT = 30 days;
    bytes32 internal constant ESCROW_ID = keccak256("t1");
    bytes internal recipientPk = hex"04bb";

    event Unlock(bytes32 indexed escrowId, bytes recipientHybridPk);

    function setUp() public {
        vm.warp(1_700_000_000);
        arb = new TimelockArbitrator(HOLDER, TIMEOUT);
    }

    function test_constructor_revertsOnZeroHolder() public {
        vm.expectRevert(bytes("TimelockArbitrator: zero holder"));
        new TimelockArbitrator(address(0), TIMEOUT);
    }

    function test_constructor_revertsOnZeroTimeout() public {
        vm.expectRevert(bytes("TimelockArbitrator: zero timeout"));
        new TimelockArbitrator(HOLDER, 0);
    }

    function test_constructor_setsLastPingToNow() public view {
        assertEq(arb.lastPing(), block.timestamp);
        assertEq(arb.holderPing(), HOLDER);
        assertEq(arb.timeoutSeconds(), TIMEOUT);
    }

    function test_earlyUnlockReverts() public {
        vm.expectRevert(bytes("TimelockArbitrator: timeout not elapsed"));
        arb.requestUnlock(ESCROW_ID, recipientPk);
    }

    function test_pingFromOtherReverts() public {
        vm.expectRevert(bytes("TimelockArbitrator: not holder"));
        arb.ping();
    }

    function test_pingResetsTimer() public {
        // Advance near the expiry boundary, holder pings, then verify the
        // timer truly reset by failing to unlock immediately after.
        vm.warp(block.timestamp + TIMEOUT - 1);
        vm.prank(HOLDER);
        arb.ping();
        // One second after the ping — nowhere near TIMEOUT elapsed.
        vm.warp(block.timestamp + 1);
        vm.expectRevert(bytes("TimelockArbitrator: timeout not elapsed"));
        arb.requestUnlock(ESCROW_ID, recipientPk);
    }

    function test_unlockAfterTimeoutEmits() public {
        vm.warp(block.timestamp + TIMEOUT + 1);
        vm.expectEmit(true, false, false, true, address(arb));
        emit Unlock(ESCROW_ID, recipientPk);
        arb.requestUnlock(ESCROW_ID, recipientPk);
        assertTrue(arb.unlocked(ESCROW_ID));
    }

    function test_doubleUnlockReverts() public {
        vm.warp(block.timestamp + TIMEOUT + 1);
        arb.requestUnlock(ESCROW_ID, recipientPk);
        vm.expectRevert(bytes("TimelockArbitrator: already unlocked"));
        arb.requestUnlock(ESCROW_ID, recipientPk);
    }

    function test_independentEscrowIdsCanEachUnlock() public {
        vm.warp(block.timestamp + TIMEOUT + 1);
        arb.requestUnlock(ESCROW_ID, recipientPk);
        bytes32 other = keccak256("t2");
        vm.expectEmit(true, false, false, true, address(arb));
        emit Unlock(other, recipientPk);
        arb.requestUnlock(other, recipientPk);
    }
}
