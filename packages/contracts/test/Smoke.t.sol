// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";

contract SmokeTest is Test {
    function test_smoke() public pure {
        assertEq(uint256(1) + uint256(1), uint256(2));
    }
}
