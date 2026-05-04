// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import { Verified, IZkqesRegistry } from "../src/Verified.sol";
import { MockRegistry } from "./mocks/MockRegistry.sol";

contract Gated is Verified {
    uint256 public counter;
    constructor(IZkqesRegistry r) Verified(r) {}
    function bump() external onlyVerifiedUkrainian { counter++; }
}

contract VerifiedTest is Test {
    MockRegistry r;
    Gated        g;
    address constant ALICE = address(0xA11CE);

    function setUp() public {
        r = new MockRegistry();
        g = new Gated(IZkqesRegistry(address(r)));
    }

    function test_modifier_passesForVerifiedCaller() public {
        r.set(ALICE, bytes32(uint256(1)));
        vm.prank(ALICE);
        g.bump();
        assertEq(g.counter(), 1);
    }

    function test_modifier_revertsForUnverifiedCaller() public {
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Verified.NotVerifiedUkrainian.selector, ALICE));
        g.bump();
    }

    function test_zkqesRegistry_publicGetterReturnsAddress() public view {
        assertEq(address(g.zkqesRegistry()), address(r));
    }
}
