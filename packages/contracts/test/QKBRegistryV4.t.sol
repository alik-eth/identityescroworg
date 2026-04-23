// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import { QKBRegistryV4 } from "../src/QKBRegistryV4.sol";

contract QKBRegistryV4Test is Test {
    function test_constructor_stores_country_and_roots() public {
        QKBRegistryV4 r = new QKBRegistryV4({
            country_: "UA",
            trustedListRoot_: bytes32(uint256(0x123)),
            policyRoot_: bytes32(uint256(0x456)),
            leafVerifier_: address(0x1111),
            chainVerifier_: address(0x2222),
            ageVerifier_: address(0x3333),
            admin_: address(this)
        });
        assertEq(r.country(), "UA");
        assertEq(r.trustedListRoot(), bytes32(uint256(0x123)));
        assertEq(r.policyRoot(), bytes32(uint256(0x456)));
        assertEq(address(r.leafVerifier()), address(0x1111));
        assertEq(address(r.chainVerifier()), address(0x2222));
        assertEq(address(r.ageVerifier()), address(0x3333));
        assertEq(r.admin(), address(this));
    }
}
