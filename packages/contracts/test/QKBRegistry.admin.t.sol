// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { IGroth16Verifier } from "../src/QKBVerifier.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

contract QKBRegistryAdminTest is Test {
    QKBRegistry internal registry;
    StubGroth16Verifier internal stub;

    address internal constant ADMIN = address(0xA11CE);
    address internal constant ALICE = address(0xB0B);
    bytes32 internal constant INITIAL_ROOT = bytes32(uint256(0xC0FFEE));

    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    function setUp() public {
        stub = new StubGroth16Verifier();
        registry = new QKBRegistry(IGroth16Verifier(address(stub)), INITIAL_ROOT, ADMIN);
    }

    function test_constructor_initialState() public view {
        assertEq(registry.admin(), ADMIN);
        assertEq(registry.trustedListRoot(), INITIAL_ROOT);
        assertEq(address(registry.verifier()), address(stub));
    }

    function test_constructor_revertsOnZeroAdmin() public {
        vm.expectRevert(QKBRegistry.ZeroAddress.selector);
        new QKBRegistry(IGroth16Verifier(address(stub)), INITIAL_ROOT, address(0));
    }

    function test_constructor_revertsOnZeroVerifier() public {
        vm.expectRevert(QKBRegistry.ZeroAddress.selector);
        new QKBRegistry(IGroth16Verifier(address(0)), INITIAL_ROOT, ADMIN);
    }

    function test_updateTrustedListRoot_onlyAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(QKBRegistry.NotAdmin.selector);
        registry.updateTrustedListRoot(bytes32(uint256(1)));
    }

    function test_updateTrustedListRoot_emitsEventAndStores() public {
        bytes32 newRoot = bytes32(uint256(0xDEAD));
        vm.expectEmit(false, false, false, true, address(registry));
        emit TrustedListRootUpdated(INITIAL_ROOT, newRoot);
        vm.prank(ADMIN);
        registry.updateTrustedListRoot(newRoot);
        assertEq(registry.trustedListRoot(), newRoot);
    }

    function test_setAdmin_onlyAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(QKBRegistry.NotAdmin.selector);
        registry.setAdmin(ALICE);
    }

    function test_setAdmin_revertsOnZero() public {
        vm.prank(ADMIN);
        vm.expectRevert(QKBRegistry.ZeroAddress.selector);
        registry.setAdmin(address(0));
    }

    function test_setAdmin_transfersAuthorityAndEmits() public {
        vm.expectEmit(true, true, false, false, address(registry));
        emit AdminTransferred(ADMIN, ALICE);
        vm.prank(ADMIN);
        registry.setAdmin(ALICE);
        assertEq(registry.admin(), ALICE);

        // Old admin can no longer rotate root.
        vm.prank(ADMIN);
        vm.expectRevert(QKBRegistry.NotAdmin.selector);
        registry.updateTrustedListRoot(bytes32(uint256(2)));

        // New admin can.
        vm.prank(ALICE);
        registry.updateTrustedListRoot(bytes32(uint256(3)));
        assertEq(registry.trustedListRoot(), bytes32(uint256(3)));
    }
}
