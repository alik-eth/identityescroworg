// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {QKBRegistryV5, IGroth16VerifierV5_1} from "../src/QKBRegistryV5.sol";
import {Groth16VerifierV5_1Placeholder} from "../src/Groth16VerifierV5_1Placeholder.sol";

/// @notice §6.1 skeleton tests — constructor, IQKBRegistry view fns, admin
/// surface. The full 5-gate register() body and its negative tests land
/// in §6.2..§6.7 with their own commits.
contract QKBRegistryV5SkeletonTest is Test {
    QKBRegistryV5 internal registry;
    Groth16VerifierV5_1Placeholder internal verifier;

    address internal admin = address(0xA1);
    bytes32 internal initialTrustRoot  = bytes32(uint256(0xA));
    bytes32 internal initialPolicyRoot = bytes32(uint256(0xB));

    function setUp() public {
        verifier = new Groth16VerifierV5_1Placeholder();
        registry = new QKBRegistryV5(
            IGroth16VerifierV5_1(address(verifier)),
            admin,
            initialTrustRoot,
            initialPolicyRoot
        );
    }

    /* --- constructor --- */

    function test_constructor_setsImmutables() public view {
        assertEq(address(registry.groth16Verifier()), address(verifier), "verifier");
        assertEq(registry.admin(), admin, "admin");
        assertEq(registry.trustedListRoot(), initialTrustRoot, "trustRoot");
        assertEq(registry.policyRoot(), initialPolicyRoot, "policyRoot");
    }

    function test_constructor_deploysPoseidonContracts() public view {
        address t3 = registry.poseidonT3();
        address t7 = registry.poseidonT7();
        assertTrue(t3 != address(0), "t3 deployed");
        assertTrue(t7 != address(0), "t7 deployed");
        assertTrue(t3 != t7, "t3 != t7");
        // Each Poseidon contract has non-empty runtime bytecode.
        assertGt(t3.code.length, 0, "t3 has code");
        assertGt(t7.code.length, 0, "t7 has code");
    }

    function test_constructor_revertsOnZeroVerifier() public {
        vm.expectRevert(QKBRegistryV5.ZeroAddress.selector);
        new QKBRegistryV5(IGroth16VerifierV5_1(address(0)), admin, initialTrustRoot, initialPolicyRoot);
    }

    function test_constructor_revertsOnZeroAdmin() public {
        vm.expectRevert(QKBRegistryV5.ZeroAddress.selector);
        new QKBRegistryV5(
            IGroth16VerifierV5_1(address(verifier)),
            address(0),
            initialTrustRoot,
            initialPolicyRoot
        );
    }

    /* --- IQKBRegistry view fns --- */

    function test_isVerified_falseBeforeRegister() public view {
        assertFalse(registry.isVerified(address(this)));
        assertFalse(registry.isVerified(address(0xBEEF)));
    }

    function test_nullifierOf_zeroBeforeRegister() public view {
        assertEq(registry.nullifierOf(address(this)), bytes32(0));
    }

    /* --- admin: setTrustedListRoot --- */

    function test_setTrustedListRoot_updatesAndEmits() public {
        bytes32 newRoot = bytes32(uint256(0xC0FFEE));
        vm.expectEmit(true, true, false, true);
        emit QKBRegistryV5.TrustedListRootRotated(initialTrustRoot, newRoot, admin);
        vm.prank(admin);
        registry.setTrustedListRoot(newRoot);
        assertEq(registry.trustedListRoot(), newRoot);
    }

    function test_setTrustedListRoot_onlyAdmin() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(QKBRegistryV5.OnlyAdmin.selector);
        registry.setTrustedListRoot(bytes32(uint256(0xC)));
    }

    /* --- admin: setPolicyRoot --- */

    function test_setPolicyRoot_updatesAndEmits() public {
        bytes32 newRoot = bytes32(uint256(0xD00D));
        vm.expectEmit(true, true, false, true);
        emit QKBRegistryV5.PolicyRootRotated(initialPolicyRoot, newRoot, admin);
        vm.prank(admin);
        registry.setPolicyRoot(newRoot);
        assertEq(registry.policyRoot(), newRoot);
    }

    function test_setPolicyRoot_onlyAdmin() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(QKBRegistryV5.OnlyAdmin.selector);
        registry.setPolicyRoot(bytes32(uint256(0xC)));
    }

    /* --- admin: transferAdmin --- */

    function test_transferAdmin_updatesAndEmits() public {
        address newAdmin = address(0xA2);
        vm.expectEmit(true, true, false, false);
        emit QKBRegistryV5.AdminTransferred(admin, newAdmin);
        vm.prank(admin);
        registry.transferAdmin(newAdmin);
        assertEq(registry.admin(), newAdmin);
    }

    function test_transferAdmin_onlyAdmin() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(QKBRegistryV5.OnlyAdmin.selector);
        registry.transferAdmin(address(0xA2));
    }

    function test_transferAdmin_revertsOnZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(QKBRegistryV5.ZeroAddress.selector);
        registry.transferAdmin(address(0));
    }

    /* --- IQKBRegistry interface compatibility (V4↔V5 ABI stability) --- */

    function test_iqkbregistry_interface_callable() public view {
        // Smoke: each of the three IQKBRegistry view fns is callable on
        // QKBRegistryV5 with the V4 ABI shape. Returns are zero-valued
        // pre-registration; this test will fail only if the interface
        // shape drifts between V4 and V5 (the SDK's `Verified` modifier
        // depends on this contract).
        registry.isVerified(address(this));
        registry.nullifierOf(address(this));
        registry.trustedListRoot();
    }
}
