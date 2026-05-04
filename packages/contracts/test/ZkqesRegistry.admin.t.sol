// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { ZkqesRegistry } from "../src/ZkqesRegistry.sol";
import { IGroth16VerifierV2 } from "../src/ZkqesVerifierV2.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

contract ZkqesRegistryAdminTest is Test {
    ZkqesRegistry internal registry;
    StubGroth16Verifier internal verifier;

    address internal constant ADMIN = address(0xA11CE);
    address internal constant ALICE = address(0xB0B);
    bytes32 internal constant INITIAL_ROOT = bytes32(uint256(0xC0FFEE));

    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event VerifierUpdated(uint8 indexed algorithmTag, address oldVerifier, address newVerifier);

    StubGroth16Verifier internal rsa;
    StubGroth16Verifier internal ecdsa;

    function setUp() public {
        verifier = new StubGroth16Verifier();
        rsa = verifier; // alias for RSA slot
        ecdsa = new StubGroth16Verifier();
        registry = new ZkqesRegistry(
            IGroth16VerifierV2(address(rsa)),
            IGroth16VerifierV2(address(ecdsa)),
            INITIAL_ROOT,
            ADMIN
        );
    }

    function test_constructor_initialState() public view {
        assertEq(registry.admin(), ADMIN);
        assertEq(registry.trustedListRoot(), INITIAL_ROOT);
        assertEq(address(registry.rsaVerifier()), address(rsa));
        assertEq(address(registry.ecdsaVerifier()), address(ecdsa));
    }

    function test_constructor_revertsOnZeroAdmin() public {
        vm.expectRevert(ZkqesRegistry.ZeroAddress.selector);
        new ZkqesRegistry(
            IGroth16VerifierV2(address(rsa)),
            IGroth16VerifierV2(address(ecdsa)),
            INITIAL_ROOT,
            address(0)
        );
    }

    function test_constructor_revertsOnZeroRsaVerifier() public {
        vm.expectRevert(ZkqesRegistry.ZeroAddress.selector);
        new ZkqesRegistry(
            IGroth16VerifierV2(address(0)),
            IGroth16VerifierV2(address(ecdsa)),
            INITIAL_ROOT,
            ADMIN
        );
    }

    function test_constructor_revertsOnZeroEcdsaVerifier() public {
        vm.expectRevert(ZkqesRegistry.ZeroAddress.selector);
        new ZkqesRegistry(
            IGroth16VerifierV2(address(rsa)),
            IGroth16VerifierV2(address(0)),
            INITIAL_ROOT,
            ADMIN
        );
    }

    function test_updateTrustedListRoot_onlyAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(ZkqesRegistry.NotAdmin.selector);
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
        vm.expectRevert(ZkqesRegistry.NotAdmin.selector);
        registry.setAdmin(ALICE);
    }

    function test_setAdmin_revertsOnZero() public {
        vm.prank(ADMIN);
        vm.expectRevert(ZkqesRegistry.ZeroAddress.selector);
        registry.setAdmin(address(0));
    }

    function test_setAdmin_transfersAuthorityAndEmits() public {
        vm.expectEmit(true, true, false, false, address(registry));
        emit AdminTransferred(ADMIN, ALICE);
        vm.prank(ADMIN);
        registry.setAdmin(ALICE);
        assertEq(registry.admin(), ALICE);

        vm.prank(ADMIN);
        vm.expectRevert(ZkqesRegistry.NotAdmin.selector);
        registry.updateTrustedListRoot(bytes32(uint256(2)));

        vm.prank(ALICE);
        registry.updateTrustedListRoot(bytes32(uint256(3)));
        assertEq(registry.trustedListRoot(), bytes32(uint256(3)));
    }

    function test_setRsaVerifier_onlyAdmin() public {
        StubGroth16Verifier newV = new StubGroth16Verifier();
        vm.prank(ALICE);
        vm.expectRevert(ZkqesRegistry.NotAdmin.selector);
        registry.setRsaVerifier(IGroth16VerifierV2(address(newV)));
    }

    function test_setRsaVerifier_revertsOnZero() public {
        vm.prank(ADMIN);
        vm.expectRevert(ZkqesRegistry.ZeroAddress.selector);
        registry.setRsaVerifier(IGroth16VerifierV2(address(0)));
    }

    function test_setRsaVerifier_rotatesAndEmits() public {
        StubGroth16Verifier newV = new StubGroth16Verifier();
        vm.expectEmit(true, false, false, true, address(registry));
        emit VerifierUpdated(0, address(rsa), address(newV));
        vm.prank(ADMIN);
        registry.setRsaVerifier(IGroth16VerifierV2(address(newV)));
        assertEq(address(registry.rsaVerifier()), address(newV));
    }

    function test_setEcdsaVerifier_onlyAdmin() public {
        StubGroth16Verifier newV = new StubGroth16Verifier();
        vm.prank(ALICE);
        vm.expectRevert(ZkqesRegistry.NotAdmin.selector);
        registry.setEcdsaVerifier(IGroth16VerifierV2(address(newV)));
    }

    function test_setEcdsaVerifier_revertsOnZero() public {
        vm.prank(ADMIN);
        vm.expectRevert(ZkqesRegistry.ZeroAddress.selector);
        registry.setEcdsaVerifier(IGroth16VerifierV2(address(0)));
    }

    function test_setEcdsaVerifier_rotatesAndEmits() public {
        StubGroth16Verifier newV = new StubGroth16Verifier();
        vm.expectEmit(true, false, false, true, address(registry));
        emit VerifierUpdated(1, address(ecdsa), address(newV));
        vm.prank(ADMIN);
        registry.setEcdsaVerifier(IGroth16VerifierV2(address(newV)));
        assertEq(address(registry.ecdsaVerifier()), address(newV));
    }
}
