// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { QKBRegistryV3 } from "../src/QKBRegistryV3.sol";
import {
    IGroth16LeafVerifier,
    IGroth16ChainVerifier
} from "../src/QKBVerifier.sol";
import {
    StubGroth16LeafVerifier,
    StubGroth16ChainVerifier
} from "./helpers/StubSplitVerifiers.sol";

contract QKBRegistryV3AdminTest is Test {
    QKBRegistryV3 internal registry;

    StubGroth16LeafVerifier  internal rsaLeaf;
    StubGroth16ChainVerifier internal rsaChain;
    StubGroth16LeafVerifier  internal ecdsaLeaf;
    StubGroth16ChainVerifier internal ecdsaChain;

    address internal constant ADMIN = address(0xA11CE);
    address internal constant ALICE = address(0xB0B);
    bytes32 internal constant INITIAL_ROOT = bytes32(uint256(0xC0FFEE));

    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event VerifierUpdated(
        uint8 indexed algorithmTag,
        bool  indexed isLeaf,
        address oldVerifier,
        address newVerifier
    );

    function setUp() public {
        rsaLeaf    = new StubGroth16LeafVerifier();
        rsaChain   = new StubGroth16ChainVerifier();
        ecdsaLeaf  = new StubGroth16LeafVerifier();
        ecdsaChain = new StubGroth16ChainVerifier();
        registry   = new QKBRegistryV3(
            IGroth16LeafVerifier(address(rsaLeaf)),
            IGroth16ChainVerifier(address(rsaChain)),
            IGroth16LeafVerifier(address(ecdsaLeaf)),
            IGroth16ChainVerifier(address(ecdsaChain)),
            INITIAL_ROOT,
            ADMIN
        );
    }

    // ----- Constructor ------------------------------------------------------

    function test_constructor_initialState() public view {
        assertEq(registry.admin(), ADMIN);
        assertEq(registry.trustedListRoot(), INITIAL_ROOT);
        assertEq(address(registry.rsaLeafVerifier()),    address(rsaLeaf));
        assertEq(address(registry.rsaChainVerifier()),   address(rsaChain));
        assertEq(address(registry.ecdsaLeafVerifier()),  address(ecdsaLeaf));
        assertEq(address(registry.ecdsaChainVerifier()), address(ecdsaChain));
    }

    function test_constructor_revertsOnZeroRsaLeaf() public {
        vm.expectRevert(QKBRegistryV3.ZeroAddress.selector);
        new QKBRegistryV3(
            IGroth16LeafVerifier(address(0)),
            IGroth16ChainVerifier(address(rsaChain)),
            IGroth16LeafVerifier(address(ecdsaLeaf)),
            IGroth16ChainVerifier(address(ecdsaChain)),
            INITIAL_ROOT,
            ADMIN
        );
    }

    function test_constructor_revertsOnZeroRsaChain() public {
        vm.expectRevert(QKBRegistryV3.ZeroAddress.selector);
        new QKBRegistryV3(
            IGroth16LeafVerifier(address(rsaLeaf)),
            IGroth16ChainVerifier(address(0)),
            IGroth16LeafVerifier(address(ecdsaLeaf)),
            IGroth16ChainVerifier(address(ecdsaChain)),
            INITIAL_ROOT,
            ADMIN
        );
    }

    function test_constructor_revertsOnZeroEcdsaLeaf() public {
        vm.expectRevert(QKBRegistryV3.ZeroAddress.selector);
        new QKBRegistryV3(
            IGroth16LeafVerifier(address(rsaLeaf)),
            IGroth16ChainVerifier(address(rsaChain)),
            IGroth16LeafVerifier(address(0)),
            IGroth16ChainVerifier(address(ecdsaChain)),
            INITIAL_ROOT,
            ADMIN
        );
    }

    function test_constructor_revertsOnZeroEcdsaChain() public {
        vm.expectRevert(QKBRegistryV3.ZeroAddress.selector);
        new QKBRegistryV3(
            IGroth16LeafVerifier(address(rsaLeaf)),
            IGroth16ChainVerifier(address(rsaChain)),
            IGroth16LeafVerifier(address(ecdsaLeaf)),
            IGroth16ChainVerifier(address(0)),
            INITIAL_ROOT,
            ADMIN
        );
    }

    function test_constructor_revertsOnZeroAdmin() public {
        vm.expectRevert(QKBRegistryV3.ZeroAddress.selector);
        new QKBRegistryV3(
            IGroth16LeafVerifier(address(rsaLeaf)),
            IGroth16ChainVerifier(address(rsaChain)),
            IGroth16LeafVerifier(address(ecdsaLeaf)),
            IGroth16ChainVerifier(address(ecdsaChain)),
            INITIAL_ROOT,
            address(0)
        );
    }

    // ----- Root rotation ----------------------------------------------------

    function test_updateTrustedListRoot_onlyAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(QKBRegistryV3.NotAdmin.selector);
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

    // ----- Admin transfer ---------------------------------------------------

    function test_setAdmin_onlyAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(QKBRegistryV3.NotAdmin.selector);
        registry.setAdmin(ALICE);
    }

    function test_setAdmin_revertsOnZero() public {
        vm.prank(ADMIN);
        vm.expectRevert(QKBRegistryV3.ZeroAddress.selector);
        registry.setAdmin(address(0));
    }

    function test_setAdmin_transfersAuthorityAndEmits() public {
        vm.expectEmit(true, true, false, false, address(registry));
        emit AdminTransferred(ADMIN, ALICE);
        vm.prank(ADMIN);
        registry.setAdmin(ALICE);
        assertEq(registry.admin(), ALICE);

        // Old admin no longer authoritative.
        vm.prank(ADMIN);
        vm.expectRevert(QKBRegistryV3.NotAdmin.selector);
        registry.updateTrustedListRoot(bytes32(uint256(2)));

        // New admin can rotate root.
        vm.prank(ALICE);
        registry.updateTrustedListRoot(bytes32(uint256(3)));
        assertEq(registry.trustedListRoot(), bytes32(uint256(3)));
    }

    // ----- setRsaLeafVerifier ----------------------------------------------

    function test_setRsaLeafVerifier_onlyAdmin() public {
        StubGroth16LeafVerifier newV = new StubGroth16LeafVerifier();
        vm.prank(ALICE);
        vm.expectRevert(QKBRegistryV3.NotAdmin.selector);
        registry.setRsaLeafVerifier(IGroth16LeafVerifier(address(newV)));
    }

    function test_setRsaLeafVerifier_revertsOnZero() public {
        vm.prank(ADMIN);
        vm.expectRevert(QKBRegistryV3.ZeroAddress.selector);
        registry.setRsaLeafVerifier(IGroth16LeafVerifier(address(0)));
    }

    function test_setRsaLeafVerifier_rotatesAndEmits() public {
        StubGroth16LeafVerifier newV = new StubGroth16LeafVerifier();
        vm.expectEmit(true, true, false, true, address(registry));
        emit VerifierUpdated(0, true, address(rsaLeaf), address(newV));
        vm.prank(ADMIN);
        registry.setRsaLeafVerifier(IGroth16LeafVerifier(address(newV)));
        assertEq(address(registry.rsaLeafVerifier()), address(newV));
    }

    // ----- setRsaChainVerifier ---------------------------------------------

    function test_setRsaChainVerifier_onlyAdmin() public {
        StubGroth16ChainVerifier newV = new StubGroth16ChainVerifier();
        vm.prank(ALICE);
        vm.expectRevert(QKBRegistryV3.NotAdmin.selector);
        registry.setRsaChainVerifier(IGroth16ChainVerifier(address(newV)));
    }

    function test_setRsaChainVerifier_revertsOnZero() public {
        vm.prank(ADMIN);
        vm.expectRevert(QKBRegistryV3.ZeroAddress.selector);
        registry.setRsaChainVerifier(IGroth16ChainVerifier(address(0)));
    }

    function test_setRsaChainVerifier_rotatesAndEmits() public {
        StubGroth16ChainVerifier newV = new StubGroth16ChainVerifier();
        vm.expectEmit(true, true, false, true, address(registry));
        emit VerifierUpdated(0, false, address(rsaChain), address(newV));
        vm.prank(ADMIN);
        registry.setRsaChainVerifier(IGroth16ChainVerifier(address(newV)));
        assertEq(address(registry.rsaChainVerifier()), address(newV));
    }

    // ----- setEcdsaLeafVerifier --------------------------------------------

    function test_setEcdsaLeafVerifier_onlyAdmin() public {
        StubGroth16LeafVerifier newV = new StubGroth16LeafVerifier();
        vm.prank(ALICE);
        vm.expectRevert(QKBRegistryV3.NotAdmin.selector);
        registry.setEcdsaLeafVerifier(IGroth16LeafVerifier(address(newV)));
    }

    function test_setEcdsaLeafVerifier_revertsOnZero() public {
        vm.prank(ADMIN);
        vm.expectRevert(QKBRegistryV3.ZeroAddress.selector);
        registry.setEcdsaLeafVerifier(IGroth16LeafVerifier(address(0)));
    }

    function test_setEcdsaLeafVerifier_rotatesAndEmits() public {
        StubGroth16LeafVerifier newV = new StubGroth16LeafVerifier();
        vm.expectEmit(true, true, false, true, address(registry));
        emit VerifierUpdated(1, true, address(ecdsaLeaf), address(newV));
        vm.prank(ADMIN);
        registry.setEcdsaLeafVerifier(IGroth16LeafVerifier(address(newV)));
        assertEq(address(registry.ecdsaLeafVerifier()), address(newV));
    }

    // ----- setEcdsaChainVerifier -------------------------------------------

    function test_setEcdsaChainVerifier_onlyAdmin() public {
        StubGroth16ChainVerifier newV = new StubGroth16ChainVerifier();
        vm.prank(ALICE);
        vm.expectRevert(QKBRegistryV3.NotAdmin.selector);
        registry.setEcdsaChainVerifier(IGroth16ChainVerifier(address(newV)));
    }

    function test_setEcdsaChainVerifier_revertsOnZero() public {
        vm.prank(ADMIN);
        vm.expectRevert(QKBRegistryV3.ZeroAddress.selector);
        registry.setEcdsaChainVerifier(IGroth16ChainVerifier(address(0)));
    }

    function test_setEcdsaChainVerifier_rotatesAndEmits() public {
        StubGroth16ChainVerifier newV = new StubGroth16ChainVerifier();
        vm.expectEmit(true, true, false, true, address(registry));
        emit VerifierUpdated(1, false, address(ecdsaChain), address(newV));
        vm.prank(ADMIN);
        registry.setEcdsaChainVerifier(IGroth16ChainVerifier(address(newV)));
        assertEq(address(registry.ecdsaChainVerifier()), address(newV));
    }
}
