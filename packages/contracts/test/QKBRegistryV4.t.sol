// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import { QKBRegistryV4 } from "../src/QKBRegistryV4.sol";

contract QKBRegistryV4Test is Test {
    event TrustedListRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event PolicyRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    event VerifierUpdated(bytes32 indexed kind, address oldV, address newV);
    event AdminTransferred(address oldAdmin, address newAdmin);

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

    function test_admin_rotates_trusted_list_root() public {
        QKBRegistryV4 r = _deploy();
        vm.expectEmit();
        emit TrustedListRootUpdated(bytes32(uint256(0x123)), bytes32(uint256(0x999)));
        r.setTrustedListRoot(bytes32(uint256(0x999)));
        assertEq(r.trustedListRoot(), bytes32(uint256(0x999)));
    }

    function test_non_admin_cannot_rotate() public {
        QKBRegistryV4 r = _deploy();
        vm.prank(address(0xBEEF));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setTrustedListRoot(bytes32(uint256(0x999)));
    }

    function test_admin_rotates_policy_root() public {
        QKBRegistryV4 r = _deploy();
        vm.expectEmit();
        emit PolicyRootUpdated(bytes32(uint256(0x456)), bytes32(uint256(0xAAA)));
        r.setPolicyRoot(bytes32(uint256(0xAAA)));
        assertEq(r.policyRoot(), bytes32(uint256(0xAAA)));
    }

    function test_non_admin_cannot_rotate_policy_root() public {
        QKBRegistryV4 r = _deploy();
        vm.prank(address(0xBEEF));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setPolicyRoot(bytes32(uint256(0xAAA)));
    }

    function test_admin_rotates_leaf_verifier() public {
        QKBRegistryV4 r = _deploy();
        vm.expectEmit(true, false, false, true);
        emit VerifierUpdated(keccak256("leaf"), address(0x1111), address(0x4444));
        r.setLeafVerifier(address(0x4444));
        assertEq(address(r.leafVerifier()), address(0x4444));
    }

    function test_admin_rotates_chain_verifier() public {
        QKBRegistryV4 r = _deploy();
        vm.expectEmit(true, false, false, true);
        emit VerifierUpdated(keccak256("chain"), address(0x2222), address(0x5555));
        r.setChainVerifier(address(0x5555));
        assertEq(address(r.chainVerifier()), address(0x5555));
    }

    function test_admin_rotates_age_verifier() public {
        QKBRegistryV4 r = _deploy();
        vm.expectEmit(true, false, false, true);
        emit VerifierUpdated(keccak256("age"), address(0x3333), address(0x6666));
        r.setAgeVerifier(address(0x6666));
        assertEq(address(r.ageVerifier()), address(0x6666));
    }

    function test_non_admin_cannot_rotate_verifiers() public {
        QKBRegistryV4 r = _deploy();
        vm.startPrank(address(0xBEEF));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setLeafVerifier(address(0x4444));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setChainVerifier(address(0x5555));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setAgeVerifier(address(0x6666));
        vm.stopPrank();
    }

    function test_setAdmin_transfers() public {
        QKBRegistryV4 r = _deploy();
        address newAdmin = address(0xCAFE);
        vm.expectEmit();
        emit AdminTransferred(address(this), newAdmin);
        r.setAdmin(newAdmin);
        assertEq(r.admin(), newAdmin);
    }

    function test_non_admin_cannot_setAdmin() public {
        QKBRegistryV4 r = _deploy();
        vm.prank(address(0xBEEF));
        vm.expectRevert(QKBRegistryV4.OnlyAdmin.selector);
        r.setAdmin(address(0xCAFE));
    }

    function _deploy() private returns (QKBRegistryV4) {
        return new QKBRegistryV4({
            country_: "UA",
            trustedListRoot_: bytes32(uint256(0x123)),
            policyRoot_: bytes32(uint256(0x456)),
            leafVerifier_: address(0x1111),
            chainVerifier_: address(0x2222),
            ageVerifier_: address(0x3333),
            admin_: address(this)
        });
    }
}
