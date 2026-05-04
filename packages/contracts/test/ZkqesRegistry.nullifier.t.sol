// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { ZkqesRegistry } from "../src/ZkqesRegistry.sol";
import { ZkqesVerifierV2, IGroth16VerifierV2 } from "../src/ZkqesVerifierV2.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

/// @notice Sprint 0 §14.4 nullifier primitive coverage.
///         - Uniqueness: duplicate nullifier reverts even on a fresh pk.
///         - Storage: usedNullifiers + nullifierToPk written on success.
///         - Revocation: admin-only, requires non-zero reasonHash, flips
///           isActiveAt from true to false for the mapped binding.
contract ZkqesRegistryNullifierTest is Test {
    ZkqesRegistry internal registry;
    StubGroth16Verifier internal rsa;
    StubGroth16Verifier internal ecdsa;

    address internal constant ADMIN = address(0xA11CE);
    address internal constant ALICE = address(0xB0B);
    bytes32 internal constant INITIAL_ROOT = bytes32(uint256(0xC0FFEE));

    // secp256k1 G (priv=1).
    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    // 2G (priv=2).
    uint256 internal constant GX2 = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5;
    uint256 internal constant GY2 = 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A;

    bytes32 internal constant CTX_HASH = bytes32(uint256(0xA1));
    bytes32 internal constant NULLIFIER_A = bytes32(uint256(0xBEEF));
    bytes32 internal constant NULLIFIER_B = bytes32(uint256(0xCAFE));
    bytes32 internal constant REASON = bytes32(uint256(0x1234));

    event NullifierRevoked(bytes32 indexed nullifier, address indexed pkAddr, bytes32 reasonHash);

    function setUp() public {
        rsa = new StubGroth16Verifier();
        ecdsa = new StubGroth16Verifier();
        registry = new ZkqesRegistry(
            IGroth16VerifierV2(address(rsa)),
            IGroth16VerifierV2(address(ecdsa)),
            INITIAL_ROOT,
            ADMIN
        );
        vm.warp(1_700_000_000);
    }

    function _splitToLimbsLE(uint256 v) internal pure returns (uint256[4] memory out) {
        out[0] = v & type(uint64).max;
        out[1] = (v >> 64) & type(uint64).max;
        out[2] = (v >> 128) & type(uint64).max;
        out[3] = (v >> 192) & type(uint64).max;
    }

    function _inputsFor(uint256 x, uint256 y, bytes32 nullifier) internal view returns (ZkqesVerifierV2.Inputs memory i) {
        i.pkX = _splitToLimbsLE(x);
        i.pkY = _splitToLimbsLE(y);
        i.ctxHash = CTX_HASH;
        i.rTL = INITIAL_ROOT;
        i.declHash = DeclarationHashes.EN;
        i.timestamp = uint64(block.timestamp);
        i.algorithmTag = 1;
        i.nullifier = nullifier;
    }

    function _proof() internal pure returns (ZkqesVerifierV2.Proof memory p) {}

    // ---- uniqueness + storage ------------------------------------------------

    function test_register_storesUsedNullifierAndMapping() public {
        ZkqesVerifierV2.Inputs memory i = _inputsFor(GX, GY, NULLIFIER_A);
        registry.register(_proof(), i);

        assertTrue(registry.usedNullifiers(NULLIFIER_A));
        assertEq(registry.nullifierToPk(NULLIFIER_A), vm.addr(1));
    }

    function test_register_duplicateNullifierOnDifferentPkReverts() public {
        // First Holder registers with nullifier A.
        registry.register(_proof(), _inputsFor(GX, GY, NULLIFIER_A));

        // Second Holder uses a fresh pk (priv=2) but submits the SAME
        // nullifier — simulating a Sybil attempt by the same cert subject
        // against the same ctxHash. Must revert even though the pk is new.
        ZkqesVerifierV2.Inputs memory i2 = _inputsFor(GX2, GY2, NULLIFIER_A);
        vm.expectRevert(ZkqesRegistry.NullifierUsed.selector);
        registry.register(_proof(), i2);
    }

    function test_register_differentNullifierSamePkStillRevertsOnAlreadyBound() public {
        // Complementary sanity: pk uniqueness still enforced independently.
        registry.register(_proof(), _inputsFor(GX, GY, NULLIFIER_A));
        vm.expectRevert(ZkqesRegistry.AlreadyBound.selector);
        registry.register(_proof(), _inputsFor(GX, GY, NULLIFIER_B));
    }

    // ---- admin revocation ----------------------------------------------------

    function test_revokeNullifier_onlyAdmin() public {
        registry.register(_proof(), _inputsFor(GX, GY, NULLIFIER_A));
        vm.prank(ALICE);
        vm.expectRevert(ZkqesRegistry.NotAdmin.selector);
        registry.revokeNullifier(NULLIFIER_A, REASON);
    }

    function test_revokeNullifier_unknownReverts() public {
        vm.prank(ADMIN);
        vm.expectRevert(ZkqesRegistry.UnknownNullifier.selector);
        registry.revokeNullifier(NULLIFIER_A, REASON);
    }

    function test_revokeNullifier_zeroReasonReverts() public {
        registry.register(_proof(), _inputsFor(GX, GY, NULLIFIER_A));
        vm.prank(ADMIN);
        vm.expectRevert(ZkqesRegistry.ZeroAddress.selector);
        registry.revokeNullifier(NULLIFIER_A, bytes32(0));
    }

    function test_revokeNullifier_doubleRevokeReverts() public {
        registry.register(_proof(), _inputsFor(GX, GY, NULLIFIER_A));
        vm.prank(ADMIN);
        registry.revokeNullifier(NULLIFIER_A, REASON);
        vm.prank(ADMIN);
        vm.expectRevert(ZkqesRegistry.NullifierAlreadyRevoked.selector);
        registry.revokeNullifier(NULLIFIER_A, REASON);
    }

    function test_revokeNullifier_storesReasonAndEmits() public {
        address pkAddr = vm.addr(1);
        registry.register(_proof(), _inputsFor(GX, GY, NULLIFIER_A));

        vm.expectEmit(true, true, false, true, address(registry));
        emit NullifierRevoked(NULLIFIER_A, pkAddr, REASON);
        vm.prank(ADMIN);
        registry.revokeNullifier(NULLIFIER_A, REASON);

        assertEq(registry.revokedNullifiers(NULLIFIER_A), REASON);
    }

    function test_revokeNullifier_flipsIsActiveAtToFalse() public {
        address pkAddr = vm.addr(1);
        registry.register(_proof(), _inputsFor(GX, GY, NULLIFIER_A));

        // Before revocation: active.
        assertTrue(registry.isActiveAt(pkAddr, uint64(block.timestamp)));

        vm.prank(ADMIN);
        registry.revokeNullifier(NULLIFIER_A, REASON);

        // After revocation: not active, regardless of status or timestamp.
        assertFalse(registry.isActiveAt(pkAddr, uint64(block.timestamp)));
        assertFalse(registry.isActiveAt(pkAddr, type(uint64).max));
    }
}
