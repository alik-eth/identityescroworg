// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { ZkqesRegistryV3 } from "../src/ZkqesRegistryV3.sol";
import { ZkqesVerifier } from "../src/ZkqesVerifier.sol";
import { V3Harness } from "./helpers/V3Harness.sol";

/// @notice §14.4 nullifier primitive coverage for V3. Mirrors V2's
///         \`ZkqesRegistry.nullifier.t.sol\` suite against the split-proof
///         register surface.
contract ZkqesRegistryV3NullifierTest is V3Harness {
    address internal constant ALICE = address(0xB0B);

    bytes32 internal constant NULLIFIER_A = bytes32(uint256(0xBEEF));
    bytes32 internal constant NULLIFIER_B = bytes32(uint256(0xCAFE));
    bytes32 internal constant REASON      = bytes32(uint256(0x1234));

    event NullifierRevoked(bytes32 indexed nullifier, address indexed pkAddr, bytes32 reasonHash);

    function setUp() public {
        _harnessSetUp();
        // Wide-open stubs — these tests exercise the nullifier logic, not
        // the Groth16 gate.
        rsaLeaf.setAccept(true);
        rsaChain.setAccept(true);
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
    }

    function _leafFor(uint256 x, uint256 y, bytes32 nullifier)
        internal view returns (ZkqesVerifier.LeafInputs memory i)
    {
        i = _leafInputs(nullifier);
        i.pkX = _splitToLimbsLE(x);
        i.pkY = _splitToLimbsLE(y);
    }

    // ----- uniqueness + storage ---------------------------------------------

    function test_register_storesUsedNullifierAndMapping() public {
        registry.register(
            _zeroProof(),
            _leafFor(GX, GY, NULLIFIER_A),
            _zeroProof(),
            _chainInputs(1)
        );
        assertTrue(registry.usedNullifiers(NULLIFIER_A));
        assertEq(registry.nullifierToPk(NULLIFIER_A), vm.addr(1));
    }

    function test_register_duplicateNullifierOnDifferentPkReverts() public {
        // First Holder registers with nullifier A.
        registry.register(
            _zeroProof(),
            _leafFor(GX, GY, NULLIFIER_A),
            _zeroProof(),
            _chainInputs(1)
        );
        // Second Holder uses a fresh pk (priv = 2) but the SAME nullifier
        // — simulating a Sybil by the same cert subject against the same
        // ctxHash. Must revert even though the pk is new.
        vm.expectRevert(ZkqesRegistryV3.NullifierUsed.selector);
        registry.register(
            _zeroProof(),
            _leafFor(GX2, GY2, NULLIFIER_A),
            _zeroProof(),
            _chainInputs(1)
        );
    }

    function test_register_differentNullifierSamePkStillRevertsOnAlreadyBound() public {
        registry.register(
            _zeroProof(),
            _leafFor(GX, GY, NULLIFIER_A),
            _zeroProof(),
            _chainInputs(1)
        );
        vm.expectRevert(ZkqesRegistryV3.AlreadyBound.selector);
        registry.register(
            _zeroProof(),
            _leafFor(GX, GY, NULLIFIER_B),
            _zeroProof(),
            _chainInputs(1)
        );
    }

    // ----- admin revocation -------------------------------------------------

    function test_revokeNullifier_onlyAdmin() public {
        registry.register(
            _zeroProof(),
            _leafFor(GX, GY, NULLIFIER_A),
            _zeroProof(),
            _chainInputs(1)
        );
        vm.prank(ALICE);
        vm.expectRevert(ZkqesRegistryV3.NotAdmin.selector);
        registry.revokeNullifier(NULLIFIER_A, REASON);
    }

    function test_revokeNullifier_unknownReverts() public {
        vm.prank(ADMIN);
        vm.expectRevert(ZkqesRegistryV3.UnknownNullifier.selector);
        registry.revokeNullifier(NULLIFIER_A, REASON);
    }

    function test_revokeNullifier_zeroReasonReverts() public {
        registry.register(
            _zeroProof(),
            _leafFor(GX, GY, NULLIFIER_A),
            _zeroProof(),
            _chainInputs(1)
        );
        vm.prank(ADMIN);
        vm.expectRevert(ZkqesRegistryV3.ZeroAddress.selector);
        registry.revokeNullifier(NULLIFIER_A, bytes32(0));
    }

    function test_revokeNullifier_doubleRevokeReverts() public {
        registry.register(
            _zeroProof(),
            _leafFor(GX, GY, NULLIFIER_A),
            _zeroProof(),
            _chainInputs(1)
        );
        vm.prank(ADMIN);
        registry.revokeNullifier(NULLIFIER_A, REASON);
        vm.prank(ADMIN);
        vm.expectRevert(ZkqesRegistryV3.NullifierAlreadyRevoked.selector);
        registry.revokeNullifier(NULLIFIER_A, REASON);
    }

    function test_revokeNullifier_storesReasonAndEmits() public {
        address pkAddr = vm.addr(1);
        registry.register(
            _zeroProof(),
            _leafFor(GX, GY, NULLIFIER_A),
            _zeroProof(),
            _chainInputs(1)
        );

        vm.expectEmit(true, true, false, true, address(registry));
        emit NullifierRevoked(NULLIFIER_A, pkAddr, REASON);
        vm.prank(ADMIN);
        registry.revokeNullifier(NULLIFIER_A, REASON);

        assertEq(registry.revokedNullifiers(NULLIFIER_A), REASON);
    }

    function test_revokeNullifier_flipsIsActiveAtToFalse() public {
        address pkAddr = vm.addr(1);
        registry.register(
            _zeroProof(),
            _leafFor(GX, GY, NULLIFIER_A),
            _zeroProof(),
            _chainInputs(1)
        );

        assertTrue(registry.isActiveAt(pkAddr, uint64(block.timestamp)));

        vm.prank(ADMIN);
        registry.revokeNullifier(NULLIFIER_A, REASON);

        assertFalse(registry.isActiveAt(pkAddr, uint64(block.timestamp)));
        assertFalse(registry.isActiveAt(pkAddr, type(uint64).max));
    }
}
