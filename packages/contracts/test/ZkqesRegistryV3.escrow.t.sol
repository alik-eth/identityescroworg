// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { ZkqesRegistryV3 } from "../src/ZkqesRegistryV3.sol";
import {
    ZkqesVerifier,
    IGroth16LeafVerifier,
    IGroth16ChainVerifier
} from "../src/ZkqesVerifier.sol";
import { V3Harness } from "./helpers/V3Harness.sol";

/// @notice V3 escrow surface — register / revoke / release-pending
///         transitions, all behind the split-proof auth gate. Mirrors
///         V2's \`ZkqesRegistry.escrow.t.sol\` semantically but uses the new
///         dual-proof entrypoints.
contract ZkqesRegistryV3EscrowTest is V3Harness {
    bytes32 internal constant NULLIFIER = bytes32(uint256(0xBEEF));
    bytes32 internal constant ESCROW_ID = keccak256("escrow-1");
    bytes32 internal constant REASON    = keccak256("reason");
    address internal constant ARBITRATOR = address(0xAAA0);

    event EscrowRegistered(
        address indexed pkAddr,
        bytes32 indexed escrowId,
        address arbitrator,
        uint64 expiry
    );
    event EscrowRevoked(address indexed pkAddr, bytes32 indexed escrowId, bytes32 reasonHash);
    event EscrowReleasePendingRequested(bytes32 indexed escrowId, address indexed arbitrator, uint64 at);
    event EscrowReleased(bytes32 indexed escrowId, address indexed arbitrator);
    event EscrowReleaseCancelled(bytes32 indexed escrowId, address indexed pkAddr);

    function setUp() public {
        _harnessSetUp();
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        _registerG();
    }

    function _registerG() internal {
        registry.register(
            _zeroProof(),
            _leafInputs(NULLIFIER),
            _zeroProof(),
            _chainInputs(1)
        );
    }

    function _pkAddr() internal pure returns (address) {
        return vm.addr(1);
    }

    // Convenience: default split-proof pair for escrow ops.
    function _registerEscrow(bytes32 id, address arb, uint64 expiry) internal {
        registry.registerEscrow(
            id,
            arb,
            expiry,
            _zeroProof(), _leafInputs(NULLIFIER),
            _zeroProof(), _chainInputs(1)
        );
    }

    function _revokeEscrow(bytes32 reasonHash) internal {
        registry.revokeEscrow(
            reasonHash,
            _zeroProof(), _leafInputs(NULLIFIER),
            _zeroProof(), _chainInputs(1)
        );
    }

    function _cancelReleasePending() internal {
        registry.cancelReleasePending(
            _zeroProof(), _leafInputs(NULLIFIER),
            _zeroProof(), _chainInputs(1)
        );
    }

    // ---- happy paths --------------------------------------------------------

    function test_registerEscrow_writesAndEmits() public {
        uint64 expiry = uint64(block.timestamp + 365 days);
        address pk = _pkAddr();

        vm.expectEmit(true, true, false, true, address(registry));
        emit EscrowRegistered(pk, ESCROW_ID, ARBITRATOR, expiry);
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);

        assertEq(registry.escrowCommitment(pk), ESCROW_ID);
        assertTrue(registry.isEscrowActive(pk));
    }

    function test_revokeEscrow_writesAndEmits() public {
        uint64 expiry = uint64(block.timestamp + 365 days);
        address pk = _pkAddr();
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);

        vm.expectEmit(true, true, false, true, address(registry));
        emit EscrowRevoked(pk, ESCROW_ID, REASON);
        _revokeEscrow(REASON);

        assertFalse(registry.isEscrowActive(pk));
        assertEq(registry.escrowCommitment(pk), bytes32(0));
    }

    function test_isEscrowActive_falseAfterExpiry() public {
        uint64 expiry = uint64(block.timestamp + 10);
        address pk = _pkAddr();
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);
        assertTrue(registry.isEscrowActive(pk));
        vm.warp(expiry + 1);
        assertFalse(registry.isEscrowActive(pk));
        assertEq(registry.escrowCommitment(pk), bytes32(0));
    }

    // ---- registerEscrow reverts --------------------------------------------

    function test_registerEscrow_revertsOnZeroArbitrator() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        vm.expectRevert(ZkqesRegistryV3.ZeroAddress.selector);
        _registerEscrow(ESCROW_ID, address(0), expiry);
    }

    function test_registerEscrow_revertsOnPastExpiry() public {
        vm.expectRevert(ZkqesRegistryV3.EscrowExpiryInPast.selector);
        _registerEscrow(ESCROW_ID, ARBITRATOR, uint64(block.timestamp));
    }

    function test_registerEscrow_revertsOnDoubleRegister() public {
        uint64 expiry = uint64(block.timestamp + 365 days);
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);
        vm.expectRevert(ZkqesRegistryV3.EscrowExists.selector);
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);
    }

    function test_registerEscrow_revertsOnBadLeafProof() public {
        ecdsaLeaf.setAccept(false);
        uint64 expiry = uint64(block.timestamp + 1 days);
        vm.expectRevert(ZkqesRegistryV3.InvalidProof.selector);
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);
    }

    function test_registerEscrow_revertsOnBadChainProof() public {
        ecdsaChain.setAccept(false);
        uint64 expiry = uint64(block.timestamp + 1 days);
        vm.expectRevert(ZkqesRegistryV3.InvalidProof.selector);
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);
    }

    function test_registerEscrow_revertsOnRootMismatch() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        ZkqesVerifier.ChainInputs memory chain = _chainInputs(1);
        chain.rTL = bytes32(uint256(0xDEAD));
        vm.expectRevert(ZkqesRegistryV3.RootMismatch.selector);
        registry.registerEscrow(
            ESCROW_ID, ARBITRATOR, expiry,
            _zeroProof(), _leafInputs(NULLIFIER),
            _zeroProof(), chain
        );
    }

    function test_registerEscrow_revertsOnLeafSpkiCommitMismatch() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        ZkqesVerifier.ChainInputs memory chain = _chainInputs(1);
        chain.leafSpkiCommit = bytes32(uint256(SPKI_COMMIT) ^ 1);
        vm.expectRevert(ZkqesRegistryV3.LeafSpkiCommitMismatch.selector);
        registry.registerEscrow(
            ESCROW_ID, ARBITRATOR, expiry,
            _zeroProof(), _leafInputs(NULLIFIER),
            _zeroProof(), chain
        );
    }

    function test_registerEscrow_revertsOnUnknownAlgorithm() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        ZkqesVerifier.ChainInputs memory chain = _chainInputs(2);
        vm.expectRevert(ZkqesRegistryV3.UnknownAlgorithm.selector);
        registry.registerEscrow(
            ESCROW_ID, ARBITRATOR, expiry,
            _zeroProof(), _leafInputs(NULLIFIER),
            _zeroProof(), chain
        );
    }

    function test_registerEscrow_revertsWhenBindingNotActive() public {
        // Fresh registry — no prior binding for this pk.
        ZkqesRegistryV3 r2 = new ZkqesRegistryV3(
            IGroth16LeafVerifier(address(rsaLeaf)),
            IGroth16ChainVerifier(address(rsaChain)),
            IGroth16LeafVerifier(address(ecdsaLeaf)),
            IGroth16ChainVerifier(address(ecdsaChain)),
            INITIAL_ROOT,
            ADMIN
        );
        uint64 expiry = uint64(block.timestamp + 1 days);
        vm.expectRevert(ZkqesRegistryV3.NotBound.selector);
        r2.registerEscrow(
            ESCROW_ID, ARBITRATOR, expiry,
            _zeroProof(), _leafInputs(NULLIFIER),
            _zeroProof(), _chainInputs(1)
        );
    }

    // ---- revokeEscrow reverts ----------------------------------------------

    function test_revokeEscrow_revertsWhenNoEscrow() public {
        vm.expectRevert(ZkqesRegistryV3.NoEscrow.selector);
        _revokeEscrow(REASON);
    }

    function test_revokeEscrow_revertsOnDoubleRevoke() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);
        _revokeEscrow(REASON);
        vm.expectRevert(ZkqesRegistryV3.EscrowAlreadyRevoked.selector);
        _revokeEscrow(REASON);
    }

    function test_revokeEscrow_revertsOnBadProof() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);
        ecdsaLeaf.setAccept(false);
        vm.expectRevert(ZkqesRegistryV3.InvalidProof.selector);
        _revokeEscrow(REASON);
    }

    // ---- state enum + reverse id mapping -----------------------------------

    function test_EscrowState_EnumDefault() public view {
        (bytes32 id, address arb, uint64 exp, uint64 pendingAt, ZkqesRegistryV3.EscrowState state)
            = registry.escrows(address(0xdead));
        assertEq(id, bytes32(0));
        assertEq(arb, address(0));
        assertEq(exp, 0);
        assertEq(pendingAt, 0);
        assertEq(uint8(state), uint8(ZkqesRegistryV3.EscrowState.NONE));
    }

    function test_EscrowIdToPkAddr_InitiallyZero() public view {
        assertEq(registry.escrowIdToPkAddr(bytes32(uint256(1))), address(0));
    }

    function test_registerEscrow_populatesReverseMapAndActiveState() public {
        uint64 expiry = uint64(block.timestamp + 365 days);
        address pk = _pkAddr();
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);

        assertEq(registry.escrowIdToPkAddr(ESCROW_ID), pk);
        (,,, uint64 pendingAt, ZkqesRegistryV3.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(ZkqesRegistryV3.EscrowState.ACTIVE));
        assertEq(pendingAt, 0);
    }

    function test_revokeEscrow_setsStateRevoked() public {
        uint64 expiry = uint64(block.timestamp + 365 days);
        address pk = _pkAddr();
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);
        _revokeEscrow(REASON);
        (,,,, ZkqesRegistryV3.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(ZkqesRegistryV3.EscrowState.REVOKED));
    }

    // ---- notifyReleasePending + finalizeRelease ----------------------------

    function _registerDefaultEscrow() internal returns (address pk, uint64 expiry) {
        expiry = uint64(block.timestamp + 365 days);
        pk = _pkAddr();
        _registerEscrow(ESCROW_ID, ARBITRATOR, expiry);
    }

    function test_NotifyReleasePending_OnlyArbitrator() public {
        _registerDefaultEscrow();
        vm.expectRevert(ZkqesRegistryV3.NotArbitrator.selector);
        vm.prank(address(0xBAD));
        registry.notifyReleasePending(ESCROW_ID);
    }

    function test_NotifyReleasePending_TransitionsActiveToPending() public {
        (address pk,) = _registerDefaultEscrow();
        vm.expectEmit(true, true, false, true, address(registry));
        emit EscrowReleasePendingRequested(ESCROW_ID, ARBITRATOR, uint64(block.timestamp));
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        (,,, uint64 pendingAt, ZkqesRegistryV3.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(ZkqesRegistryV3.EscrowState.RELEASE_PENDING));
        assertEq(pendingAt, uint64(block.timestamp));
    }

    function test_NotifyReleasePending_BlocksRevoke() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.expectRevert(ZkqesRegistryV3.EscrowReleasePending.selector);
        _revokeEscrow(REASON);
    }

    function test_NotifyReleasePending_UnknownEscrowIdReverts() public {
        vm.expectRevert(ZkqesRegistryV3.UnknownEscrowId.selector);
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(bytes32(uint256(0xDEADBEEF)));
    }

    function test_NotifyReleasePending_RevertsFromNonActiveState() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.expectRevert(ZkqesRegistryV3.WrongState.selector);
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
    }

    function test_FinalizeRelease_OnlyArbitrator() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.warp(block.timestamp + 48 hours);
        vm.expectRevert(ZkqesRegistryV3.NotArbitrator.selector);
        vm.prank(address(0xBAD));
        registry.finalizeRelease(ESCROW_ID);
    }

    function test_FinalizeRelease_RevertsBeforeTimeout() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.warp(block.timestamp + 48 hours - 1);
        vm.expectRevert(ZkqesRegistryV3.WrongState.selector);
        vm.prank(ARBITRATOR);
        registry.finalizeRelease(ESCROW_ID);
    }

    function test_FinalizeRelease_TransitionsPendingToReleased() public {
        (address pk,) = _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.warp(block.timestamp + 48 hours);
        vm.expectEmit(true, true, false, true, address(registry));
        emit EscrowReleased(ESCROW_ID, ARBITRATOR);
        vm.prank(ARBITRATOR);
        registry.finalizeRelease(ESCROW_ID);
        (,,,, ZkqesRegistryV3.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(ZkqesRegistryV3.EscrowState.RELEASED));
    }

    function test_FinalizeRelease_BlocksRevoke() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.warp(block.timestamp + 48 hours);
        vm.prank(ARBITRATOR);
        registry.finalizeRelease(ESCROW_ID);
        vm.expectRevert(ZkqesRegistryV3.EscrowAlreadyReleased.selector);
        _revokeEscrow(REASON);
    }

    function test_FinalizeRelease_UnknownEscrowIdReverts() public {
        vm.expectRevert(ZkqesRegistryV3.UnknownEscrowId.selector);
        vm.prank(ARBITRATOR);
        registry.finalizeRelease(bytes32(uint256(0xDEADBEEF)));
    }

    // ---- cancelReleasePending (Holder 48 h window) -------------------------

    function test_CancelReleasePending_RestoresActive() public {
        (address pk,) = _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);

        vm.expectEmit(true, true, false, true, address(registry));
        emit EscrowReleaseCancelled(ESCROW_ID, pk);
        _cancelReleasePending();

        (,,, uint64 pendingAt, ZkqesRegistryV3.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(ZkqesRegistryV3.EscrowState.ACTIVE));
        assertEq(pendingAt, 0);
    }

    function test_CancelReleasePending_OnlyDuringWindow() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.warp(block.timestamp + 48 hours);
        vm.expectRevert(ZkqesRegistryV3.WrongState.selector);
        _cancelReleasePending();
    }

    function test_CancelReleasePending_RevertsWhenActive() public {
        _registerDefaultEscrow();
        vm.expectRevert(ZkqesRegistryV3.WrongState.selector);
        _cancelReleasePending();
    }

    function test_CancelReleasePending_RestoresRevokeEligibility() public {
        (address pk,) = _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        _cancelReleasePending();

        _revokeEscrow(REASON);
        (,,,, ZkqesRegistryV3.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(ZkqesRegistryV3.EscrowState.REVOKED));
    }

    function test_CancelReleasePending_RevertsOnBadProof() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        ecdsaLeaf.setAccept(false);
        vm.expectRevert(ZkqesRegistryV3.InvalidProof.selector);
        _cancelReleasePending();
    }
}
