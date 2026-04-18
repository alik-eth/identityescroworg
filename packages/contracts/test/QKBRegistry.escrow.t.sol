// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { QKBVerifierV2, IGroth16VerifierV2 } from "../src/QKBVerifierV2.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

/// @notice Phase 2 Task 4+5: escrow register / revoke / getters, all
///         behind a real Phase-1 Groth16 auth gate. Stub verifiers stand
///         in for the ceremony-generated ones; the auth *path* is exercised
///         end to end (dispatch on algorithmTag, rTL check, pk-match,
///         bound-binding requirement).
contract QKBRegistryEscrowTest is Test {
    QKBRegistry internal registry;
    StubGroth16Verifier internal rsa;
    StubGroth16Verifier internal ecdsa;

    address internal constant ADMIN = address(0xA11CE);
    bytes32 internal constant INITIAL_ROOT = bytes32(uint256(0xC0FFEE));

    // priv=1 → G.
    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    bytes32 internal constant CTX_HASH = bytes32(uint256(0xA1));
    bytes32 internal constant NULLIFIER = bytes32(uint256(0xBEEF));
    bytes32 internal constant ESCROW_ID = keccak256("escrow-1");
    bytes32 internal constant REASON = keccak256("reason");
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
        rsa = new StubGroth16Verifier();
        ecdsa = new StubGroth16Verifier();
        registry = new QKBRegistry(
            IGroth16VerifierV2(address(rsa)),
            IGroth16VerifierV2(address(ecdsa)),
            INITIAL_ROOT,
            ADMIN
        );
        vm.warp(1_700_000_000);
        _registerG();
    }

    function _splitToLimbsLE(uint256 v) internal pure returns (uint256[4] memory out) {
        out[0] = v & type(uint64).max;
        out[1] = (v >> 64) & type(uint64).max;
        out[2] = (v >> 128) & type(uint64).max;
        out[3] = (v >> 192) & type(uint64).max;
    }

    function _inputs(bytes32 nullifier) internal view returns (QKBVerifierV2.Inputs memory i) {
        i.pkX = _splitToLimbsLE(GX);
        i.pkY = _splitToLimbsLE(GY);
        i.ctxHash = CTX_HASH;
        i.rTL = INITIAL_ROOT;
        i.declHash = DeclarationHashes.EN;
        i.timestamp = uint64(block.timestamp);
        i.algorithmTag = 1;
        i.nullifier = nullifier;
    }

    function _proof() internal pure returns (QKBVerifierV2.Proof memory p) {}

    function _registerG() internal {
        QKBVerifierV2.Inputs memory i = _inputs(NULLIFIER);
        registry.register(_proof(), i);
    }

    function _pkAddr() internal pure returns (address) {
        return vm.addr(1);
    }

    // ---- happy paths --------------------------------------------------------

    function test_registerEscrow_writesAndEmits() public {
        uint64 expiry = uint64(block.timestamp + 365 days);
        address pk = _pkAddr();

        vm.expectEmit(true, true, false, true, address(registry));
        emit EscrowRegistered(pk, ESCROW_ID, ARBITRATOR, expiry);
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));

        assertEq(registry.escrowCommitment(pk), ESCROW_ID);
        assertTrue(registry.isEscrowActive(pk));
    }

    function test_revokeEscrow_writesAndEmits() public {
        uint64 expiry = uint64(block.timestamp + 365 days);
        address pk = _pkAddr();
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));

        vm.expectEmit(true, true, false, true, address(registry));
        emit EscrowRevoked(pk, ESCROW_ID, REASON);
        registry.revokeEscrow(REASON, _proof(), _inputs(NULLIFIER));

        assertFalse(registry.isEscrowActive(pk));
        assertEq(registry.escrowCommitment(pk), bytes32(0));
    }

    function test_isEscrowActive_falseAfterExpiry() public {
        uint64 expiry = uint64(block.timestamp + 10);
        address pk = _pkAddr();
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));
        assertTrue(registry.isEscrowActive(pk));
        vm.warp(expiry + 1);
        assertFalse(registry.isEscrowActive(pk));
        assertEq(registry.escrowCommitment(pk), bytes32(0));
    }

    // ---- registerEscrow reverts --------------------------------------------

    function test_registerEscrow_revertsOnZeroArbitrator() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        vm.expectRevert(QKBRegistry.ZeroAddress.selector);
        registry.registerEscrow(ESCROW_ID, address(0), expiry, _proof(), _inputs(NULLIFIER));
    }

    function test_registerEscrow_revertsOnPastExpiry() public {
        vm.expectRevert(QKBRegistry.EscrowExpiryInPast.selector);
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, uint64(block.timestamp), _proof(), _inputs(NULLIFIER));
    }

    function test_registerEscrow_revertsOnDoubleRegister() public {
        uint64 expiry = uint64(block.timestamp + 365 days);
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));
        vm.expectRevert(QKBRegistry.EscrowExists.selector);
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));
    }

    function test_registerEscrow_revertsOnBadProof() public {
        ecdsa.setAccept(false);
        uint64 expiry = uint64(block.timestamp + 1 days);
        vm.expectRevert(QKBRegistry.InvalidProof.selector);
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));
    }

    function test_registerEscrow_revertsOnRootMismatch() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        QKBVerifierV2.Inputs memory i = _inputs(NULLIFIER);
        i.rTL = bytes32(uint256(0xDEAD));
        vm.expectRevert(QKBRegistry.RootMismatch.selector);
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), i);
    }

    function test_registerEscrow_revertsOnUnknownAlgorithm() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        QKBVerifierV2.Inputs memory i = _inputs(NULLIFIER);
        i.algorithmTag = 2;
        vm.expectRevert(QKBRegistry.UnknownAlgorithm.selector);
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), i);
    }

    function test_registerEscrow_revertsWhenBindingNotActive() public {
        // Fresh registry with no prior binding for this pk.
        QKBRegistry r2 = new QKBRegistry(
            IGroth16VerifierV2(address(rsa)),
            IGroth16VerifierV2(address(ecdsa)),
            INITIAL_ROOT,
            ADMIN
        );
        uint64 expiry = uint64(block.timestamp + 1 days);
        vm.expectRevert(QKBRegistry.NotBound.selector);
        r2.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));
    }

    // ---- revokeEscrow reverts -----------------------------------------------

    function test_revokeEscrow_revertsWhenNoEscrow() public {
        vm.expectRevert(QKBRegistry.NoEscrow.selector);
        registry.revokeEscrow(REASON, _proof(), _inputs(NULLIFIER));
    }

    function test_revokeEscrow_revertsOnDoubleRevoke() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));
        registry.revokeEscrow(REASON, _proof(), _inputs(NULLIFIER));
        vm.expectRevert(QKBRegistry.EscrowAlreadyRevoked.selector);
        registry.revokeEscrow(REASON, _proof(), _inputs(NULLIFIER));
    }

    function test_revokeEscrow_revertsOnBadProof() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));
        ecdsa.setAccept(false);
        vm.expectRevert(QKBRegistry.InvalidProof.selector);
        registry.revokeEscrow(REASON, _proof(), _inputs(NULLIFIER));
    }

    // ---- C1: state enum + reverse id mapping --------------------------------

    /// @notice State machine default — an unregistered pkAddr has NONE state
    ///         and all-zero EscrowEntry fields (MVP refinement §0.3).
    function test_EscrowState_EnumDefault() public {
        (bytes32 id, address arb, uint64 exp, uint64 pendingAt, QKBRegistry.EscrowState state)
            = registry.escrows(address(0xdead));
        assertEq(id, bytes32(0));
        assertEq(arb, address(0));
        assertEq(exp, 0);
        assertEq(pendingAt, 0);
        assertEq(uint8(state), uint8(QKBRegistry.EscrowState.NONE));
    }

    /// @notice Reverse escrowId → pkAddr lookup is initially empty (MVP §0.3).
    function test_EscrowIdToPkAddr_InitiallyZero() public {
        assertEq(registry.escrowIdToPkAddr(bytes32(uint256(1))), address(0));
    }

    /// @notice registerEscrow populates `escrowIdToPkAddr` reverse map and
    ///         sets state to ACTIVE (no releasePendingAt).
    function test_registerEscrow_populatesReverseMapAndActiveState() public {
        uint64 expiry = uint64(block.timestamp + 365 days);
        address pk = _pkAddr();
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));

        assertEq(registry.escrowIdToPkAddr(ESCROW_ID), pk);
        (,,, uint64 pendingAt, QKBRegistry.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(QKBRegistry.EscrowState.ACTIVE));
        assertEq(pendingAt, 0);
    }

    /// @notice revokeEscrow flips state to REVOKED (not a `revoked` bool).
    function test_revokeEscrow_setsStateRevoked() public {
        uint64 expiry = uint64(block.timestamp + 365 days);
        address pk = _pkAddr();
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));
        registry.revokeEscrow(REASON, _proof(), _inputs(NULLIFIER));
        (,,,, QKBRegistry.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(QKBRegistry.EscrowState.REVOKED));
    }

    // ---- C2: notifyReleasePending + finalizeRelease -------------------------

    /// @dev Helper — register the default escrow so the state-machine tests
    ///      can hop straight into the interesting transitions.
    function _registerDefaultEscrow() internal returns (address pk, uint64 expiry) {
        expiry = uint64(block.timestamp + 365 days);
        pk = _pkAddr();
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), _inputs(NULLIFIER));
    }

    /// @notice Only the escrow's bound arbitrator may drive the release
    ///         state machine — anyone else reverts `NotArbitrator`.
    function test_NotifyReleasePending_OnlyArbitrator() public {
        _registerDefaultEscrow();
        vm.expectRevert(QKBRegistry.NotArbitrator.selector);
        vm.prank(address(0xBAD));
        registry.notifyReleasePending(ESCROW_ID);
    }

    /// @notice notifyReleasePending flips ACTIVE -> RELEASE_PENDING and
    ///         stamps `releasePendingAt` with `block.timestamp`.
    function test_NotifyReleasePending_TransitionsActiveToPending() public {
        (address pk,) = _registerDefaultEscrow();
        vm.expectEmit(true, true, false, true, address(registry));
        emit EscrowReleasePendingRequested(ESCROW_ID, ARBITRATOR, uint64(block.timestamp));
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        (,,, uint64 pendingAt, QKBRegistry.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(QKBRegistry.EscrowState.RELEASE_PENDING));
        assertEq(pendingAt, uint64(block.timestamp));
    }

    /// @notice Once pending, revoke is blocked with `EscrowReleasePending`.
    function test_NotifyReleasePending_BlocksRevoke() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.expectRevert(QKBRegistry.EscrowReleasePending.selector);
        registry.revokeEscrow(REASON, _proof(), _inputs(NULLIFIER));
    }

    /// @notice Unknown escrowId reverts `UnknownEscrowId`.
    function test_NotifyReleasePending_UnknownEscrowIdReverts() public {
        vm.expectRevert(QKBRegistry.UnknownEscrowId.selector);
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(bytes32(uint256(0xDEADBEEF)));
    }

    /// @notice Cannot notify twice — state must be ACTIVE.
    function test_NotifyReleasePending_RevertsFromNonActiveState() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.expectRevert(QKBRegistry.WrongState.selector);
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
    }

    /// @notice finalizeRelease only callable by the arbitrator.
    function test_FinalizeRelease_OnlyArbitrator() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.warp(block.timestamp + 48 hours);
        vm.expectRevert(QKBRegistry.NotArbitrator.selector);
        vm.prank(address(0xBAD));
        registry.finalizeRelease(ESCROW_ID);
    }

    /// @notice finalizeRelease reverts if called before RELEASE_TIMEOUT elapses.
    function test_FinalizeRelease_RevertsBeforeTimeout() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.warp(block.timestamp + 48 hours - 1);
        vm.expectRevert(QKBRegistry.WrongState.selector);
        vm.prank(ARBITRATOR);
        registry.finalizeRelease(ESCROW_ID);
    }

    /// @notice finalizeRelease transitions RELEASE_PENDING -> RELEASED after
    ///         the Holder cancellation window elapses and emits the event.
    function test_FinalizeRelease_TransitionsPendingToReleased() public {
        (address pk,) = _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.warp(block.timestamp + 48 hours);
        vm.expectEmit(true, true, false, true, address(registry));
        emit EscrowReleased(ESCROW_ID, ARBITRATOR);
        vm.prank(ARBITRATOR);
        registry.finalizeRelease(ESCROW_ID);
        (,,,, QKBRegistry.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(QKBRegistry.EscrowState.RELEASED));
    }

    /// @notice Once RELEASED, revoke reverts `EscrowAlreadyReleased`.
    function test_FinalizeRelease_BlocksRevoke() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.warp(block.timestamp + 48 hours);
        vm.prank(ARBITRATOR);
        registry.finalizeRelease(ESCROW_ID);
        vm.expectRevert(QKBRegistry.EscrowAlreadyReleased.selector);
        registry.revokeEscrow(REASON, _proof(), _inputs(NULLIFIER));
    }

    /// @notice finalizeRelease on an unknown escrowId reverts `UnknownEscrowId`.
    function test_FinalizeRelease_UnknownEscrowIdReverts() public {
        vm.expectRevert(QKBRegistry.UnknownEscrowId.selector);
        vm.prank(ARBITRATOR);
        registry.finalizeRelease(bytes32(uint256(0xDEADBEEF)));
    }

    // ---- C3: cancelReleasePending (Holder 48 h window) ----------------------

    /// @notice cancelReleasePending flips RELEASE_PENDING back to ACTIVE when
    ///         called within the 48 h Holder window. Same Groth16 auth as
    ///         revoke/register so only the Holder can do it.
    function test_CancelReleasePending_RestoresActive() public {
        (address pk,) = _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);

        vm.expectEmit(true, true, false, true, address(registry));
        emit EscrowReleaseCancelled(ESCROW_ID, pk);
        registry.cancelReleasePending(_proof(), _inputs(NULLIFIER));

        (,,, uint64 pendingAt, QKBRegistry.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(QKBRegistry.EscrowState.ACTIVE));
        assertEq(pendingAt, 0);
    }

    /// @notice After the Holder window elapses, cancel reverts `WrongState`
    ///         (arbitrator may now finalize instead).
    function test_CancelReleasePending_OnlyDuringWindow() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        vm.warp(block.timestamp + 48 hours);
        vm.expectRevert(QKBRegistry.WrongState.selector);
        registry.cancelReleasePending(_proof(), _inputs(NULLIFIER));
    }

    /// @notice Cannot cancel when escrow is ACTIVE — there's nothing to
    ///         cancel, state must be RELEASE_PENDING.
    function test_CancelReleasePending_RevertsWhenActive() public {
        _registerDefaultEscrow();
        vm.expectRevert(QKBRegistry.WrongState.selector);
        registry.cancelReleasePending(_proof(), _inputs(NULLIFIER));
    }

    /// @notice After cancel, revoke is available again (ACTIVE path).
    function test_CancelReleasePending_RestoresRevokeEligibility() public {
        (address pk,) = _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        registry.cancelReleasePending(_proof(), _inputs(NULLIFIER));

        registry.revokeEscrow(REASON, _proof(), _inputs(NULLIFIER));
        (,,,, QKBRegistry.EscrowState state) = registry.escrows(pk);
        assertEq(uint8(state), uint8(QKBRegistry.EscrowState.REVOKED));
    }

    /// @notice cancel still requires a valid Groth16 proof — tamper the
    ///         verifier and the call reverts `InvalidProof`.
    function test_CancelReleasePending_RevertsOnBadProof() public {
        _registerDefaultEscrow();
        vm.prank(ARBITRATOR);
        registry.notifyReleasePending(ESCROW_ID);
        ecdsa.setAccept(false);
        vm.expectRevert(QKBRegistry.InvalidProof.selector);
        registry.cancelReleasePending(_proof(), _inputs(NULLIFIER));
    }
}
