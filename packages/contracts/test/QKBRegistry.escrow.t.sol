// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { QKBVerifier, IGroth16Verifier } from "../src/QKBVerifier.sol";
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

    function setUp() public {
        rsa = new StubGroth16Verifier();
        ecdsa = new StubGroth16Verifier();
        registry = new QKBRegistry(
            IGroth16Verifier(address(rsa)),
            IGroth16Verifier(address(ecdsa)),
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

    function _inputs(bytes32 nullifier) internal view returns (QKBVerifier.Inputs memory i) {
        i.pkX = _splitToLimbsLE(GX);
        i.pkY = _splitToLimbsLE(GY);
        i.ctxHash = CTX_HASH;
        i.rTL = INITIAL_ROOT;
        i.declHash = DeclarationHashes.EN;
        i.timestamp = uint64(block.timestamp);
        i.algorithmTag = 1;
        i.nullifier = nullifier;
    }

    function _proof() internal pure returns (QKBVerifier.Proof memory p) {}

    function _registerG() internal {
        QKBVerifier.Inputs memory i = _inputs(NULLIFIER);
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
        QKBVerifier.Inputs memory i = _inputs(NULLIFIER);
        i.rTL = bytes32(uint256(0xDEAD));
        vm.expectRevert(QKBRegistry.RootMismatch.selector);
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), i);
    }

    function test_registerEscrow_revertsOnUnknownAlgorithm() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        QKBVerifier.Inputs memory i = _inputs(NULLIFIER);
        i.algorithmTag = 2;
        vm.expectRevert(QKBRegistry.UnknownAlgorithm.selector);
        registry.registerEscrow(ESCROW_ID, ARBITRATOR, expiry, _proof(), i);
    }

    function test_registerEscrow_revertsWhenBindingNotActive() public {
        // Fresh registry with no prior binding for this pk.
        QKBRegistry r2 = new QKBRegistry(
            IGroth16Verifier(address(rsa)),
            IGroth16Verifier(address(ecdsa)),
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
}
