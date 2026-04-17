// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { AuthorityArbitrator } from "../src/arbitrators/AuthorityArbitrator.sol";
import { IArbitrator } from "../src/arbitrators/IArbitrator.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { QKBVerifier, IGroth16Verifier } from "../src/QKBVerifier.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

/// @notice MVP refinement §0.2 + §0.3 — authority-driven release drives the
///         registry state machine and emits the additive UnlockEvidence
///         event. Tests exercise: constructor guards, happy path with both
///         events + state hop, replay protection, bad-sig / bad-length, and
///         tampered-field rejection.
contract AuthorityArbitratorTest is Test {
    AuthorityArbitrator internal arb;
    QKBRegistry internal registry;
    StubGroth16Verifier internal rsa;
    StubGroth16Verifier internal ecdsa;

    uint256 internal constant AUTHORITY_SK = 0xA11CE;
    address internal authority;
    address internal constant ADMIN = address(0xA11CE0);

    // priv=1 -> G on secp256k1; pkAddr derives from that binding.
    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    bytes32 internal constant INITIAL_ROOT = bytes32(uint256(0xC0FFEE));
    bytes32 internal constant CTX_HASH = bytes32(uint256(0xA1));
    bytes32 internal constant NULLIFIER = bytes32(uint256(0xBEEF));
    bytes32 internal constant ESCROW_ID = keccak256("e1");
    bytes internal recipientPk = hex"04aa";
    bytes32 internal constant EVIDENCE_HASH = keccak256("court-order-123");
    bytes32 internal constant KIND_HASH = keccak256("death_certificate");
    bytes32 internal constant REFERENCE = bytes32(uint256(0xDC001));

    event Unlock(bytes32 indexed escrowId, bytes recipientHybridPk);
    event UnlockEvidence(
        bytes32 indexed escrowId,
        bytes32 kindHash,
        bytes32 referenceHash,
        bytes32 evidenceHash,
        uint64  issuedAt
    );
    event EscrowReleasePendingRequested(bytes32 indexed escrowId, address indexed arbitrator, uint64 at);

    function setUp() public {
        authority = vm.addr(AUTHORITY_SK);
        rsa = new StubGroth16Verifier();
        ecdsa = new StubGroth16Verifier();
        registry = new QKBRegistry(
            IGroth16Verifier(address(rsa)),
            IGroth16Verifier(address(ecdsa)),
            INITIAL_ROOT,
            ADMIN
        );
        arb = new AuthorityArbitrator(authority, address(registry));

        vm.warp(1_700_000_000);
        // Register G-derived binding, then register an escrow pointing at `arb`.
        registry.register(_proof(), _inputs(NULLIFIER));
        registry.registerEscrow(
            ESCROW_ID,
            address(arb),
            uint64(block.timestamp + 365 days),
            _proof(),
            _inputs(NULLIFIER)
        );
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

    function _pkAddr() internal pure returns (address) {
        return vm.addr(1);
    }

    function _sign(
        uint256 sk,
        bytes32 escrowId,
        bytes memory rpk,
        bytes32 eh,
        bytes32 kh,
        bytes32 ref,
        uint64 issuedAt
    ) internal pure returns (bytes memory) {
        bytes32 digest = keccak256(abi.encode(escrowId, rpk, eh, kh, ref, issuedAt));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ---- constructor --------------------------------------------------------

    function test_constructor_revertsOnZeroAuthority() public {
        vm.expectRevert(AuthorityArbitrator.ZeroAddr.selector);
        new AuthorityArbitrator(address(0), address(registry));
    }

    function test_constructor_revertsOnZeroRegistry() public {
        vm.expectRevert(AuthorityArbitrator.ZeroAddr.selector);
        new AuthorityArbitrator(authority, address(0));
    }

    function test_constructor_setsBothImmutables() public {
        assertEq(arb.authority(), authority);
        assertEq(address(arb.registry()), address(registry));
    }

    // ---- happy path ---------------------------------------------------------

    function test_RequestUnlock_EmitsEvidenceEventBeforeUnlock() public {
        uint64 issuedAt = uint64(block.timestamp - 3600);
        bytes memory sig = _sign(AUTHORITY_SK, ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt);

        // UnlockEvidence fires first, then Unlock — both from the arbitrator.
        vm.expectEmit(true, false, false, true, address(arb));
        emit UnlockEvidence(ESCROW_ID, KIND_HASH, REFERENCE, EVIDENCE_HASH, issuedAt);
        vm.expectEmit(true, false, false, true, address(arb));
        emit Unlock(ESCROW_ID, recipientPk);
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt, sig);

        assertTrue(arb.evidenceHashUsed(EVIDENCE_HASH));
    }

    function test_RequestUnlock_TransitionsRegistryToPending() public {
        uint64 issuedAt = uint64(block.timestamp - 3600);
        bytes memory sig = _sign(AUTHORITY_SK, ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt);

        // Expect the registry to emit its own pending-requested event too.
        vm.expectEmit(true, true, false, true, address(registry));
        emit EscrowReleasePendingRequested(ESCROW_ID, address(arb), uint64(block.timestamp));
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt, sig);

        (,,, uint64 pendingAt, QKBRegistry.EscrowState state) = registry.escrows(_pkAddr());
        assertEq(uint8(state), uint8(QKBRegistry.EscrowState.RELEASE_PENDING));
        assertEq(pendingAt, uint64(block.timestamp));
    }

    // ---- reverts ------------------------------------------------------------

    function test_RequestUnlock_WrongSignerReverts() public {
        uint64 issuedAt = uint64(block.timestamp - 3600);
        bytes memory sig = _sign(0xB0B, ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt);
        vm.expectRevert(AuthorityArbitrator.BadAuthoritySig.selector);
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt, sig);
    }

    function test_RequestUnlock_ReplayedEvidenceReverts() public {
        uint64 issuedAt = uint64(block.timestamp - 3600);
        bytes memory sig = _sign(AUTHORITY_SK, ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt);
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt, sig);
        vm.expectRevert(AuthorityArbitrator.EvidenceReplayed.selector);
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt, sig);
    }

    function test_RequestUnlock_BadSigLengthReverts() public {
        uint64 issuedAt = uint64(block.timestamp - 3600);
        bytes memory badSig = hex"aabb";
        vm.expectRevert(AuthorityArbitrator.BadSigLength.selector);
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt, badSig);
    }

    function test_RequestUnlock_TamperedEscrowIdReverts() public {
        uint64 issuedAt = uint64(block.timestamp - 3600);
        bytes memory sig = _sign(AUTHORITY_SK, ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt);
        vm.expectRevert(AuthorityArbitrator.BadAuthoritySig.selector);
        arb.requestUnlock(keccak256("different"), recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt, sig);
    }

    function test_RequestUnlock_TamperedKindHashReverts() public {
        uint64 issuedAt = uint64(block.timestamp - 3600);
        bytes memory sig = _sign(AUTHORITY_SK, ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt);
        vm.expectRevert(AuthorityArbitrator.BadAuthoritySig.selector);
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, keccak256("other"), REFERENCE, issuedAt, sig);
    }

    function test_RequestUnlock_RevertsWhenRegistryRejects() public {
        // Different arbitrator (not the one the escrow points at) — registry
        // state-machine hop reverts NotArbitrator, bubbling out.
        AuthorityArbitrator rogue = new AuthorityArbitrator(authority, address(registry));
        uint64 issuedAt = uint64(block.timestamp - 3600);
        bytes memory sig = _sign(AUTHORITY_SK, ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt);
        vm.expectRevert(QKBRegistry.NotArbitrator.selector);
        rogue.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, KIND_HASH, REFERENCE, issuedAt, sig);
    }
}
