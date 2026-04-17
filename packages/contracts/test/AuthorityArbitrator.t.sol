// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { AuthorityArbitrator } from "../src/arbitrators/AuthorityArbitrator.sol";
import { IArbitrator } from "../src/arbitrators/IArbitrator.sol";

contract AuthorityArbitratorTest is Test {
    AuthorityArbitrator internal arb;
    uint256 internal constant AUTHORITY_SK = 0xA11CE;
    address internal authority;
    address internal constant ALICE = address(0xB0B);

    bytes32 internal constant ESCROW_ID = keccak256("e1");
    bytes internal recipientPk = hex"04aa";
    bytes32 internal constant EVIDENCE_HASH = keccak256("court-order-123");

    event Unlock(bytes32 indexed escrowId, bytes recipientHybridPk);

    function setUp() public {
        authority = vm.addr(AUTHORITY_SK);
        arb = new AuthorityArbitrator(authority);
    }

    function _sign(uint256 sk, bytes32 escrowId, bytes memory rpk, bytes32 eh) internal pure returns (bytes memory) {
        bytes32 digest = keccak256(abi.encode(escrowId, rpk, eh));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_constructor_revertsOnZeroAuthority() public {
        vm.expectRevert(bytes("AuthorityArbitrator: zero authority"));
        new AuthorityArbitrator(address(0));
    }

    function test_validAuthoritySigEmitsUnlock() public {
        bytes memory sig = _sign(AUTHORITY_SK, ESCROW_ID, recipientPk, EVIDENCE_HASH);
        vm.expectEmit(true, false, false, true, address(arb));
        emit Unlock(ESCROW_ID, recipientPk);
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, sig);
        assertTrue(arb.evidenceHashUsed(EVIDENCE_HASH));
    }

    function test_wrongSignerReverts() public {
        bytes memory sig = _sign(0xB0B, ESCROW_ID, recipientPk, EVIDENCE_HASH);
        vm.expectRevert(bytes("AuthorityArbitrator: bad authority sig"));
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, sig);
    }

    function test_replayedEvidenceReverts() public {
        bytes memory sig = _sign(AUTHORITY_SK, ESCROW_ID, recipientPk, EVIDENCE_HASH);
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, sig);
        vm.expectRevert(bytes("AuthorityArbitrator: evidence replayed"));
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, sig);
    }

    function test_badSigLengthReverts() public {
        bytes memory badSig = hex"aabb";
        vm.expectRevert(bytes("AuthorityArbitrator: bad sig length"));
        arb.requestUnlock(ESCROW_ID, recipientPk, EVIDENCE_HASH, badSig);
    }

    function test_tamperedEscrowIdReverts() public {
        bytes memory sig = _sign(AUTHORITY_SK, ESCROW_ID, recipientPk, EVIDENCE_HASH);
        vm.expectRevert(bytes("AuthorityArbitrator: bad authority sig"));
        arb.requestUnlock(keccak256("different"), recipientPk, EVIDENCE_HASH, sig);
    }
}
