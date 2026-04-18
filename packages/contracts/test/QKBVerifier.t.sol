// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import {
    QKBVerifier,
    IGroth16LeafVerifier,
    IGroth16ChainVerifier
} from "../src/QKBVerifier.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import {
    StubGroth16LeafVerifier,
    StubGroth16ChainVerifier
} from "./helpers/StubSplitVerifiers.sol";

contract QKBVerifierTest is Test {
    StubGroth16LeafVerifier  internal leafStub;
    StubGroth16ChainVerifier internal chainStub;

    // secp256k1 generator G — the public key for private key = 1.
    // Reference: SEC 2 §2.7.1.
    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    // Opaque but non-zero glue value used in the happy-path tests.
    bytes32 internal constant SPKI_COMMIT = bytes32(uint256(0xDEADBEEF));

    function setUp() public {
        leafStub  = new StubGroth16LeafVerifier();
        chainStub = new StubGroth16ChainVerifier();
    }

    function _zeroProof() internal pure returns (QKBVerifier.Proof memory p) {
        // All zeros — stubs ignore.
    }

    function _splitToLimbsLE(uint256 v) internal pure returns (uint256[4] memory out) {
        out[0] = v & type(uint64).max;
        out[1] = (v >> 64) & type(uint64).max;
        out[2] = (v >> 128) & type(uint64).max;
        out[3] = (v >> 192) & type(uint64).max;
    }

    function _baseLeaf() internal pure returns (QKBVerifier.LeafInputs memory i) {
        i.pkX            = _splitToLimbsLE(GX);
        i.pkY            = _splitToLimbsLE(GY);
        i.ctxHash        = bytes32(uint256(0xA1));
        i.declHash       = DeclarationHashes.EN;
        i.timestamp      = 1_700_000_000;
        i.nullifier      = bytes32(uint256(0xBEEF));
        i.leafSpkiCommit = SPKI_COMMIT;
    }

    function _baseChain() internal pure returns (QKBVerifier.ChainInputs memory i) {
        i.rTL            = bytes32(uint256(0xC0FFEE));
        i.algorithmTag   = 1; // ECDSA
        i.leafSpkiCommit = SPKI_COMMIT;
    }

    function _verify(
        QKBVerifier.LeafInputs memory leaf,
        QKBVerifier.ChainInputs memory chain
    ) internal view returns (bool) {
        return QKBVerifier.verify(
            IGroth16LeafVerifier(address(leafStub)),
            IGroth16ChainVerifier(address(chainStub)),
            _zeroProof(),
            leaf,
            _zeroProof(),
            chain
        );
    }

    // ----- Happy-path / basic acceptance ------------------------------------

    function test_verify_packsInputsAndReturnsTrue() public {
        leafStub.setAccept(true);
        chainStub.setAccept(true);
        assertTrue(_verify(_baseLeaf(), _baseChain()));
    }

    function test_verify_acceptsUKDeclHash() public {
        leafStub.setAccept(true);
        chainStub.setAccept(true);
        QKBVerifier.LeafInputs memory leaf = _baseLeaf();
        leaf.declHash = DeclarationHashes.UK;
        assertTrue(_verify(leaf, _baseChain()));
    }

    // ----- Stub-driven negative cases ---------------------------------------

    function test_verify_returnsFalseWhenLeafStubRejects() public {
        leafStub.setAccept(false);
        chainStub.setAccept(true);
        assertFalse(_verify(_baseLeaf(), _baseChain()));
    }

    function test_verify_returnsFalseWhenChainStubRejects() public {
        leafStub.setAccept(true);
        chainStub.setAccept(false);
        assertFalse(_verify(_baseLeaf(), _baseChain()));
    }

    // ----- DeclHash whitelist (defence-in-depth) ----------------------------

    function test_verify_rejectsUnknownDeclHashWithoutCallingVerifiers() public {
        // Both stubs accept by default — prove the declHash guard short-
        // circuits before either is consulted.
        leafStub.setAccept(true);
        chainStub.setAccept(true);
        QKBVerifier.LeafInputs memory leaf = _baseLeaf();
        leaf.declHash = bytes32(uint256(1));
        assertFalse(_verify(leaf, _baseChain()));
    }

    // ----- leafSpkiCommit equality glue -------------------------------------

    function test_verify_rejectsCommitMismatch() public {
        leafStub.setAccept(true);
        chainStub.setAccept(true);
        QKBVerifier.LeafInputs memory leaf = _baseLeaf();
        QKBVerifier.ChainInputs memory chain = _baseChain();
        // Perturb chain's commit — glue no longer holds.
        chain.leafSpkiCommit = bytes32(uint256(SPKI_COMMIT) ^ 1);
        assertFalse(_verify(leaf, chain));
    }

    function test_verify_rejectsBothMismatchedEvenWhenStubsAccept() public {
        // Defence-in-depth: commit mismatch must fail even with both stubs
        // wide-open and a valid declHash.
        leafStub.setAccept(true);
        chainStub.setAccept(true);
        QKBVerifier.LeafInputs memory leaf = _baseLeaf();
        leaf.leafSpkiCommit = bytes32(uint256(1));
        QKBVerifier.ChainInputs memory chain = _baseChain();
        chain.leafSpkiCommit = bytes32(uint256(2));
        assertFalse(_verify(leaf, chain));
    }

    // ----- toPkAddress unchanged from V2 ------------------------------------

    function test_toPkAddress_matchesVmAddrAcrossPrivkeys() public view {
        // priv = 1 → G
        assertEq(QKBVerifier.toPkAddress(_splitToLimbsLE(GX), _splitToLimbsLE(GY)), vm.addr(1));

        // priv = 2 → 2G
        uint256 px2 = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5;
        uint256 py2 = 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A;
        assertEq(QKBVerifier.toPkAddress(_splitToLimbsLE(px2), _splitToLimbsLE(py2)), vm.addr(2));

        // priv = 3 → 3G
        uint256 px3 = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9;
        uint256 py3 = 0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672;
        assertEq(QKBVerifier.toPkAddress(_splitToLimbsLE(px3), _splitToLimbsLE(py3)), vm.addr(3));
    }
}
