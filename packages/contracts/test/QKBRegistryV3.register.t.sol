// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { QKBRegistryV3 } from "../src/QKBRegistryV3.sol";
import { QKBVerifier } from "../src/QKBVerifier.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import { V3Harness } from "./helpers/V3Harness.sol";

contract QKBRegistryV3RegisterTest is V3Harness {
    bytes32 internal constant NULLIFIER = bytes32(uint256(0xBEEF));

    event BindingRegistered(
        address indexed pkAddr,
        uint8 indexed algorithmTag,
        bytes32 ctxHash,
        bytes32 declHash,
        bytes32 nullifier
    );

    function setUp() public {
        _harnessSetUp();
    }

    // ----- Happy path × 2 (ECDSA + RSA) --------------------------------------

    function test_register_ecdsa_happyPath_writesBindingAndEmits() public {
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        QKBVerifier.LeafInputs memory leaf   = _leafInputs(NULLIFIER);
        QKBVerifier.ChainInputs memory chain = _chainInputs(1);
        address pkAddr = QKBVerifier.toPkAddress(leaf.pkX, leaf.pkY);
        assertEq(pkAddr, vm.addr(1));

        vm.expectEmit(true, true, false, true, address(registry));
        emit BindingRegistered(pkAddr, 1, CTX_HASH, DeclarationHashes.EN, NULLIFIER);
        registry.register(_zeroProof(), leaf, _zeroProof(), chain);

        (
            QKBRegistryV3.Status status,
            uint8 algorithmTag,
            uint64 boundAt,
            uint64 expiredAt,
            bytes32 ctxHash,
            bytes32 declHash,
            bytes32 nullifier
        ) = registry.bindings(pkAddr);
        assertEq(uint8(status), uint8(QKBRegistryV3.Status.ACTIVE));
        assertEq(algorithmTag, 1);
        assertEq(boundAt, uint64(block.timestamp));
        assertEq(expiredAt, uint64(0));
        assertEq(ctxHash, CTX_HASH);
        assertEq(declHash, DeclarationHashes.EN);
        assertEq(nullifier, NULLIFIER);
    }

    function test_register_rsa_happyPath_routesThroughRsaSlots() public {
        // Ecdsa verifiers reject; RSA accepts → must route via RSA slots.
        rsaLeaf.setAccept(true);
        rsaChain.setAccept(true);
        ecdsaLeaf.setAccept(false);
        ecdsaChain.setAccept(false);

        QKBVerifier.LeafInputs memory leaf   = _leafInputs(NULLIFIER);
        QKBVerifier.ChainInputs memory chain = _chainInputs(0);
        address pkAddr = QKBVerifier.toPkAddress(leaf.pkX, leaf.pkY);

        vm.expectEmit(true, true, false, true, address(registry));
        emit BindingRegistered(pkAddr, 0, CTX_HASH, DeclarationHashes.EN, NULLIFIER);
        registry.register(_zeroProof(), leaf, _zeroProof(), chain);

        (, uint8 algorithmTag,,,,,) = registry.bindings(pkAddr);
        assertEq(algorithmTag, 0);
    }

    // ----- Revert paths ------------------------------------------------------

    function test_register_revertsOnInvalidLeafProof() public {
        ecdsaLeaf.setAccept(false);
        ecdsaChain.setAccept(true);
        vm.expectRevert(QKBRegistryV3.InvalidProof.selector);
        registry.register(_zeroProof(), _leafInputs(NULLIFIER), _zeroProof(), _chainInputs(1));
    }

    function test_register_revertsOnInvalidChainProof() public {
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(false);
        vm.expectRevert(QKBRegistryV3.InvalidProof.selector);
        registry.register(_zeroProof(), _leafInputs(NULLIFIER), _zeroProof(), _chainInputs(1));
    }

    function test_register_revertsOnRootMismatch() public {
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        QKBVerifier.ChainInputs memory chain = _chainInputs(1);
        chain.rTL = bytes32(uint256(0xDEAD));
        vm.expectRevert(QKBRegistryV3.RootMismatch.selector);
        registry.register(_zeroProof(), _leafInputs(NULLIFIER), _zeroProof(), chain);
    }

    function test_register_revertsOnLeafSpkiCommitMismatch() public {
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        QKBVerifier.ChainInputs memory chain = _chainInputs(1);
        chain.leafSpkiCommit = bytes32(uint256(SPKI_COMMIT) ^ 1);
        vm.expectRevert(QKBRegistryV3.LeafSpkiCommitMismatch.selector);
        registry.register(_zeroProof(), _leafInputs(NULLIFIER), _zeroProof(), chain);
    }

    function test_register_revertsOnFutureTimestamp() public {
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        QKBVerifier.LeafInputs memory leaf = _leafInputs(NULLIFIER);
        leaf.timestamp = uint64(block.timestamp + 1);
        vm.expectRevert(QKBRegistryV3.BindingFromFuture.selector);
        registry.register(_zeroProof(), leaf, _zeroProof(), _chainInputs(1));
    }

    function test_register_revertsOnTooOldBinding() public {
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        QKBVerifier.LeafInputs memory leaf = _leafInputs(NULLIFIER);
        vm.warp(uint256(leaf.timestamp) + uint256(registry.MAX_AGE()) + 1);
        vm.expectRevert(QKBRegistryV3.BindingTooOld.selector);
        registry.register(_zeroProof(), leaf, _zeroProof(), _chainInputs(1));
    }

    function test_register_revertsOnAlreadyBound() public {
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        registry.register(_zeroProof(), _leafInputs(NULLIFIER), _zeroProof(), _chainInputs(1));
        // Second attempt — same pk but fresh nullifier so uniqueness doesn't
        // fire first; exercising the pk-uniqueness path.
        QKBVerifier.LeafInputs memory leaf2 = _leafInputs(bytes32(uint256(NULLIFIER) ^ 1));
        vm.expectRevert(QKBRegistryV3.AlreadyBound.selector);
        registry.register(_zeroProof(), leaf2, _zeroProof(), _chainInputs(1));
    }

    /// @dev declHash whitelist is enforced inside QKBVerifier.verify(); bad
    ///      declHash ⇒ verify() returns false ⇒ user-visible InvalidProof.
    function test_register_revertsOnBadDeclHash() public {
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        QKBVerifier.LeafInputs memory leaf = _leafInputs(NULLIFIER);
        leaf.declHash = keccak256("not-EN-not-UK");
        vm.expectRevert(QKBRegistryV3.InvalidProof.selector);
        registry.register(_zeroProof(), leaf, _zeroProof(), _chainInputs(1));
    }

    function test_register_revertsOnUnknownAlgorithm() public {
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        QKBVerifier.ChainInputs memory chain = _chainInputs(2);
        vm.expectRevert(QKBRegistryV3.UnknownAlgorithm.selector);
        registry.register(_zeroProof(), _leafInputs(NULLIFIER), _zeroProof(), chain);
    }

    // ----- Cross-dispatch sanity --------------------------------------------

    function test_register_crossDispatch_rsaAcceptsButEcdsaTagFails() public {
        // RSA slots wide open, ECDSA slots closed. Submit with ECDSA tag →
        // route goes to ECDSA slot and reverts InvalidProof.
        rsaLeaf.setAccept(true);
        rsaChain.setAccept(true);
        ecdsaLeaf.setAccept(false);
        ecdsaChain.setAccept(false);
        vm.expectRevert(QKBRegistryV3.InvalidProof.selector);
        registry.register(_zeroProof(), _leafInputs(NULLIFIER), _zeroProof(), _chainInputs(1));
    }

    function test_register_crossDispatch_ecdsaAcceptsButRsaTagFails() public {
        rsaLeaf.setAccept(false);
        rsaChain.setAccept(false);
        ecdsaLeaf.setAccept(true);
        ecdsaChain.setAccept(true);
        vm.expectRevert(QKBRegistryV3.InvalidProof.selector);
        registry.register(_zeroProof(), _leafInputs(NULLIFIER), _zeroProof(), _chainInputs(0));
    }
}
