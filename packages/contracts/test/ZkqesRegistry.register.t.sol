// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { QKBVerifierV2, IGroth16VerifierV2 } from "../src/QKBVerifierV2.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

contract QKBRegistryRegisterTest is Test {
    QKBRegistry internal registry;
    StubGroth16Verifier internal rsaVerifier;
    StubGroth16Verifier internal ecdsaVerifier;
    // Back-compat alias used by existing tests (ECDSA path).
    StubGroth16Verifier internal verifier;

    address internal constant ADMIN = address(0xA11CE);
    bytes32 internal constant INITIAL_ROOT = bytes32(uint256(0xC0FFEE));

    // secp256k1 G — pubkey for priv = 1.
    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    bytes32 internal constant CTX_HASH = bytes32(uint256(0xA1));

    event BindingRegistered(
        address indexed pkAddr,
        uint8 indexed algorithmTag,
        bytes32 ctxHash,
        bytes32 declHash,
        bytes32 nullifier
    );

    function setUp() public {
        rsaVerifier = new StubGroth16Verifier();
        ecdsaVerifier = new StubGroth16Verifier();
        verifier = ecdsaVerifier; // default test path is ECDSA (tag=1)
        registry = new QKBRegistry(
            IGroth16VerifierV2(address(rsaVerifier)),
            IGroth16VerifierV2(address(ecdsaVerifier)),
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

    function _validInputs() internal view returns (QKBVerifierV2.Inputs memory i) {
        i.pkX = _splitToLimbsLE(GX);
        i.pkY = _splitToLimbsLE(GY);
        i.ctxHash = CTX_HASH;
        i.rTL = INITIAL_ROOT;
        i.declHash = DeclarationHashes.EN;
        i.timestamp = uint64(block.timestamp);
        i.algorithmTag = 1; // ECDSA
        i.nullifier = bytes32(uint256(0xBEEF));
    }

    function _zeroProof() internal pure returns (QKBVerifierV2.Proof memory p) {}

    function test_register_revertsOnInvalidProof() public {
        verifier.setAccept(false);
        QKBVerifierV2.Inputs memory i = _validInputs();
        vm.expectRevert(QKBRegistry.InvalidProof.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_revertsOnFutureTimestamp() public {
        verifier.setAccept(true);
        QKBVerifierV2.Inputs memory i = _validInputs();
        i.timestamp = uint64(block.timestamp + 1);
        vm.expectRevert(QKBRegistry.BindingFromFuture.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_revertsOnTooOldBinding() public {
        verifier.setAccept(true);
        QKBVerifierV2.Inputs memory i = _validInputs();
        vm.warp(uint256(i.timestamp) + uint256(registry.MAX_AGE()) + 1);
        vm.expectRevert(QKBRegistry.BindingTooOld.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_revertsOnAlreadyBound() public {
        verifier.setAccept(true);
        QKBVerifierV2.Inputs memory i = _validInputs();
        registry.register(_zeroProof(), i);
        QKBVerifierV2.Inputs memory i2 = _validInputs();
        // Distinct nullifier so the uniqueness guard doesn't fire first;
        // here we're exercising the pk-uniqueness path.
        i2.nullifier = bytes32(uint256(i.nullifier) ^ 1);
        vm.expectRevert(QKBRegistry.AlreadyBound.selector);
        registry.register(_zeroProof(), i2);
    }

    /// @dev declHash whitelist is enforced inside QKBVerifierV2.verify(), so an
    ///      unknown declHash short-circuits to verify()==false before register
    ///      reaches its own checks. User-visible error is InvalidProof.
    function test_register_revertsOnBadDeclHash() public {
        verifier.setAccept(true);
        QKBVerifierV2.Inputs memory i = _validInputs();
        i.declHash = keccak256("not-EN-not-UK");
        vm.expectRevert(QKBRegistry.InvalidProof.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_happyPath_writesBindingAndEmits() public {
        verifier.setAccept(true);
        QKBVerifierV2.Inputs memory i = _validInputs();
        address pkAddr = QKBVerifierV2.toPkAddress(i.pkX, i.pkY);
        assertEq(pkAddr, vm.addr(1));

        vm.expectEmit(true, true, false, true, address(registry));
        emit BindingRegistered(pkAddr, 1, CTX_HASH, DeclarationHashes.EN, i.nullifier);
        registry.register(_zeroProof(), i);

        (
            QKBRegistry.Status status,
            uint8 algorithmTag,
            uint64 boundAt,
            uint64 expiredAt,
            bytes32 ctxHash,
            bytes32 declHash,
            bytes32 nullifier
        ) = registry.bindings(pkAddr);
        assertEq(uint8(status), uint8(QKBRegistry.Status.ACTIVE));
        assertEq(algorithmTag, 1);
        assertEq(boundAt, uint64(block.timestamp));
        assertEq(expiredAt, uint64(0));
        assertEq(ctxHash, CTX_HASH);
        assertEq(declHash, DeclarationHashes.EN);
        assertEq(nullifier, i.nullifier);
    }

    function test_register_rsaPath_routesThroughRsaVerifier() public {
        // ECDSA verifier rejects everything; RSA accepts → proof routed by tag.
        rsaVerifier.setAccept(true);
        ecdsaVerifier.setAccept(false);
        QKBVerifierV2.Inputs memory i = _validInputs();
        i.algorithmTag = 0; // RSA
        address pkAddr = QKBVerifierV2.toPkAddress(i.pkX, i.pkY);

        vm.expectEmit(true, true, false, true, address(registry));
        emit BindingRegistered(pkAddr, 0, CTX_HASH, DeclarationHashes.EN, i.nullifier);
        registry.register(_zeroProof(), i);

        (, uint8 algorithmTag,,,,,) = registry.bindings(pkAddr);
        assertEq(algorithmTag, 0);
    }

    function test_register_crossDispatch_rsaAcceptsButEcdsaTagFails() public {
        // RSA accepts, ECDSA rejects. Submit with ECDSA tag → route goes to
        // ecdsaVerifier and reverts InvalidProof.
        rsaVerifier.setAccept(true);
        ecdsaVerifier.setAccept(false);
        QKBVerifierV2.Inputs memory i = _validInputs();
        i.algorithmTag = 1;
        vm.expectRevert(QKBRegistry.InvalidProof.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_crossDispatch_ecdsaAcceptsButRsaTagFails() public {
        rsaVerifier.setAccept(false);
        ecdsaVerifier.setAccept(true);
        QKBVerifierV2.Inputs memory i = _validInputs();
        i.algorithmTag = 0;
        vm.expectRevert(QKBRegistry.InvalidProof.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_revertsOnUnknownAlgorithm() public {
        rsaVerifier.setAccept(true);
        ecdsaVerifier.setAccept(true);
        QKBVerifierV2.Inputs memory i = _validInputs();
        i.algorithmTag = 2;
        vm.expectRevert(QKBRegistry.UnknownAlgorithm.selector);
        registry.register(_zeroProof(), i);
    }
}
