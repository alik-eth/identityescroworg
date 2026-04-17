// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { QKBVerifier, IGroth16Verifier } from "../src/QKBVerifier.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

contract QKBRegistryRegisterTest is Test {
    QKBRegistry internal registry;
    StubGroth16Verifier internal rsa;
    StubGroth16Verifier internal ecdsa;

    address internal constant ADMIN = address(0xA11CE);
    bytes32 internal constant INITIAL_ROOT = bytes32(uint256(0xC0FFEE));

    // secp256k1 G — pubkey for priv = 1.
    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    bytes32 internal constant CTX_HASH = bytes32(uint256(0xA1));

    event BindingRegistered(address indexed pkAddr, bytes32 ctxHash, bytes32 declHash, uint8 algorithmTag);

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
    }

    function _splitToLimbsLE(uint256 v) internal pure returns (uint256[4] memory out) {
        out[0] = v & type(uint64).max;
        out[1] = (v >> 64) & type(uint64).max;
        out[2] = (v >> 128) & type(uint64).max;
        out[3] = (v >> 192) & type(uint64).max;
    }

    /// @dev Defaults to algorithmTag=0 (RSA). Tests override for ECDSA paths.
    function _validInputs() internal view returns (QKBVerifier.Inputs memory i) {
        i.pkX = _splitToLimbsLE(GX);
        i.pkY = _splitToLimbsLE(GY);
        i.ctxHash = CTX_HASH;
        i.rTL = INITIAL_ROOT;
        i.declHash = DeclarationHashes.EN;
        i.timestamp = uint64(block.timestamp);
        i.algorithmTag = 0; // RSA
    }

    function _zeroProof() internal pure returns (QKBVerifier.Proof memory p) {}

    function test_register_revertsOnInvalidProof() public {
        rsa.setAccept(false);
        QKBVerifier.Inputs memory i = _validInputs();
        vm.expectRevert(QKBRegistry.InvalidProof.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_revertsOnRootMismatch() public {
        rsa.setAccept(true);
        QKBVerifier.Inputs memory i = _validInputs();
        i.rTL = bytes32(uint256(0xBADBAD));
        vm.expectRevert(QKBRegistry.RootMismatch.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_revertsOnFutureTimestamp() public {
        rsa.setAccept(true);
        QKBVerifier.Inputs memory i = _validInputs();
        i.timestamp = uint64(block.timestamp + 1);
        vm.expectRevert(QKBRegistry.BindingFromFuture.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_revertsOnTooOldBinding() public {
        rsa.setAccept(true);
        QKBVerifier.Inputs memory i = _validInputs();
        vm.warp(uint256(i.timestamp) + uint256(registry.MAX_AGE()) + 1);
        vm.expectRevert(QKBRegistry.BindingTooOld.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_revertsOnAlreadyBound() public {
        rsa.setAccept(true);
        QKBVerifier.Inputs memory i = _validInputs();
        registry.register(_zeroProof(), i);
        QKBVerifier.Inputs memory i2 = _validInputs();
        vm.expectRevert(QKBRegistry.AlreadyBound.selector);
        registry.register(_zeroProof(), i2);
    }

    /// @dev declHash whitelist is enforced inside QKBVerifier.verify(), so an
    ///      unknown declHash short-circuits to verify()==false before register
    ///      reaches its own checks. The user-visible error is therefore
    ///      InvalidProof — same defence-in-depth story, one fewer custom
    ///      error in the ABI.
    function test_register_revertsOnBadDeclHash() public {
        rsa.setAccept(true);
        QKBVerifier.Inputs memory i = _validInputs();
        i.declHash = keccak256("not-EN-not-UK");
        vm.expectRevert(QKBRegistry.InvalidProof.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_revertsOnUnknownAlgorithm() public {
        rsa.setAccept(true);
        ecdsa.setAccept(true);
        QKBVerifier.Inputs memory i = _validInputs();
        i.algorithmTag = 2;
        vm.expectRevert(QKBRegistry.UnknownAlgorithm.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_rsa_happyPath_writesBindingAndEmits() public {
        rsa.setAccept(true);
        ecdsa.setAccept(false); // proves dispatch picks the right one
        QKBVerifier.Inputs memory i = _validInputs(); // algorithmTag = 0
        address pkAddr = QKBVerifier.toPkAddress(i.pkX, i.pkY);
        assertEq(pkAddr, vm.addr(1));

        vm.expectEmit(true, false, false, true, address(registry));
        emit BindingRegistered(pkAddr, CTX_HASH, DeclarationHashes.EN, 0);
        registry.register(_zeroProof(), i);

        (
            QKBRegistry.Status status,
            uint64 boundAt,
            uint64 expiredAt,
            uint8 algorithmTag,
            bytes32 ctxHash,
            bytes32 declHash
        ) = registry.bindings(pkAddr);
        assertEq(uint8(status), uint8(QKBRegistry.Status.ACTIVE));
        assertEq(boundAt, uint64(block.timestamp));
        assertEq(expiredAt, uint64(0));
        assertEq(algorithmTag, uint8(0));
        assertEq(ctxHash, CTX_HASH);
        assertEq(declHash, DeclarationHashes.EN);
    }

    function test_register_ecdsa_happyPath_writesBindingAndEmits() public {
        rsa.setAccept(false); // proves dispatch picks the right one
        ecdsa.setAccept(true);
        QKBVerifier.Inputs memory i = _validInputs();
        i.algorithmTag = 1;
        address pkAddr = QKBVerifier.toPkAddress(i.pkX, i.pkY);

        vm.expectEmit(true, false, false, true, address(registry));
        emit BindingRegistered(pkAddr, CTX_HASH, DeclarationHashes.EN, 1);
        registry.register(_zeroProof(), i);

        (,,, uint8 algorithmTag,,) = registry.bindings(pkAddr);
        assertEq(algorithmTag, uint8(1));
    }

    function test_register_rsa_revertsWhenRsaStubRejects_evenIfEcdsaAccepts() public {
        rsa.setAccept(false);
        ecdsa.setAccept(true);
        QKBVerifier.Inputs memory i = _validInputs(); // tag=0 → RSA
        vm.expectRevert(QKBRegistry.InvalidProof.selector);
        registry.register(_zeroProof(), i);
    }

    function test_register_ecdsa_revertsWhenEcdsaStubRejects_evenIfRsaAccepts() public {
        rsa.setAccept(true);
        ecdsa.setAccept(false);
        QKBVerifier.Inputs memory i = _validInputs();
        i.algorithmTag = 1;
        vm.expectRevert(QKBRegistry.InvalidProof.selector);
        registry.register(_zeroProof(), i);
    }
}
