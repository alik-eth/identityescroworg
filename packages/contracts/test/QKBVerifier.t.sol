// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { QKBVerifier, IGroth16Verifier } from "../src/QKBVerifier.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

contract QKBVerifierTest is Test {
    StubGroth16Verifier internal stub;

    // secp256k1 generator G — the public key for private key = 1.
    // Reference: SEC 2 §2.7.1.
    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    function setUp() public {
        stub = new StubGroth16Verifier();
    }

    function _zeroProof() internal pure returns (QKBVerifier.Proof memory p) {
        // Defaults: all zeros — stub verifier ignores.
    }

    function _splitToLimbsLE(uint256 v) internal pure returns (uint256[4] memory out) {
        out[0] = v & type(uint64).max;
        out[1] = (v >> 64) & type(uint64).max;
        out[2] = (v >> 128) & type(uint64).max;
        out[3] = (v >> 192) & type(uint64).max;
    }

    function _baseInputs() internal pure returns (QKBVerifier.Inputs memory i) {
        i.pkX = _splitToLimbsLE(GX);
        i.pkY = _splitToLimbsLE(GY);
        i.ctxHash = bytes32(uint256(0xA1));
        i.rTL = bytes32(uint256(0xB2));
        i.declHash = DeclarationHashes.EN;
        i.timestamp = 1_700_000_000;
        i.algorithmTag = 0;
    }

    function test_verify_packsInputsAndReturnsTrue() public {
        stub.setAccept(true);
        QKBVerifier.Inputs memory i = _baseInputs();
        assertTrue(QKBVerifier.verify(IGroth16Verifier(address(stub)), _zeroProof(), i));
    }

    function test_verify_returnsFalseWhenStubRejects() public {
        stub.setAccept(false);
        QKBVerifier.Inputs memory i = _baseInputs();
        assertFalse(QKBVerifier.verify(IGroth16Verifier(address(stub)), _zeroProof(), i));
    }

    function test_verify_rejectsUnknownDeclHashWithoutCallingVerifier() public {
        stub.setAccept(true);
        QKBVerifier.Inputs memory i = _baseInputs();
        i.declHash = bytes32(uint256(1));
        assertFalse(QKBVerifier.verify(IGroth16Verifier(address(stub)), _zeroProof(), i));
    }

    function test_verify_acceptsUKDeclHash() public {
        stub.setAccept(true);
        QKBVerifier.Inputs memory i = _baseInputs();
        i.declHash = DeclarationHashes.UK;
        assertTrue(QKBVerifier.verify(IGroth16Verifier(address(stub)), _zeroProof(), i));
    }

    function test_toPkAddress_matchesVmAddrAcrossPrivkeys() public view {
        // Use vm.addr to derive ground-truth addresses, then provide
        // hardcoded pubkey coords for the same privkeys.
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
