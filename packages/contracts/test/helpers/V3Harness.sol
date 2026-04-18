// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { QKBRegistryV3 } from "../../src/QKBRegistryV3.sol";
import {
    QKBVerifier,
    IGroth16LeafVerifier,
    IGroth16ChainVerifier
} from "../../src/QKBVerifier.sol";
import { DeclarationHashes } from "../../src/constants/DeclarationHashes.sol";
import {
    StubGroth16LeafVerifier,
    StubGroth16ChainVerifier
} from "./StubSplitVerifiers.sol";

/// @notice Shared base for the QKBRegistryV3 test suites. Encapsulates the
///         four-slot stub verifier deploy, the registry deploy, and the
///         standard split-proof input builders. Each concrete test file
///         inherits this and adds its behaviour-specific tests.
abstract contract V3Harness is Test {
    QKBRegistryV3 internal registry;

    StubGroth16LeafVerifier  internal rsaLeaf;
    StubGroth16ChainVerifier internal rsaChain;
    StubGroth16LeafVerifier  internal ecdsaLeaf;
    StubGroth16ChainVerifier internal ecdsaChain;

    address internal constant ADMIN = address(0xA11CE);
    bytes32 internal constant INITIAL_ROOT = bytes32(uint256(0xC0FFEE));

    // secp256k1 generator G — pubkey for priv = 1.
    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    // 2G — pubkey for priv = 2.
    uint256 internal constant GX2 = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5;
    uint256 internal constant GY2 = 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A;

    bytes32 internal constant CTX_HASH       = bytes32(uint256(0xA1));
    bytes32 internal constant SPKI_COMMIT    = bytes32(uint256(0xDEADBEEF));
    bytes32 internal constant DEFAULT_NULL   = bytes32(uint256(0xBEEF));

    function _harnessSetUp() internal {
        rsaLeaf    = new StubGroth16LeafVerifier();
        rsaChain   = new StubGroth16ChainVerifier();
        ecdsaLeaf  = new StubGroth16LeafVerifier();
        ecdsaChain = new StubGroth16ChainVerifier();
        registry   = new QKBRegistryV3(
            IGroth16LeafVerifier(address(rsaLeaf)),
            IGroth16ChainVerifier(address(rsaChain)),
            IGroth16LeafVerifier(address(ecdsaLeaf)),
            IGroth16ChainVerifier(address(ecdsaChain)),
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

    /// @dev Default leaf inputs — priv=1 (G), EN declaration, default
    ///      nullifier, commit = SPKI_COMMIT. Callers mutate fields as
    ///      needed for specific revert cases.
    function _leafInputs(bytes32 nullifier) internal view returns (QKBVerifier.LeafInputs memory i) {
        i.pkX            = _splitToLimbsLE(GX);
        i.pkY            = _splitToLimbsLE(GY);
        i.ctxHash        = CTX_HASH;
        i.declHash       = DeclarationHashes.EN;
        i.timestamp      = uint64(block.timestamp);
        i.nullifier      = nullifier;
        i.leafSpkiCommit = SPKI_COMMIT;
    }

    /// @dev Default chain inputs — rTL = initial, algorithmTag = ECDSA,
    ///      commit = SPKI_COMMIT (must equal the leaf's).
    function _chainInputs(uint8 algorithmTag) internal pure returns (QKBVerifier.ChainInputs memory i) {
        i.rTL            = INITIAL_ROOT;
        i.algorithmTag   = algorithmTag;
        i.leafSpkiCommit = SPKI_COMMIT;
    }

    /// @dev All-zero proof struct. Stubs ignore proof contents entirely.
    function _zeroProof() internal pure returns (QKBVerifier.Proof memory p) {}
}
