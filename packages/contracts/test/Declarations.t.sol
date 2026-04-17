// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";

contract DeclarationsTest is Test {
    /// @dev BN254 scalar field prime. The circuit packs sha256(declaration)
    ///      MSB-first into a field element, which reduces mod p when the raw
    ///      digest exceeds it — both canonical declarations happen to have
    ///      the high bit set so both reduce. Contract constants store the
    ///      *reduced* value so on-chain whitelist matches circuit output.
    uint256 internal constant BN254_P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function test_EN_matchesCanonicalDigest() public view {
        bytes memory text = vm.readFileBinary("packages/contracts/test/fixtures/declarations/en.txt");
        bytes32 digest = sha256(text);
        bytes32 digestModP = bytes32(uint256(digest) % BN254_P);
        assertEq(digestModP, DeclarationHashes.EN, "EN declaration digest drift");
    }

    function test_UK_matchesCanonicalDigest() public view {
        bytes memory text = vm.readFileBinary("packages/contracts/test/fixtures/declarations/uk.txt");
        bytes32 digest = sha256(text);
        bytes32 digestModP = bytes32(uint256(digest) % BN254_P);
        assertEq(digestModP, DeclarationHashes.UK, "UK declaration digest drift");
    }

    function test_isAllowed_acceptsBothCanonicalDigests() public pure {
        assertTrue(DeclarationHashes.isAllowed(DeclarationHashes.EN));
        assertTrue(DeclarationHashes.isAllowed(DeclarationHashes.UK));
    }

    function test_isAllowed_rejectsUnknownDigest() public pure {
        assertFalse(DeclarationHashes.isAllowed(bytes32(uint256(1))));
        assertFalse(DeclarationHashes.isAllowed(bytes32(0)));
    }
}
