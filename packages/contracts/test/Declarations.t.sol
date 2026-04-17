// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { DeclarationHashes } from "../src/constants/DeclarationHashes.sol";

contract DeclarationsTest is Test {
    function test_EN_matchesCanonicalDigest() public view {
        bytes memory text = vm.readFileBinary("packages/contracts/test/fixtures/declarations/en.txt");
        bytes32 digest = sha256(text);
        assertEq(digest, DeclarationHashes.EN, "EN declaration digest drift");
    }

    function test_UK_matchesCanonicalDigest() public view {
        bytes memory text = vm.readFileBinary("packages/contracts/test/fixtures/declarations/uk.txt");
        bytes32 digest = sha256(text);
        assertEq(digest, DeclarationHashes.UK, "UK declaration digest drift");
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
