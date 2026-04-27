// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import { CertificateRenderer } from "../src/CertificateRenderer.sol";

contract CertificateRendererTest is Test {
    function test_tokenURI_startsWithDataUriPrefix() public pure {
        string memory uri = CertificateRenderer.tokenURI(
            42, bytes32(uint256(0xABC)), "Base", uint64(1735689600)
        );
        bytes memory b = bytes(uri);
        assertGt(b.length, 32);
        assertEq(string(_slice(b, 0, 29)), "data:application/json;base64,");
    }

    function test_tokenURI_isDeterministic() public pure {
        bytes32 n = bytes32(uint256(0xDEADBEEF));
        string memory a = CertificateRenderer.tokenURI(7, n, "Base", 1735689600);
        string memory b = CertificateRenderer.tokenURI(7, n, "Base", 1735689600);
        assertEq(a, b);
    }

    function test_tokenURI_differsByTokenId() public pure {
        bytes32 n = bytes32(uint256(0xDEADBEEF));
        string memory a = CertificateRenderer.tokenURI(1, n, "Base", 1735689600);
        string memory b = CertificateRenderer.tokenURI(2, n, "Base", 1735689600);
        assertTrue(keccak256(bytes(a)) != keccak256(bytes(b)));
    }

    function _slice(bytes memory b, uint start, uint len) private pure returns (bytes memory r) {
        r = new bytes(len);
        for (uint i = 0; i < len; i++) r[i] = b[start + i];
    }
}
