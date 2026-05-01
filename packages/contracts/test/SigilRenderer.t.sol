// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import { SigilRenderer } from "../src/SigilRenderer.sol";

contract SigilRendererTest is Test {
    function test_render_isDeterministic() public pure {
        bytes32 nullifier = bytes32(uint256(0xDEADBEEFCAFEBABE));
        string memory a = SigilRenderer.render(nullifier);
        string memory b = SigilRenderer.render(nullifier);
        assertEq(a, b, "same nullifier must produce identical SVG fragment");
    }

    function test_render_differsByNullifier() public pure {
        string memory a = SigilRenderer.render(bytes32(uint256(1)));
        string memory b = SigilRenderer.render(bytes32(uint256(2)));
        assertTrue(keccak256(bytes(a)) != keccak256(bytes(b)), "different nullifiers must produce different SVGs");
    }

    function test_render_returnsNonEmptyValidSvgFragment() public pure {
        string memory svg = SigilRenderer.render(bytes32(uint256(0xABC)));
        bytes memory b = bytes(svg);
        assertGt(b.length, 100, "fragment should be substantial");
        assertEq(b[0], bytes1("<"), "must start with an SVG element");
    }

    function test_render_zeroNullifierProducesValidOutput() public pure {
        // Edge case: even zero (theoretically impossible from circuit) renders
        string memory svg = SigilRenderer.render(bytes32(0));
        assertGt(bytes(svg).length, 100);
    }
}
