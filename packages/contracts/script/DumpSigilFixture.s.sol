// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;
import "forge-std/Script.sol";
import { SigilRenderer } from "../src/SigilRenderer.sol";

contract DumpSigilFixture is Script {
    function run() external {
        string memory s = SigilRenderer.render(bytes32(uint256(0xDEADBEEF)));
        vm.writeFile("packages/web/tests/fixtures/sigil-deadbeef.svg.txt", s);
    }
}
