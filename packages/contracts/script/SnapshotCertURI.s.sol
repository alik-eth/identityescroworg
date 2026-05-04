// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Script.sol";
import { ZkqesCertificate, IZkqesRegistry } from "../src/ZkqesCertificate.sol";

contract MockReg is IZkqesRegistry {
    mapping(address => bytes32) private _n;
    function set(address h, bytes32 v) external { _n[h] = v; }
    function isVerified(address h) external view returns (bool) { return _n[h] != bytes32(0); }
    function nullifierOf(address h) external view returns (bytes32) { return _n[h]; }
    function trustedListRoot() external pure returns (bytes32) { return bytes32(uint256(0)); }
}

contract SnapshotCertURI is Script {
    function run() external {
        MockReg r = new MockReg();
        ZkqesCertificate nft = new ZkqesCertificate(IZkqesRegistry(address(r)), 2_000_000_000, "Sepolia");
        r.set(address(0xA11CE), bytes32(uint256(0xDEADBEEF)));
        vm.warp(1735689600);
        vm.prank(address(0xA11CE));
        uint256 id = nft.mint();
        string memory uri = nft.tokenURI(id);
        bytes32 h = keccak256(bytes(uri));
        vm.writeFileBinary(
            "packages/contracts/test/fixtures/snapshots/cert-token-1-deadbeef.txt",
            abi.encode(h)
        );
        console.log("Snapshot written");
        console.logBytes32(h);
    }
}
