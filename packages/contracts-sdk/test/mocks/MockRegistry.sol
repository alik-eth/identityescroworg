// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IQKBRegistry } from "../../src/IQKBRegistry.sol";

contract MockRegistry is IQKBRegistry {
    mapping(address => bytes32) private _n;
    function set(address h, bytes32 v) external { _n[h] = v; }
    function isVerified(address h) external view returns (bool)  { return _n[h] != bytes32(0); }
    function nullifierOf(address h) external view returns (bytes32) { return _n[h]; }
    function trustedListRoot() external pure returns (bytes32) { return bytes32(uint256(0xABC)); }
}
