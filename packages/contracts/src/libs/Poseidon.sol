// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {PoseidonBytecode} from "./PoseidonBytecode.sol";

/// @title  Poseidon — bytecode-deployed BN254 Poseidon hashes (T3 + T7).
/// @notice The Poseidon contracts are deployed once per registry instance via
///         `deploy()` in the registry's constructor; the resulting addresses
///         are stashed as immutables and threaded into `hashT3` / `hashT7`
///         calls as the first parameter.
/// @dev    This library is stateless. The on-chain bytecode it deploys is
///         emitted by circomlibjs's poseidon_gencontract.js (GPL-3.0,
///         pinned via pnpm-lock.yaml to circomlibjs version 0.1.7). See
///         `script/generate-poseidon-bytecode.ts` for the in-tree generator
///         and `test/PoseidonReproducibility.t.sol` for the gate that asserts
///         `PoseidonBytecode.t3Initcode` / `t7Initcode` round-trip through
///         the generator without drift.
library Poseidon {
    /// @notice Solidity ABI of the deployed contract:
    ///   function poseidon(uint256[N]) external pure returns (uint256)
    /// We invoke it via abi.encodeWithSelector(0x29a5f2f6, …) for the
    /// uint256[2] entry and 0x11436195 for uint256[6]. Selectors confirmed
    /// against circomlibjs's own ABI emitter (poseidon_gencontract.js
    /// `generateABI`).
    bytes4 internal constant POSEIDON_T3_SELECTOR = 0x29a5f2f6; // poseidon(uint256[2])
    bytes4 internal constant POSEIDON_T7_SELECTOR = 0xf5b4a788; // poseidon(uint256[6])

    error PoseidonDeployFailed();
    error PoseidonStaticcallFailed();

    /// @notice CREATE-deploy a Poseidon contract from initcode and return its address.
    /// @param  initcode The bytecode emitted by circomlibjs's createCode(N).
    function deploy(bytes memory initcode) internal returns (address addr) {
        assembly {
            addr := create(0, add(initcode, 0x20), mload(initcode))
        }
        if (addr == address(0)) revert PoseidonDeployFailed();
    }

    /// @notice Hash 2 BN254-Fr field elements with Poseidon₂ (t=3).
    function hashT3(address t3, uint256[2] memory inp) internal view returns (uint256 out) {
        bytes memory call = abi.encodeWithSelector(POSEIDON_T3_SELECTOR, inp);
        (bool ok, bytes memory ret) = t3.staticcall(call);
        if (!ok || ret.length != 32) revert PoseidonStaticcallFailed();
        assembly { out := mload(add(ret, 0x20)) }
    }

    /// @notice Hash 6 BN254-Fr field elements with Poseidon₆ (t=7).
    function hashT7(address t7, uint256[6] memory inp) internal view returns (uint256 out) {
        bytes memory call = abi.encodeWithSelector(POSEIDON_T7_SELECTOR, inp);
        (bool ok, bytes memory ret) = t7.staticcall(call);
        if (!ok || ret.length != 32) revert PoseidonStaticcallFailed();
        assembly { out := mload(add(ret, 0x20)) }
    }
}
