// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";

/// @notice Admin-only rotation of QKBRegistry.trustedListRoot. Called when
///         a fresh LOTL flatten ships a new rTL.
///
///         Required env:
///           REGISTRY_ADDR   address  — deployed QKBRegistry
///           NEW_ROOT_TL     bytes32  — new trustedListRoot
///         Caller (the broadcasting key) must be the registry admin.
contract UpdateTrustedRoot is Script {
    function run() external {
        QKBRegistry registry = QKBRegistry(vm.envAddress("REGISTRY_ADDR"));
        bytes32 newRoot = vm.envBytes32("NEW_ROOT_TL");
        bytes32 oldRoot = registry.trustedListRoot();

        vm.startBroadcast();
        registry.updateTrustedListRoot(newRoot);
        vm.stopBroadcast();

        console2.log("QKBRegistry:", address(registry));
        console2.logBytes32(oldRoot);
        console2.logBytes32(newRoot);
    }
}
