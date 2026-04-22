// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { QKBRegistryV3 } from "../src/QKBRegistryV3.sol";

/// @notice Admin-only rotation of QKBRegistryV3.trustedListRoot. Called when
///         a fresh LOTL flatten ships a new rTL.
///
///         Admin credentials are sourced from repo-root `.env` (gitignored,
///         see CLAUDE.md §10). Never commit them.
///
///         Required env:
///           REGISTRY_ADDR        address  — deployed QKBRegistryV3
///           NEW_ROOT_TL          bytes32  — new trustedListRoot
///           ADMIN_PRIVATE_KEY    uint256  — broadcasting key (must be the
///                                           registry admin or the call reverts
///                                           NotAdmin on-chain)
contract UpdateTrustedRoot is Script {
    function run() external {
        QKBRegistryV3 registry = QKBRegistryV3(vm.envAddress("REGISTRY_ADDR"));
        bytes32 newRoot = vm.envBytes32("NEW_ROOT_TL");
        uint256 adminPriv = vm.envUint("ADMIN_PRIVATE_KEY");
        bytes32 oldRoot = registry.trustedListRoot();

        vm.startBroadcast(adminPriv);
        registry.updateTrustedListRoot(newRoot);
        vm.stopBroadcast();

        console2.log("QKBRegistryV3:", address(registry));
        console2.log("admin (broadcaster):", vm.addr(adminPriv));
        console2.log("chainid:", block.chainid);
        console2.logBytes32(oldRoot);
        console2.logBytes32(newRoot);
    }
}
