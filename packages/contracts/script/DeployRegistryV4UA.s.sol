// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { ZkqesRegistryV4 } from "../src/ZkqesRegistryV4.sol";

/// @notice v5 redeploy of `ZkqesRegistryV4` for the Ukraine (UA) configuration.
///         Country tag is constructor-frozen; admin can rotate roots and verifier
///         addresses post-deploy via the existing setters.
///
///         Required env:
///           ADMIN_PRIVATE_KEY      uint256 — broadcast key.
///           ADMIN_ADDRESS          address — must equal `vm.addr(ADMIN_PRIVATE_KEY)`.
///           UA_TRUSTED_LIST_ROOT   bytes32 — initial trustedListRoot.
///           UA_POLICY_ROOT         bytes32 — initial policyRoot.
///           LEAF_VERIFIER_ADDR     address — UA-specific 16-signal leaf verifier.
///           CHAIN_VERIFIER_ADDR    address — shared 3-signal chain verifier.
///           AGE_VERIFIER_ADDR      address — shared 3-signal age verifier.
contract DeployRegistryV4UA is Script {
    error AdminMismatch();

    function run() external returns (address registryAddr) {
        bytes32 trustedListRoot = vm.envBytes32("UA_TRUSTED_LIST_ROOT");
        bytes32 policyRoot      = vm.envBytes32("UA_POLICY_ROOT");
        address leaf            = vm.envAddress("LEAF_VERIFIER_ADDR");
        address chain           = vm.envAddress("CHAIN_VERIFIER_ADDR");
        address age             = vm.envAddress("AGE_VERIFIER_ADDR");
        address admin           = vm.envAddress("ADMIN_ADDRESS");
        uint256 pk              = vm.envUint("ADMIN_PRIVATE_KEY");
        if (vm.addr(pk) != admin) revert AdminMismatch();

        vm.startBroadcast(pk);
        ZkqesRegistryV4 r = new ZkqesRegistryV4(
            "UA", trustedListRoot, policyRoot, leaf, chain, age, admin
        );
        vm.stopBroadcast();
        registryAddr = address(r);
        console2.log("ZkqesRegistryV4 deployed at:", registryAddr);
        console2.log("  admin            :", admin);
        console2.log("  leafVerifier     :", leaf);
        console2.log("  chainVerifier    :", chain);
        console2.log("  ageVerifier      :", age);
        console2.log("  chainid          :", block.chainid);
        console2.logBytes32(trustedListRoot);
        console2.logBytes32(policyRoot);
    }
}
