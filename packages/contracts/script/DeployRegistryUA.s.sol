// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { ZkqesRegistryV4 } from "../src/ZkqesRegistryV4.sol";

/// @notice Fresh deploy of `ZkqesRegistryV4` for the Ukraine (UA) country
///         configuration. The registry's `country` field is constructor-
///         frozen; admin can rotate trust roots and verifier addresses
///         later via the setters.
///
///         Required env:
///           ADMIN_PRIVATE_KEY      uint256 — broadcast key. `admin_` will
///                                             be set to `vm.addr(pk)`.
///           UA_TRUSTED_LIST_ROOT   bytes32 — initial `trustedListRoot`.
///           UA_POLICY_ROOT         bytes32 — initial `policyRoot`.
///           UA_LEAF_VERIFIER       address — UA-specific 16-signal leaf verifier.
///           SHARED_CHAIN_VERIFIER  address — shared 3-signal chain verifier.
///           SHARED_AGE_VERIFIER    address — shared 3-signal age verifier.
///
///         Anvil dry-run (verifier addresses are cast to interface types
///         but never called by the constructor, so any non-zero placeholder
///         address works — typically 0x...0001/0002/0003):
///           anvil --port 8545 &
///           ADMIN_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
///           UA_TRUSTED_LIST_ROOT=0x0000000000000000000000000000000000000000000000000000000002a5ce7b \
///           UA_POLICY_ROOT=0x0000000000000000000000000000000000000000000000000000000000000009 \
///           UA_LEAF_VERIFIER=0x0000000000000000000000000000000000000001 \
///           SHARED_CHAIN_VERIFIER=0x0000000000000000000000000000000000000002 \
///           SHARED_AGE_VERIFIER=0x0000000000000000000000000000000000000003 \
///             forge script packages/contracts/script/DeployRegistryUA.s.sol \
///               --fork-url http://localhost:8545 --broadcast -vv
///
///         Sepolia (chainId 11155111):
///           source /data/Develop/identityescroworg/.env
///           export UA_TRUSTED_LIST_ROOT=...       # from fixtures/expected/ua/root-pinned.json
///           export UA_POLICY_ROOT=...             # computed from fixtures/declarations/ua/
///           export UA_LEAF_VERIFIER=0x...         # from the UA leaf ceremony
///           export SHARED_CHAIN_VERIFIER=0x...    # from the chain ceremony
///           export SHARED_AGE_VERIFIER=0x...      # from the age ceremony
///           forge script packages/contracts/script/DeployRegistryUA.s.sol \
///             --rpc-url $SEPOLIA_RPC_URL --broadcast \
///             --verify --etherscan-api-key $ETHERSCAN_KEY -vv
contract DeployRegistryUA is Script {
    error ZeroVerifier(string slot);

    function run() external returns (address registry) {
        uint256 adminPriv       = vm.envUint("ADMIN_PRIVATE_KEY");
        bytes32 trustedListRoot = vm.envBytes32("UA_TRUSTED_LIST_ROOT");
        bytes32 policyRoot      = vm.envBytes32("UA_POLICY_ROOT");
        address leafV           = vm.envAddress("UA_LEAF_VERIFIER");
        address chainV          = vm.envAddress("SHARED_CHAIN_VERIFIER");
        address ageV            = vm.envAddress("SHARED_AGE_VERIFIER");

        if (leafV  == address(0)) revert ZeroVerifier("UA_LEAF_VERIFIER");
        if (chainV == address(0)) revert ZeroVerifier("SHARED_CHAIN_VERIFIER");
        if (ageV   == address(0)) revert ZeroVerifier("SHARED_AGE_VERIFIER");

        address admin = vm.addr(adminPriv);

        vm.startBroadcast(adminPriv);
        ZkqesRegistryV4 r = new ZkqesRegistryV4({
            country_: "UA",
            trustedListRoot_: trustedListRoot,
            policyRoot_: policyRoot,
            leafVerifier_: leafV,
            chainVerifier_: chainV,
            ageVerifier_: ageV,
            admin_: admin
        });
        vm.stopBroadcast();

        registry = address(r);
        console2.log("ZkqesRegistryV4[UA]:", registry);
        console2.log("  country       : UA");
        console2.log("  leafVerifier  :", leafV);
        console2.log("  chainVerifier :", chainV);
        console2.log("  ageVerifier   :", ageV);
        console2.log("  admin         :", admin);
        console2.log("  chainid       :", block.chainid);
        console2.logBytes32(trustedListRoot);
        console2.logBytes32(policyRoot);
    }
}
