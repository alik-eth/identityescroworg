// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { AuthorityArbitrator } from "../src/arbitrators/AuthorityArbitrator.sol";
// MVP: deferred post-pilot, see 2026-04-17-qie-mvp-refinement.md §3.2
// import { TimelockArbitrator } from "../src/arbitrators/TimelockArbitrator.sol";

/// @notice Deploys the Phase 2 AuthorityArbitrator pointing at a given
///         ZkqesRegistry (v2). TimelockArbitrator deploy is commented out
///         for the MVP window (see plan §3.2) — the contract itself is
///         reduced to an interface-only stub in-tree.
///
///         Required env:
///           QIE_AUTHORITY_ADDRESS   address — AuthorityArbitrator authority
///           QIE_REGISTRY_ADDRESS    address — ZkqesRegistry v2 deployment
///           ADMIN_PRIVATE_KEY       uint256 — broadcasting key
///
///         Sepolia (lead-triggered):
///           QIE_AUTHORITY_ADDRESS=<authority> QIE_REGISTRY_ADDRESS=<registry> \
///             forge script packages/contracts/script/DeployArbitrators.s.sol \
///             --rpc-url $SEPOLIA_RPC_URL --broadcast \
///             --verify --etherscan-api-key $ETHERSCAN_KEY -vv
///
///         Anvil dry-run (no --broadcast):
///           QIE_AUTHORITY_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
///           QIE_REGISTRY_ADDRESS=<anvil-registry> \
///             forge script packages/contracts/script/DeployArbitrators.s.sol \
///             --fork-url http://127.0.0.1:8545 -vv
contract DeployArbitrators is Script {
    function run() external returns (address authAddr) {
        address authority = vm.envAddress("QIE_AUTHORITY_ADDRESS");
        address registry = vm.envAddress("QIE_REGISTRY_ADDRESS");
        uint256 adminPriv = vm.envUint("ADMIN_PRIVATE_KEY");

        vm.startBroadcast(adminPriv);
        authAddr = address(new AuthorityArbitrator(authority, registry));
        // MVP: TimelockArbitrator deploy disabled — see plan §3.2.
        // address holderPing = vm.envAddress("QIE_TIMELOCK_HOLDER");
        // uint256 timeout = vm.envOr("QIE_TIMELOCK_SECONDS", uint256(30 days));
        // timelockAddr = address(new TimelockArbitrator(holderPing, timeout));
        vm.stopBroadcast();

        console2.log("AuthorityArbitrator:", authAddr);
        console2.log("  authority:", authority);
        console2.log("  registry:", registry);
        console2.log("chainid:", block.chainid);
    }
}
