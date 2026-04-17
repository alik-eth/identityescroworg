// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { AuthorityArbitrator } from "../src/arbitrators/AuthorityArbitrator.sol";
import { TimelockArbitrator } from "../src/arbitrators/TimelockArbitrator.sol";

/// @notice Deploys both Phase 2 arbitrator contracts to the target chain.
///
///         Required env:
///           QIE_AUTHORITY_ADDRESS   address — AuthorityArbitrator authority
///           QIE_TIMELOCK_HOLDER     address — TimelockArbitrator holder (ping)
///           ADMIN_PRIVATE_KEY       uint256 — broadcasting key
///         Optional env:
///           QIE_TIMELOCK_SECONDS    uint256 — timeout (default: 30 days)
///
///         Sepolia (lead-triggered):
///           QIE_AUTHORITY_ADDRESS=<authority> QIE_TIMELOCK_HOLDER=<holder> \
///             forge script packages/contracts/script/DeployArbitrators.s.sol \
///             --rpc-url $SEPOLIA_RPC_URL --broadcast \
///             --verify --etherscan-api-key $ETHERSCAN_KEY -vv
///
///         Anvil dry-run (no --broadcast):
///           QIE_AUTHORITY_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
///           QIE_TIMELOCK_HOLDER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
///             forge script packages/contracts/script/DeployArbitrators.s.sol \
///             --fork-url http://127.0.0.1:8545 -vv
contract DeployArbitrators is Script {
    function run() external returns (address authAddr, address timelockAddr) {
        address authority = vm.envAddress("QIE_AUTHORITY_ADDRESS");
        address holderPing = vm.envAddress("QIE_TIMELOCK_HOLDER");
        uint256 timeout = vm.envOr("QIE_TIMELOCK_SECONDS", uint256(30 days));
        uint256 adminPriv = vm.envUint("ADMIN_PRIVATE_KEY");

        vm.startBroadcast(adminPriv);
        authAddr = address(new AuthorityArbitrator(authority));
        timelockAddr = address(new TimelockArbitrator(holderPing, timeout));
        vm.stopBroadcast();

        console2.log("AuthorityArbitrator:", authAddr);
        console2.log("  authority:", authority);
        console2.log("TimelockArbitrator:", timelockAddr);
        console2.log("  holderPing:", holderPing);
        console2.log("  timeoutSeconds:", timeout);
        console2.log("chainid:", block.chainid);
    }
}
