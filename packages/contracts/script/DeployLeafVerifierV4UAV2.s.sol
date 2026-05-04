// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { LeafVerifierV4_UA_V2 } from "../src/verifiers/LeafVerifierV4_UA_V2.sol";

/// @notice Deploys the V2 UA leaf verifier from the hardened re-ceremony
///         (6 Codex findings closed; new zkey sha256
///          9370ac2514123f80b32936bf09e715f2975d46fb02ac15117d1e925873b6e22f).
///         Only LeafVerifier is redeployed — chain + age verifiers are
///         unaffected by the M11 hardening.
///
///         After deploy the admin must rotate it in on the UA
///         ZkqesRegistryV4 at 0x4c8541f4Ff16AE2650C4e146587E81eD56A2456C via
///         `setLeafVerifier(<newAddress>)`.
///
///         Required env:
///           ADMIN_PRIVATE_KEY   uint256 — broadcast key.
contract DeployLeafVerifierV4UAV2 is Script {
    function run() external returns (address leafVerifier) {
        uint256 adminPriv = vm.envUint("ADMIN_PRIVATE_KEY");

        vm.startBroadcast(adminPriv);
        leafVerifier = address(new LeafVerifierV4_UA_V2());
        vm.stopBroadcast();

        console2.log("LeafVerifierV4_UA_V2:", leafVerifier);
        console2.log("chainid             :", block.chainid);
    }
}
