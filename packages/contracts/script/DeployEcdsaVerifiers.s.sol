// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";

import { QKBGroth16VerifierEcdsaLeaf }  from "../src/verifiers/QKBGroth16VerifierEcdsaLeaf.sol";
import { QKBGroth16VerifierEcdsaChain } from "../src/verifiers/QKBGroth16VerifierEcdsaChain.sol";

/// @notice Deploys the two REAL ECDSA Groth16 verifiers emitted by the
///         split-proof ceremony (2026-04-19). Deploy BEFORE
///         `DeployRegistryV3.s.sol`; capture the two logged addresses and
///         pass them as `ECDSA_LEAF_VERIFIER_ADDR` +
///         `ECDSA_CHAIN_VERIFIER_ADDR` when running that script.
///
///         This script is deliberately separate from `DeployRegistryV3`
///         so that verifier redeploys (e.g. after a re-ceremony with
///         fresh entropy) don't force a registry redeploy.
///
///         Required env:
///           ADMIN_PRIVATE_KEY         uint256 — broadcast key.
///           ADMIN_ADDRESS             address — must equal vm.addr(ADMIN_PRIVATE_KEY).
///
///         Anvil dry-run:
///           anvil --port 8545 &
///           ADMIN_PRIVATE_KEY=... ADMIN_ADDRESS=... \
///             forge script packages/contracts/script/DeployEcdsaVerifiers.s.sol \
///               --fork-url http://localhost:8545 -vv
///
///         Sepolia (chainId 11155111):
///           forge script packages/contracts/script/DeployEcdsaVerifiers.s.sol \
///             --rpc-url $SEPOLIA_RPC_URL --broadcast \
///             --verify --etherscan-api-key $ETHERSCAN_KEY -vv
contract DeployEcdsaVerifiers is Script {
    error AdminMismatch(address expected, address derived);

    function run()
        external
        returns (address leafVerifier, address chainVerifier)
    {
        uint256 adminPriv = vm.envUint("ADMIN_PRIVATE_KEY");
        address admin     = vm.envAddress("ADMIN_ADDRESS");

        address derivedAdmin = vm.addr(adminPriv);
        if (derivedAdmin != admin) revert AdminMismatch(admin, derivedAdmin);

        vm.startBroadcast(adminPriv);

        leafVerifier  = address(new QKBGroth16VerifierEcdsaLeaf());
        chainVerifier = address(new QKBGroth16VerifierEcdsaChain());

        vm.stopBroadcast();

        console2.log("QKBGroth16VerifierEcdsaLeaf :", leafVerifier);
        console2.log("QKBGroth16VerifierEcdsaChain:", chainVerifier);
        console2.log("  admin  :", admin);
        console2.log("  chainid:", block.chainid);
        console2.log("");
        console2.log("Now run DeployRegistryV3.s.sol with these env vars:");
        console2.log("  ECDSA_LEAF_VERIFIER_ADDR=", leafVerifier);
        console2.log("  ECDSA_CHAIN_VERIFIER_ADDR=", chainVerifier);
    }
}
