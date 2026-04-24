// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { Groth16Verifier as LeafVerifierV4_UA } from "../src/verifiers/LeafVerifierV4_UA.sol";
import { Groth16Verifier as AgeVerifierV4 }     from "../src/verifiers/AgeVerifierV4.sol";

/// @notice Deploys the two NEW Groth16 verifiers for the UA QKB/2 deploy:
///           - `LeafVerifierV4_UA` (16 public signals, UA-specific leaf ceremony).
///           - `AgeVerifierV4`     (3 public signals,  shared across countries).
///
///         The chain verifier is NOT redeployed — the V3 chain verifier at
///         `0xc1a0fd1e620398b019ff3941b6c601afe81b33b8` on Sepolia is reused
///         verbatim (matching zkey SHA, identical 3-signal shape). See
///         `/fixtures/circuits/chain/urls.json` note `"v3-reuse"`.
///
///         Required env:
///           ADMIN_PRIVATE_KEY   uint256 — broadcast key (funded on target chain).
///
///         Anvil dry-run:
///           anvil --port 8545 &
///           ADMIN_PRIVATE_KEY=0xac09…ff80 \
///             forge script packages/contracts/script/DeployVerifiersV4UA.s.sol \
///               --fork-url http://localhost:8545 --broadcast -vv
///
///         Sepolia (chainId 11155111):
///           source /data/Develop/identityescroworg/.env
///           forge script packages/contracts/script/DeployVerifiersV4UA.s.sol \
///             --rpc-url $SEPOLIA_RPC_URL --broadcast \
///             --verify --etherscan-api-key $ETHERSCAN_KEY -vv
///
///         After deploy, `DeployRegistryUA.s.sol` consumes:
///           UA_LEAF_VERIFIER      = <leafVerifier>
///           SHARED_AGE_VERIFIER   = <ageVerifier>
///           SHARED_CHAIN_VERIFIER = 0xc1a0fd1e620398b019ff3941b6c601afe81b33b8
contract DeployVerifiersV4UA is Script {
    function run() external returns (address leafVerifier, address ageVerifier) {
        uint256 adminPriv = vm.envUint("ADMIN_PRIVATE_KEY");

        vm.startBroadcast(adminPriv);
        leafVerifier = address(new LeafVerifierV4_UA());
        ageVerifier  = address(new AgeVerifierV4());
        vm.stopBroadcast();

        console2.log("LeafVerifierV4_UA:", leafVerifier);
        console2.log("AgeVerifierV4    :", ageVerifier);
        console2.log("chainid          :", block.chainid);
    }
}
