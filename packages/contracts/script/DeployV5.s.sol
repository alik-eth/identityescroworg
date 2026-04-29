// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {Groth16VerifierV5} from "../src/Groth16VerifierV5.sol";
import {QKBRegistryV5, IGroth16VerifierV5} from "../src/QKBRegistryV5.sol";
import {IdentityEscrowNFT} from "../src/IdentityEscrowNFT.sol";

/// @notice V5 deploy script for Base Sepolia + Base mainnet.
/// @dev    Deploys, in order: Groth16VerifierV5 (or reuses an existing
///         deployed verifier), QKBRegistryV5 (which CREATE-deploys
///         PoseidonT3 + PoseidonT7 in its constructor), and
///         IdentityEscrowNFT bound to the V5 registry. Logs all three
///         addresses to stdout for downstream consumption.
///
/// Required env:
///   PRIVATE_KEY            — deployer private key (also pays for deploy gas)
///   ADMIN_ADDRESS          — registry admin
///   INITIAL_TRUST_ROOT     — bytes32; flattener-eng's first trust-list root
///   INITIAL_POLICY_ROOT    — bytes32; first policy-list root
///   MINT_DEADLINE          — uint64; NFT mint window close (Unix seconds)
///
/// Optional env:
///   GROTH16_VERIFIER_ADDR  — address of an existing Groth16VerifierV5
///                            deployment (real ceremony output). If unset
///                            or 0x0, deploys the §5 STUB verifier (which
///                            always returns true) — dev-only path.
///   CHAIN_LABEL            — string passed to NFT constructor; default "UA".
///
/// Usage (Base Sepolia, dry-run on Anvil fork):
///   anvil --fork-url https://sepolia.base.org --port 8546 &
///   PRIVATE_KEY=0xdeadbeef... \
///     ADMIN_ADDRESS=0xA1...   \
///     INITIAL_TRUST_ROOT=0x... \
///     INITIAL_POLICY_ROOT=0x... \
///     MINT_DEADLINE=1792833194 \
///     forge script packages/contracts/script/DeployV5.s.sol \
///       --rpc-url http://localhost:8546
///
/// Usage (Base Sepolia, broadcast + verify):
///   forge script packages/contracts/script/DeployV5.s.sol \
///     --rpc-url $BASE_SEPOLIA_RPC_URL \
///     --broadcast --verify --etherscan-api-key $BASESCAN_API_KEY -vv
contract DeployV5 is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");
        bytes32 initialTrustRoot = vm.envBytes32("INITIAL_TRUST_ROOT");
        bytes32 initialPolicyRoot = vm.envBytes32("INITIAL_POLICY_ROOT");
        uint64 mintDeadline = uint64(vm.envUint("MINT_DEADLINE"));

        // Optional chain label for the NFT contract — defaults to "UA"
        // matching the V4 admin registry.
        string memory chainLabel = "UA";
        try vm.envString("CHAIN_LABEL") returns (string memory s) {
            if (bytes(s).length > 0) chainLabel = s;
        } catch {}

        // Optional pre-deployed Groth16 verifier. If absent, we deploy
        // the §5 stub which always returns true — this is a dev-only path
        // that lets us smoke the deploy on Anvil/Sepolia without waiting
        // for the ceremony. The CLI must explicitly pass GROTH16_VERIFIER_ADDR
        // for any production deploy; the script logs which path was taken.
        address verifierAddr;
        try vm.envAddress("GROTH16_VERIFIER_ADDR") returns (address a) {
            verifierAddr = a;
        } catch {
            verifierAddr = address(0);
        }

        vm.startBroadcast(deployerKey);

        IGroth16VerifierV5 verifier;
        if (verifierAddr == address(0)) {
            console2.log("WARNING: deploying STUB Groth16VerifierV5 (always-true). DO NOT use for production.");
            verifier = IGroth16VerifierV5(address(new Groth16VerifierV5()));
        } else {
            console2.log("Using pre-deployed Groth16VerifierV5 at:", verifierAddr);
            verifier = IGroth16VerifierV5(verifierAddr);
        }
        console2.log("Groth16VerifierV5:", address(verifier));

        QKBRegistryV5 registry = new QKBRegistryV5(
            verifier,
            admin,
            initialTrustRoot,
            initialPolicyRoot
        );
        console2.log("QKBRegistryV5:    ", address(registry));
        console2.log("  PoseidonT3:     ", registry.poseidonT3());
        console2.log("  PoseidonT7:     ", registry.poseidonT7());
        console2.log("  admin:          ", registry.admin());
        console2.log("  trustedListRoot:", uint256(registry.trustedListRoot()));
        console2.log("  policyRoot:     ", uint256(registry.policyRoot()));

        IdentityEscrowNFT nft = new IdentityEscrowNFT(
            registry,
            mintDeadline,
            chainLabel
        );
        console2.log("IdentityEscrowNFT:", address(nft));
        console2.log("  mintDeadline:   ", mintDeadline);
        console2.log("  chainLabel:     ", chainLabel);

        vm.stopBroadcast();
    }
}
