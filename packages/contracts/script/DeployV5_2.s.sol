// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {Groth16VerifierV5_2Placeholder} from "../src/Groth16VerifierV5_2Placeholder.sol";
import {ZkqesRegistryV5_2, IGroth16VerifierV5_2} from "../src/ZkqesRegistryV5_2.sol";
import {ZkqesCertificate} from "../src/ZkqesCertificate.sol";

/// @notice V5.2 deploy script for Base Sepolia + Base mainnet.
/// @dev    V5.2 keccak-on-chain amendment: identical scaffold to
///         `DeployV5.s.sol` (the V5.1 deploy script) except for the
///         verifier and registry types. The constructor signatures are
///         unchanged — V5.1 → V5.2 swaps the public-signal layout
///         (19 → 22, see `ZkqesRegistryV5_2.sol` header) and the
///         contract-side keccak gate, but does NOT alter the
///         (verifier, admin, trustedListRoot, policyRoot) tuple.
///
///         Verifier flip schedule:
///           - Now (T-scaffold): points at `Groth16VerifierV5_2Placeholder`
///             (always-true, 22-input shape; dev-only — wired automatically
///             when `GROTH16_VERIFIER_ADDR` is unset).
///           - Post circuits-eng T3 pump (T4): the real V5.2 stub verifier
///             `Groth16VerifierV5_2Stub.sol` lands in the contracts package;
///             dev-only deploys can opt into the real-pairing path by
///             passing its address via `GROTH16_VERIFIER_ADDR`.
///           - Production (post-Phase-B multi-contributor ceremony):
///             `GROTH16_VERIFIER_ADDR` MUST point at the real ceremonied
///             verifier. The script logs a loud warning when the
///             placeholder is wired in (mirrors the V5.1 §5-stub safety
///             pattern).
///
/// @dev    Deploys, in order: Groth16VerifierV5_2 (or reuses an existing
///         deployed verifier), ZkqesRegistryV5_2 (which CREATE-deploys
///         PoseidonT3 + PoseidonT7 in its constructor), and
///         ZkqesCertificate bound to the V5.2 registry. Logs all three
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
///   GROTH16_VERIFIER_ADDR  — address of an existing Groth16VerifierV5_2
///                            deployment (real ceremony output). If unset
///                            or 0x0, deploys the PLACEHOLDER verifier
///                            (which always returns true) — dev-only path.
///   CHAIN_LABEL            — string passed to NFT constructor; default "UA".
///
/// Usage (Base Sepolia, dry-run on Anvil fork):
///   anvil --fork-url https://sepolia.base.org --port 8546 &
///   PRIVATE_KEY=0xdeadbeef... \
///     ADMIN_ADDRESS=0xA1...   \
///     INITIAL_TRUST_ROOT=0x... \
///     INITIAL_POLICY_ROOT=0x... \
///     MINT_DEADLINE=1792833194 \
///     forge script packages/contracts/script/DeployV5_2.s.sol \
///       --rpc-url http://localhost:8546
///
/// Usage (Base Sepolia, broadcast + verify):
///   forge script packages/contracts/script/DeployV5_2.s.sol \
///     --rpc-url $BASE_SEPOLIA_RPC_URL \
///     --broadcast --verify --etherscan-api-key $BASESCAN_API_KEY -vv
contract DeployV5_2 is Script {
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
        // the V5.2 PLACEHOLDER (always-true, 22-input shape) — dev-only
        // path that lets us smoke the deploy on Anvil/Sepolia without
        // waiting for the real V5.2 stub ceremony output. The CLI must
        // explicitly pass GROTH16_VERIFIER_ADDR for any production
        // deploy; the script logs which path was taken.
        address verifierAddr;
        try vm.envAddress("GROTH16_VERIFIER_ADDR") returns (address a) {
            verifierAddr = a;
        } catch {
            verifierAddr = address(0);
        }

        vm.startBroadcast(deployerKey);

        IGroth16VerifierV5_2 verifier;
        if (verifierAddr == address(0)) {
            console2.log("WARNING: deploying V5.2 PLACEHOLDER verifier (always-true). DO NOT use for production.");
            verifier = IGroth16VerifierV5_2(address(new Groth16VerifierV5_2Placeholder()));
        } else {
            console2.log("Using pre-deployed Groth16VerifierV5_2 at:", verifierAddr);
            verifier = IGroth16VerifierV5_2(verifierAddr);
        }
        console2.log("Groth16VerifierV5_2:", address(verifier));

        ZkqesRegistryV5_2 registry = new ZkqesRegistryV5_2(
            verifier,
            admin,
            initialTrustRoot,
            initialPolicyRoot
        );
        console2.log("ZkqesRegistryV5_2:  ", address(registry));
        console2.log("  PoseidonT3:     ", registry.poseidonT3());
        console2.log("  PoseidonT7:     ", registry.poseidonT7());
        console2.log("  admin:          ", registry.admin());
        console2.log("  trustedListRoot:", uint256(registry.trustedListRoot()));
        console2.log("  policyRoot:     ", uint256(registry.policyRoot()));

        ZkqesCertificate nft = new ZkqesCertificate(
            registry,
            mintDeadline,
            chainLabel
        );
        console2.log("ZkqesCertificate:", address(nft));
        console2.log("  mintDeadline:   ", mintDeadline);
        console2.log("  chainLabel:     ", chainLabel);

        vm.stopBroadcast();
    }
}
