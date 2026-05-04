// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { ZkqesRegistry } from "../src/ZkqesRegistry.sol";
import { IGroth16VerifierV2 } from "../src/ZkqesVerifierV2.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

/// @notice Deploy ZkqesRegistry wired to the dual (RSA + ECDSA) Groth16 verifiers.
///
///         Sprint 0 transitional state: real 14-signal verifiers are in flight
///         from circuits-eng. This script accepts either pre-deployed verifier
///         addresses (via env) or stub verifiers (for CI / anvil dry-runs).
///         S0.6 locks this down further once real verifier contracts land.
///
///         Admin credentials are sourced from repo-root `.env` (gitignored,
///         see CLAUDE.md §10). They MUST NEVER appear in commits, tests,
///         fixtures, or CI workflow YAML.
///
///         Required env:
///           ROOT_TL              bytes32 — initial trustedListRoot
///           ADMIN_PRIVATE_KEY    uint256 — broadcasting key (also the admin)
///           ADMIN_ADDRESS        address — must equal vm.addr(ADMIN_PRIVATE_KEY)
///         Optional env (production MUST set real verifier addresses):
///           RSA_VERIFIER_ADDR    address — pre-deployed RSA verifier.
///           ECDSA_VERIFIER_ADDR  address — pre-deployed ECDSA verifier.
///           USE_STUB_VERIFIER    bool    — if true AND verifier env is empty,
///                                          deploys StubGroth16Verifier for
///                                          the missing slot (CI only).
///
///         Sepolia example (chainId 11155111):
///           forge script packages/contracts/script/Deploy.s.sol \
///             --rpc-url $SEPOLIA_RPC_URL --broadcast \
///             --verify --etherscan-api-key $ETHERSCAN_KEY -vv
contract Deploy is Script {
    error AdminMismatch(address expected, address derived);

    function run() external returns (ZkqesRegistry registry, address rsaAddr, address ecdsaAddr) {
        bytes32 initialRoot = vm.envBytes32("ROOT_TL");
        uint256 adminPriv = vm.envUint("ADMIN_PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");

        address derivedAdmin = vm.addr(adminPriv);
        if (derivedAdmin != admin) revert AdminMismatch(admin, derivedAdmin);

        rsaAddr = vm.envOr("RSA_VERIFIER_ADDR", address(0));
        ecdsaAddr = vm.envOr("ECDSA_VERIFIER_ADDR", address(0));
        bool useStub = vm.envOr("USE_STUB_VERIFIER", false);

        vm.startBroadcast(adminPriv);

        if (rsaAddr == address(0)) {
            require(useStub, "Deploy: RSA verifier missing (set RSA_VERIFIER_ADDR or USE_STUB_VERIFIER=true)");
            rsaAddr = address(new StubGroth16Verifier());
            console2.log("Deployed StubGroth16Verifier (RSA slot, CI only):", rsaAddr);
        }
        if (ecdsaAddr == address(0)) {
            require(useStub, "Deploy: ECDSA verifier missing (set ECDSA_VERIFIER_ADDR or USE_STUB_VERIFIER=true)");
            ecdsaAddr = address(new StubGroth16Verifier());
            console2.log("Deployed StubGroth16Verifier (ECDSA slot, CI only):", ecdsaAddr);
        }

        registry = new ZkqesRegistry(
            IGroth16VerifierV2(rsaAddr),
            IGroth16VerifierV2(ecdsaAddr),
            initialRoot,
            admin
        );

        vm.stopBroadcast();

        console2.log("ZkqesRegistry:", address(registry));
        console2.log("rsaVerifier:", rsaAddr);
        console2.log("ecdsaVerifier:", ecdsaAddr);
        console2.log("admin:", admin);
        console2.log("chainid:", block.chainid);
        console2.logBytes32(initialRoot);
    }
}
