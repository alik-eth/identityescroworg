// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { IGroth16Verifier } from "../src/QKBVerifier.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

/// @notice Deploy QKBRegistry wired to the RSA + ECDSA Groth16 verifiers.
///
///         Required env:
///           ROOT_TL          bytes32 — initial trustedListRoot
///           REGISTRY_ADMIN   address — multisig admin
///         Optional env:
///           RSA_VERIFIER_ADDR    address — pre-deployed verifier; if absent
///                                          a StubGroth16Verifier is deployed
///           ECDSA_VERIFIER_ADDR  address — same convention
///
///         Stub fallbacks let CI exercise the full deploy path against an
///         anvil fork without needing the ceremony artifacts. Production
///         (Sepolia / mainnet) deploys MUST pass real verifier addresses.
contract Deploy is Script {
    function run() external returns (QKBRegistry registry, address rsa, address ecdsa) {
        bytes32 initialRoot = vm.envBytes32("ROOT_TL");
        address admin = vm.envAddress("REGISTRY_ADMIN");

        rsa = vm.envOr("RSA_VERIFIER_ADDR", address(0));
        ecdsa = vm.envOr("ECDSA_VERIFIER_ADDR", address(0));

        vm.startBroadcast();

        if (rsa == address(0)) {
            rsa = address(new StubGroth16Verifier());
            console2.log("Deployed StubGroth16Verifier as RSA verifier:", rsa);
        }
        if (ecdsa == address(0)) {
            ecdsa = address(new StubGroth16Verifier());
            console2.log("Deployed StubGroth16Verifier as ECDSA verifier:", ecdsa);
        }

        registry = new QKBRegistry(IGroth16Verifier(rsa), IGroth16Verifier(ecdsa), initialRoot, admin);

        vm.stopBroadcast();

        console2.log("QKBRegistry:", address(registry));
        console2.log("rsaVerifier:", rsa);
        console2.log("ecdsaVerifier:", ecdsa);
        console2.log("admin:", admin);
        console2.logBytes32(initialRoot);
    }
}
