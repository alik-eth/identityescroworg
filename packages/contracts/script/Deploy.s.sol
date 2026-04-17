// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { IGroth16Verifier } from "../src/QKBVerifier.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

/// @notice Deploy QKBRegistry wired to the RSA + ECDSA Groth16 verifiers.
///
///         Admin credentials are sourced from repo-root `.env` (gitignored,
///         see CLAUDE.md §10). They MUST NEVER appear in commits, tests,
///         fixtures, or CI workflow YAML.
///
///         Required env:
///           ROOT_TL              bytes32 — initial trustedListRoot
///           ADMIN_PRIVATE_KEY    uint256 — broadcasting key (also the admin)
///           ADMIN_ADDRESS        address — must equal vm.addr(ADMIN_PRIVATE_KEY);
///                                          stored as the registry's admin
///         Optional env (production MUST set both):
///           RSA_VERIFIER_ADDR    address — pre-deployed verifier; if absent
///                                          a StubGroth16Verifier is deployed
///           ECDSA_VERIFIER_ADDR  address — same convention
///
///         Stub fallbacks let CI exercise the full deploy path against an
///         anvil fork without needing the ceremony artifacts. Production
///         (Sepolia / mainnet) deploys MUST pass real verifier addresses.
///
///         Sepolia example (chainId 11155111):
///           forge script packages/contracts/script/Deploy.s.sol \
///             --rpc-url $SEPOLIA_RPC_URL --broadcast \
///             --verify --etherscan-api-key $ETHERSCAN_KEY -vv
contract Deploy is Script {
    error AdminMismatch(address expected, address derived);

    function run() external returns (QKBRegistry registry, address rsa, address ecdsa) {
        bytes32 initialRoot = vm.envBytes32("ROOT_TL");
        uint256 adminPriv = vm.envUint("ADMIN_PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");

        // Sanity: the env-provided address MUST match the env-provided key.
        // Catches the easy mistake of pasting one but not the other.
        address derivedAdmin = vm.addr(adminPriv);
        if (derivedAdmin != admin) revert AdminMismatch(admin, derivedAdmin);

        rsa = vm.envOr("RSA_VERIFIER_ADDR", address(0));
        ecdsa = vm.envOr("ECDSA_VERIFIER_ADDR", address(0));

        vm.startBroadcast(adminPriv);

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
        console2.log("chainid:", block.chainid);
        console2.logBytes32(initialRoot);
    }
}
