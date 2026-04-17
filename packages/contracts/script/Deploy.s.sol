// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { IGroth16Verifier } from "../src/QKBVerifier.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";
import { QKBGroth16Verifier } from "../src/verifier/QKBGroth16Verifier.sol";

/// @notice Deploy QKBRegistry wired to the ECDSA-leaf Groth16 verifier.
///
///         Phase 1 ships with ONE verifier (ECDSA-leaf). RSA + chain-proof
///         variants are deferred to Phase 2 per spec §5.4.
///
///         Admin credentials are sourced from repo-root `.env` (gitignored,
///         see CLAUDE.md §10). They MUST NEVER appear in commits, tests,
///         fixtures, or CI workflow YAML.
///
///         Required env:
///           ROOT_TL              bytes32 — initial trustedListRoot
///           ADMIN_PRIVATE_KEY    uint256 — broadcasting key (also the admin)
///           ADMIN_ADDRESS        address — must equal vm.addr(ADMIN_PRIVATE_KEY)
///         Optional env (production MUST set):
///           ECDSA_VERIFIER_ADDR  address — pre-deployed verifier. If absent
///                                          a fresh QKBGroth16Verifier is
///                                          deployed in the same tx.
///           USE_STUB_VERIFIER    bool    — if true AND ECDSA_VERIFIER_ADDR
///                                          is empty, deploys a
///                                          StubGroth16Verifier instead (CI).
///
///         Sepolia example (chainId 11155111):
///           forge script packages/contracts/script/Deploy.s.sol \
///             --rpc-url $SEPOLIA_RPC_URL --broadcast \
///             --verify --etherscan-api-key $ETHERSCAN_KEY -vv
contract Deploy is Script {
    error AdminMismatch(address expected, address derived);

    function run() external returns (QKBRegistry registry, address verifierAddr) {
        bytes32 initialRoot = vm.envBytes32("ROOT_TL");
        uint256 adminPriv = vm.envUint("ADMIN_PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");

        address derivedAdmin = vm.addr(adminPriv);
        if (derivedAdmin != admin) revert AdminMismatch(admin, derivedAdmin);

        verifierAddr = vm.envOr("ECDSA_VERIFIER_ADDR", address(0));
        bool useStub = vm.envOr("USE_STUB_VERIFIER", false);

        vm.startBroadcast(adminPriv);

        if (verifierAddr == address(0)) {
            if (useStub) {
                verifierAddr = address(new StubGroth16Verifier());
                console2.log("Deployed StubGroth16Verifier (CI only):", verifierAddr);
            } else {
                verifierAddr = address(new QKBGroth16Verifier());
                console2.log("Deployed real QKBGroth16Verifier:", verifierAddr);
            }
        }

        registry = new QKBRegistry(IGroth16Verifier(verifierAddr), initialRoot, admin);

        vm.stopBroadcast();

        console2.log("QKBRegistry:", address(registry));
        console2.log("verifier:", verifierAddr);
        console2.log("admin:", admin);
        console2.log("chainid:", block.chainid);
        console2.logBytes32(initialRoot);
    }
}
