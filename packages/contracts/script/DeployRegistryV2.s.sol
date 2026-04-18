// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { QKBRegistry } from "../src/QKBRegistry.sol";
import { IGroth16VerifierV2 } from "../src/QKBVerifierV2.sol";
import { StubGroth16Verifier } from "../src/verifier/StubGroth16Verifier.sol";

/// @notice Fresh Phase 2 deployment of the (now extended) QKBRegistry.
///         Solidity contracts are non-upgradeable and Phase 2 extends the
///         storage layout with the nullifier maps + escrow surface, so
///         Phase 1's Sepolia deployment cannot absorb the changes. This
///         script emits the *v2* address; the v1 deployment stays live at
///         its Phase-1 address for historical audit.
///
///         Required env:
///           RSA_VERIFIER_ADDR    address  — pre-deployed RSA 14-signal verifier
///           ECDSA_VERIFIER_ADDR  address  — pre-deployed ECDSA 14-signal verifier
///           ROOT_TL              bytes32  — initial trustedListRoot
///           ADMIN_PRIVATE_KEY    uint256  — broadcaster (registry admin)
///           ADMIN_ADDRESS        address  — must equal vm.addr(ADMIN_PRIVATE_KEY)
///         Optional:
///           USE_STUB_VERIFIER    bool     — stubs fill missing verifier
///                                            slots for anvil / CI only.
///
///         Sepolia (chainId 11155111):
///           forge script packages/contracts/script/DeployRegistryV2.s.sol \
///             --rpc-url $SEPOLIA_RPC_URL --broadcast \
///             --verify --etherscan-api-key $ETHERSCAN_KEY -vv
contract DeployRegistryV2 is Script {
    error AdminMismatch(address expected, address derived);

    function run() external returns (address registry, address rsaAddr, address ecdsaAddr) {
        bytes32 initialRoot = vm.envBytes32("ROOT_TL");
        uint256 adminPriv = vm.envUint("ADMIN_PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");
        if (vm.addr(adminPriv) != admin) revert AdminMismatch(admin, vm.addr(adminPriv));

        rsaAddr = vm.envOr("RSA_VERIFIER_ADDR", address(0));
        ecdsaAddr = vm.envOr("ECDSA_VERIFIER_ADDR", address(0));
        bool useStub = vm.envOr("USE_STUB_VERIFIER", false);

        vm.startBroadcast(adminPriv);

        if (rsaAddr == address(0)) {
            require(useStub, "DeployRegistryV2: RSA verifier missing");
            rsaAddr = address(new StubGroth16Verifier());
            console2.log("Deployed StubGroth16Verifier (RSA slot, CI only):", rsaAddr);
        }
        if (ecdsaAddr == address(0)) {
            require(useStub, "DeployRegistryV2: ECDSA verifier missing");
            ecdsaAddr = address(new StubGroth16Verifier());
            console2.log("Deployed StubGroth16Verifier (ECDSA slot, CI only):", ecdsaAddr);
        }

        registry = address(new QKBRegistry(
            IGroth16VerifierV2(rsaAddr),
            IGroth16VerifierV2(ecdsaAddr),
            initialRoot,
            admin
        ));

        vm.stopBroadcast();

        console2.log("QKBRegistryV2:", registry);
        console2.log("  rsaVerifier :", rsaAddr);
        console2.log("  ecdsaVerifier:", ecdsaAddr);
        console2.log("  admin        :", admin);
        console2.log("  chainid      :", block.chainid);
        console2.logBytes32(initialRoot);
    }
}
