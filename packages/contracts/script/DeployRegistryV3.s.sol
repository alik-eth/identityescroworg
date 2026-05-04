// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { ZkqesRegistryV3 } from "../src/ZkqesRegistryV3.sol";
import {
    IGroth16LeafVerifier,
    IGroth16ChainVerifier
} from "../src/ZkqesVerifier.sol";
import {
    StubGroth16LeafVerifier,
    StubGroth16ChainVerifier
} from "../src/verifiers/dev/StubSplitVerifiers.sol";

/// @notice Fresh deploy of `ZkqesRegistryV3` for the split-proof pivot.
///
///         V3 is a NON-UPGRADE — storage layout changes (four verifier
///         slots instead of two, plus all the Phase-2 state) so we cannot
///         upgrade V2's Sepolia deploy at
///         `0xcac30ff7B0566b6E991061cAA5C169c82A4319a4`. V2 has no real
///         registrations and is abandoned; this script replaces it at a
///         fresh address.
///
///         Required env:
///           ROOT_TL                   bytes32 — initial `trustedListRoot`.
///           ADMIN_PRIVATE_KEY         uint256 — broadcast key.
///           ADMIN_ADDRESS             address — must equal
///                                                `vm.addr(ADMIN_PRIVATE_KEY)`.
///
///         Optional env (production MUST set all four real addresses):
///           RSA_LEAF_VERIFIER_ADDR    address — 13-signal RSA leaf verifier.
///           RSA_CHAIN_VERIFIER_ADDR   address — 5-signal  RSA chain verifier.
///           ECDSA_LEAF_VERIFIER_ADDR  address — 13-signal ECDSA leaf verifier.
///           ECDSA_CHAIN_VERIFIER_ADDR address — 5-signal  ECDSA chain verifier.
///           USE_STUB_VERIFIER         bool    — when set, deploys the
///                                               dev stubs for any missing
///                                               slot. NEVER set in production.
///
///         Anvil dry-run:
///           anvil --port 8545 &
///           ROOT_TL=0x0000...01 \
///           ADMIN_PRIVATE_KEY=... ADMIN_ADDRESS=... \
///           USE_STUB_VERIFIER=true \
///             forge script packages/contracts/script/DeployRegistryV3.s.sol \
///               --fork-url http://localhost:8545 -vv
///
///         Sepolia (chainId 11155111):
///           forge script packages/contracts/script/DeployRegistryV3.s.sol \
///             --rpc-url $SEPOLIA_RPC_URL --broadcast \
///             --verify --etherscan-api-key $ETHERSCAN_KEY -vv
contract DeployRegistryV3 is Script {
    error AdminMismatch(address expected, address derived);

    function run()
        external
        returns (
            address registry,
            address rsaLeafAddr,
            address rsaChainAddr,
            address ecdsaLeafAddr,
            address ecdsaChainAddr
        )
    {
        bytes32 initialRoot = vm.envBytes32("ROOT_TL");
        uint256 adminPriv   = vm.envUint("ADMIN_PRIVATE_KEY");
        address admin       = vm.envAddress("ADMIN_ADDRESS");

        address derivedAdmin = vm.addr(adminPriv);
        if (derivedAdmin != admin) revert AdminMismatch(admin, derivedAdmin);

        rsaLeafAddr    = vm.envOr("RSA_LEAF_VERIFIER_ADDR",    address(0));
        rsaChainAddr   = vm.envOr("RSA_CHAIN_VERIFIER_ADDR",   address(0));
        ecdsaLeafAddr  = vm.envOr("ECDSA_LEAF_VERIFIER_ADDR",  address(0));
        ecdsaChainAddr = vm.envOr("ECDSA_CHAIN_VERIFIER_ADDR", address(0));
        bool useStub   = vm.envOr("USE_STUB_VERIFIER", false);

        vm.startBroadcast(adminPriv);

        if (rsaLeafAddr == address(0)) {
            require(
                useStub,
                "DeployRegistryV3: RSA_LEAF_VERIFIER_ADDR missing (set it or USE_STUB_VERIFIER=true)"
            );
            rsaLeafAddr = address(new StubGroth16LeafVerifier());
            console2.log("Deployed StubGroth16LeafVerifier (RSA leaf slot, CI only):", rsaLeafAddr);
        }
        if (rsaChainAddr == address(0)) {
            require(
                useStub,
                "DeployRegistryV3: RSA_CHAIN_VERIFIER_ADDR missing (set it or USE_STUB_VERIFIER=true)"
            );
            rsaChainAddr = address(new StubGroth16ChainVerifier());
            console2.log("Deployed StubGroth16ChainVerifier (RSA chain slot, CI only):", rsaChainAddr);
        }
        if (ecdsaLeafAddr == address(0)) {
            require(
                useStub,
                "DeployRegistryV3: ECDSA_LEAF_VERIFIER_ADDR missing (set it or USE_STUB_VERIFIER=true)"
            );
            ecdsaLeafAddr = address(new StubGroth16LeafVerifier());
            console2.log("Deployed StubGroth16LeafVerifier (ECDSA leaf slot, CI only):", ecdsaLeafAddr);
        }
        if (ecdsaChainAddr == address(0)) {
            require(
                useStub,
                "DeployRegistryV3: ECDSA_CHAIN_VERIFIER_ADDR missing (set it or USE_STUB_VERIFIER=true)"
            );
            ecdsaChainAddr = address(new StubGroth16ChainVerifier());
            console2.log("Deployed StubGroth16ChainVerifier (ECDSA chain slot, CI only):", ecdsaChainAddr);
        }

        registry = address(new ZkqesRegistryV3(
            IGroth16LeafVerifier(rsaLeafAddr),
            IGroth16ChainVerifier(rsaChainAddr),
            IGroth16LeafVerifier(ecdsaLeafAddr),
            IGroth16ChainVerifier(ecdsaChainAddr),
            initialRoot,
            admin
        ));

        vm.stopBroadcast();

        console2.log("ZkqesRegistryV3:", registry);
        console2.log("  rsaLeafVerifier   :", rsaLeafAddr);
        console2.log("  rsaChainVerifier  :", rsaChainAddr);
        console2.log("  ecdsaLeafVerifier :", ecdsaLeafAddr);
        console2.log("  ecdsaChainVerifier:", ecdsaChainAddr);
        console2.log("  admin             :", admin);
        console2.log("  chainid           :", block.chainid);
        console2.logBytes32(initialRoot);
    }
}
