// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Test, console2 } from "forge-std/Test.sol";
import { Groth16VerifierV5_1Placeholder } from "../../src/Groth16VerifierV5_1Placeholder.sol";
import { QKBRegistryV5, IGroth16VerifierV5_1 } from "../../src/QKBRegistryV5.sol";
import { IdentityEscrowNFT } from "../../src/IdentityEscrowNFT.sol";

/// @notice CI mirror of `script/DeployV5.s.sol` — replays the same
///         constructor sequence the live deploy script uses, so any
///         drift in constructor signatures / arg ordering / cross-wiring
///         fails CI before it can hit a real RPC broadcast.
///
///         Two test paths:
///
///           1. `test_deploy_local_constructor_sequence` — always on. Deploys
///              the full V5 stack (stub Groth16 → registry → NFT) in-process
///              and asserts the wiring invariants (admin, roots, NFT.registry,
///              PoseidonT3/T7 non-zero, chainLabel, mintDeadline).
///
///           2. `test_deploy_base_sepolia_fork` — fork-only. Skips when
///              `BASE_SEPOLIA_RPC_URL` is unset. When set, creates a Base
///              Sepolia fork (chainId 84532), runs the same deploy
///              sequence, and re-asserts the invariants. This catches
///              chain-config drift (block.chainid literal usage, gas
///              pricing, EIP-7212 surface) before circuits-eng's real
///              ceremony lands.
///
///         Reachability of EIP-7212 itself is owned by `P256PrecompileSmoke.t.sol`
///         + `script/probe-eip7212.ts`. This test deliberately does NOT
///         exercise the precompile — its scope is the deploy graph alone.
contract DeployV5ForkTest is Test {
    /// Chain ID for Base Sepolia per Base docs. Hard-coded so a misconfigured
    /// RPC pointing at the wrong network fails fast with a clear assertion.
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    /// Fixed dev inputs — match the values DeployV5.s.sol's docblock uses
    /// for its dry-run example. Real deploys take these from env.
    address internal constant DEV_ADMIN  = address(0xA1);
    bytes32 internal constant DEV_TRUST  = bytes32(uint256(0x1111));
    bytes32 internal constant DEV_POLICY = bytes32(uint256(0x2222));
    string  internal constant DEV_LABEL  = "UA";
    uint64  internal constant DEV_MINT_DEADLINE = 1_900_000_000;

    /// Replays the DeployV5.s.sol constructor sequence and asserts wiring.
    function _deployAndAssert() internal returns (
        Groth16VerifierV5_1Placeholder verifier,
        QKBRegistryV5 registry,
        IdentityEscrowNFT nft
    ) {
        verifier = new Groth16VerifierV5_1Placeholder();
        registry = new QKBRegistryV5(
            IGroth16VerifierV5_1(address(verifier)),
            DEV_ADMIN,
            DEV_TRUST,
            DEV_POLICY
        );
        nft = new IdentityEscrowNFT(registry, DEV_MINT_DEADLINE, DEV_LABEL);

        // Registry wiring.
        assertEq(registry.admin(), DEV_ADMIN, "registry.admin");
        assertEq(registry.trustedListRoot(), DEV_TRUST, "trustedListRoot");
        assertEq(registry.policyRoot(), DEV_POLICY, "policyRoot");

        // PoseidonT3/T7 must be CREATEd (non-zero, with code) by the registry
        // constructor — gate ordering depends on these.
        assertTrue(registry.poseidonT3() != address(0), "poseidonT3 zero");
        assertTrue(registry.poseidonT7() != address(0), "poseidonT7 zero");
        assertGt(registry.poseidonT3().code.length, 0, "poseidonT3 no code");
        assertGt(registry.poseidonT7().code.length, 0, "poseidonT7 no code");

        // NFT bound to the registry just deployed, not some prior address.
        assertEq(address(nft.registry()), address(registry), "nft.registry");
        assertEq(nft.mintDeadline(), DEV_MINT_DEADLINE, "nft.mintDeadline");
        assertEq(nft.chainLabel(), DEV_LABEL, "nft.chainLabel");

        // Sanity: every artifact has bytecode (catches a regression where
        // an empty contract somehow ends up in the chain).
        assertGt(address(verifier).code.length, 0, "verifier no code");
        assertGt(address(registry).code.length, 0, "registry no code");
        assertGt(address(nft).code.length,      0, "nft no code");
    }

    /* -------- always-on deploy-graph regression -------- */

    function test_deploy_local_constructor_sequence() public {
        (, QKBRegistryV5 registry, ) = _deployAndAssert();
        // Surface artifact size for ad-hoc gas/limit tracking.
        console2.log("local: registry codesize", address(registry).code.length);
    }

    /* -------- fork-only Base Sepolia smoke -------- */

    /// Skips when `BASE_SEPOLIA_RPC_URL` is unset. CI sets the env var to
    /// `https://sepolia.base.org` (or a private endpoint) when fork coverage
    /// is wanted; locally, leave unset for fast offline `forge test`.
    function test_deploy_base_sepolia_fork() public {
        string memory rpc;
        try vm.envString("BASE_SEPOLIA_RPC_URL") returns (string memory s) {
            rpc = s;
        } catch {
            vm.skip(true);
            return;
        }
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }

        uint256 forkId = vm.createSelectFork(rpc);
        assertEq(block.chainid, BASE_SEPOLIA_CHAIN_ID, "fork chainid != Base Sepolia");
        console2.log("fork id", forkId);
        console2.log("fork chainid", block.chainid);
        console2.log("fork block", block.number);

        (, QKBRegistryV5 registry, IdentityEscrowNFT nft) = _deployAndAssert();
        console2.log("fork: registry @", address(registry));
        console2.log("fork: nft      @", address(nft));
    }
}
