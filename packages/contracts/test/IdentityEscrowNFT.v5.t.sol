// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {IdentityEscrowNFT, IQKBRegistry} from "../src/IdentityEscrowNFT.sol";
import {QKBRegistryV5, IGroth16VerifierV5} from "../src/QKBRegistryV5.sol";
import {Groth16VerifierV5} from "../src/Groth16VerifierV5.sol";

/// @notice §7 IdentityEscrowNFT × V5 compatibility test.
///
/// The NFT contract source is FROZEN at the V4 shape — it consumes
/// `IQKBRegistry` (`isVerified`, `nullifierOf`, `trustedListRoot`)
/// and nothing else. V5's QKBRegistryV5 implements that same
/// interface verbatim, so plugging the V5 registry into the NFT
/// constructor must work with zero NFT source change.
///
/// This test does NOT re-cover the NFT's own logic (that's exercised
/// by IdentityEscrowNFT.t.sol via MockRegistry). It confirms ABI
/// compatibility between the V5 registry and the NFT contract — i.e.,
/// the same NFT bytecode happily binds to the V5 registry instance,
/// reads `isVerified` and `nullifierOf` through it, and the mint flow
/// succeeds for a registered V5 holder.
contract IdentityEscrowNFTV5CompatibilityTest is Test {
    IdentityEscrowNFT internal nft;
    QKBRegistryV5 internal registry;
    Groth16VerifierV5 internal verifier;

    address internal admin = address(0xA1);
    uint64 internal constant DEADLINE = 2_500_000_000;

    function setUp() public {
        vm.warp(2_000_000_000); // sane block.timestamp ≪ DEADLINE
        verifier = new Groth16VerifierV5();
        registry = new QKBRegistryV5(
            IGroth16VerifierV5(address(verifier)),
            admin,
            bytes32(0),
            bytes32(0)
        );
        nft = new IdentityEscrowNFT(IQKBRegistry(address(registry)), DEADLINE, "Sepolia");
    }

    function test_nft_constructorBindsToV5_registry() public view {
        // Smoke: NFT stored the V5 registry as its IQKBRegistry — same
        // bytecode shape it would store a V4 registry as. ABI-stable
        // interface preserved verbatim across V4↔V5 (per V5 spec §0.4).
        assertEq(address(nft.registry()), address(registry));
    }

    /// Calling registry methods through the NFT's IQKBRegistry handle
    /// returns sane zero-state values pre-registration. Confirms each
    /// of the three IQKBRegistry methods is callable on V5 with V4 ABI.
    function test_nft_canCallV5Registry_iqkbInterface() public view {
        IQKBRegistry r = nft.registry();
        assertFalse(r.isVerified(address(this)));
        assertEq(r.nullifierOf(address(this)), bytes32(0));
        assertEq(r.trustedListRoot(), bytes32(0));
    }

    /// End-to-end ABI compat: forge a V5-style binding by manipulating
    /// the registry's storage directly (faster than constructing a real
    /// register() proof here — that's what the §6 register tests cover),
    /// then mint through the NFT and verify the NFT reads the V5
    /// nullifier correctly.
    function test_nft_mint_succeedsWith_V5_storedNullifier() public {
        address alice = address(0xA11CE);
        bytes32 nullifier = bytes32(uint256(0xCAFEBABE));

        // Stub-write nullifierOf[alice] = nullifier directly — emulating
        // a successful register() side-effect. Storage slot derived from
        // the contract's mapping declaration order:
        //   slot 0:  admin (address)
        //   slot 1:  trustedListRoot (bytes32)
        //   slot 2:  policyRoot (bytes32)
        //   slot 3:  nullifierOf          ← target mapping (write-once on first-claim)
        //   slot 4:  identityCommitments  (V5.1; was registrantOf in V5)
        //   slot 5:  identityWallets      (V5.1)
        //   slot 6:  usedCtx              (V5.1)
        // mapping(address => bytes32) at slot s has key=address giving
        // slot keccak256(abi.encode(key, s)).
        bytes32 nullifierSlot = keccak256(abi.encode(alice, uint256(3)));
        vm.store(address(registry), nullifierSlot, nullifier);
        // Sanity:
        assertTrue(registry.isVerified(alice));
        assertEq(registry.nullifierOf(alice), nullifier);

        vm.prank(alice);
        uint256 tokenId = nft.mint();
        assertEq(tokenId, 1);
        assertEq(nft.ownerOf(1), alice);
        assertEq(nft.tokenIdByNullifier(nullifier), 1);
    }
}
