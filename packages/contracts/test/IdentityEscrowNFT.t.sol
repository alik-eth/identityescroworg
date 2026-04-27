// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import { IdentityEscrowNFT } from "../src/IdentityEscrowNFT.sol";
import { IQKBRegistry }      from "../src/IdentityEscrowNFT.sol";

contract MockRegistry is IQKBRegistry {
    mapping(address => bytes32) private _n;
    function set(address holder, bytes32 nullifier) external { _n[holder] = nullifier; }
    function isVerified(address h) external view returns (bool)  { return _n[h] != bytes32(0); }
    function nullifierOf(address h) external view returns (bytes32) { return _n[h]; }
    function trustedListRoot() external pure returns (bytes32) { return bytes32(uint256(0xABC)); }
}

contract IdentityEscrowNFTTest is Test {
    IdentityEscrowNFT nft;
    MockRegistry      registry;
    address constant ALICE = address(0xA11CE);
    address constant BOB   = address(0xB0B);
    uint64  constant DEADLINE = 2_000_000_000;

    function setUp() public {
        registry = new MockRegistry();
        nft = new IdentityEscrowNFT(IQKBRegistry(address(registry)), DEADLINE, "Sepolia");
    }

    function test_mint_succeedsWhenVerifiedBeforeDeadline() public {
        registry.set(ALICE, bytes32(uint256(0x1234)));
        vm.warp(DEADLINE - 1);
        vm.prank(ALICE);
        uint256 tokenId = nft.mint();
        assertEq(tokenId, 1);
        assertEq(nft.ownerOf(1), ALICE);
        assertEq(nft.tokenIdByNullifier(bytes32(uint256(0x1234))), 1);
    }

    function test_mint_revertsNotVerifiedForUnregisteredAddress() public {
        vm.warp(DEADLINE - 1);
        vm.prank(ALICE);
        vm.expectRevert(bytes("NOT_VERIFIED"));
        nft.mint();
    }

    function test_mint_revertsAlreadyMintedForSecondNullifierMint() public {
        bytes32 n = bytes32(uint256(0x5678));
        registry.set(ALICE, n);
        registry.set(BOB,   n); // same nullifier somehow ends up bound to Bob too
        vm.warp(DEADLINE - 1);
        vm.prank(ALICE);
        nft.mint();
        vm.prank(BOB);
        vm.expectRevert(bytes("ALREADY_MINTED"));
        nft.mint();
    }

    function test_mint_revertsMintClosedAfterDeadline() public {
        registry.set(ALICE, bytes32(uint256(0x9999)));
        vm.warp(DEADLINE + 1);
        vm.prank(ALICE);
        vm.expectRevert(bytes("MINT_CLOSED"));
        nft.mint();
    }

    function test_mint_succeedsAtExactDeadline() public {
        registry.set(ALICE, bytes32(uint256(0xAAAA)));
        vm.warp(DEADLINE);
        vm.prank(ALICE);
        nft.mint();
        assertEq(nft.balanceOf(ALICE), 1);
    }

    function test_emit_certificateMinted() public {
        bytes32 n = bytes32(uint256(0xCAFE));
        registry.set(ALICE, n);
        vm.warp(DEADLINE - 1);
        vm.expectEmit(true, true, true, true);
        emit IdentityEscrowNFT.CertificateMinted(1, ALICE, n, uint64(DEADLINE - 1));
        vm.prank(ALICE);
        nft.mint();
    }

    function test_transfer_works() public {
        registry.set(ALICE, bytes32(uint256(0xFF)));
        vm.warp(DEADLINE - 1);
        vm.prank(ALICE);
        nft.mint();
        vm.prank(ALICE);
        nft.transferFrom(ALICE, BOB, 1);
        assertEq(nft.ownerOf(1), BOB);
    }

    function test_transferDoesNotResetNullifierMintFlag() public {
        bytes32 n = bytes32(uint256(0xDD));
        registry.set(ALICE, n);
        vm.warp(DEADLINE - 1);
        vm.prank(ALICE);
        nft.mint();
        vm.prank(ALICE);
        nft.transferFrom(ALICE, BOB, 1);
        // ALICE re-attempts mint after transferring — still blocked
        vm.prank(ALICE);
        vm.expectRevert(bytes("ALREADY_MINTED"));
        nft.mint();
    }
}
