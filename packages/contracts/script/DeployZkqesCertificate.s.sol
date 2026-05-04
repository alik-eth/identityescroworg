// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { IdentityEscrowNFT, IQKBRegistry } from "../src/IdentityEscrowNFT.sol";

/// @notice Deploys the v5 `IdentityEscrowNFT` (ERC-721) wired to a previously-
///         deployed `QKBRegistryV4`. Mint window is constructor-frozen via
///         `MINT_DEADLINE` (Unix seconds); no admin can extend it post-deploy.
///
///         Required env:
///           ADMIN_PRIVATE_KEY   uint256 — broadcast key.
///           ADMIN_ADDRESS       address — must equal `vm.addr(ADMIN_PRIVATE_KEY)`.
///           REGISTRY_ADDR       address — already-deployed QKBRegistryV4 instance.
///           MINT_DEADLINE       uint64  — Unix-seconds deadline for `mint()`.
///           CHAIN_LABEL         string  — human-readable network tag, e.g. "Sepolia" / "Base".
contract DeployIdentityEscrowNFT is Script {
    error AdminMismatch();

    function run() external returns (address nftAddr) {
        address registryAddr = vm.envAddress("REGISTRY_ADDR");
        uint64  deadline     = uint64(vm.envUint("MINT_DEADLINE"));
        string memory label  = vm.envString("CHAIN_LABEL");
        address admin        = vm.envAddress("ADMIN_ADDRESS");
        uint256 pk           = vm.envUint("ADMIN_PRIVATE_KEY");
        if (vm.addr(pk) != admin) revert AdminMismatch();

        vm.startBroadcast(pk);
        IdentityEscrowNFT nft = new IdentityEscrowNFT(
            IQKBRegistry(registryAddr), deadline, label
        );
        vm.stopBroadcast();
        nftAddr = address(nft);
        console2.log("IdentityEscrowNFT deployed at:", nftAddr);
        console2.log("  registry         :", registryAddr);
        console2.log("  mintDeadline     :", deadline);
        console2.log("  chainLabel       :", label);
        console2.log("  chainid          :", block.chainid);
    }
}
