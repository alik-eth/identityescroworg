// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IZkqesRegistry } from "./IZkqesRegistry.sol";

/// @title Verified — abstract base contract gating callers on zkqes verification.
/// @notice Inherit and apply `onlyVerifiedUkrainian` to any external function
///         that should only be callable by a verified Ukrainian holder.
abstract contract Verified {
    IZkqesRegistry public immutable zkqesRegistry;

    error NotVerifiedUkrainian(address caller);

    constructor(IZkqesRegistry _registry) {
        zkqesRegistry = _registry;
    }

    modifier onlyVerifiedUkrainian() {
        if (!zkqesRegistry.isVerified(msg.sender)) revert NotVerifiedUkrainian(msg.sender);
        _;
    }
}
