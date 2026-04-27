// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IQKBRegistry } from "./IQKBRegistry.sol";

/// @title Verified — abstract base contract gating callers on QKB verification.
/// @notice Inherit and apply `onlyVerifiedUkrainian` to any external function
///         that should only be callable by a verified Ukrainian holder.
abstract contract Verified {
    IQKBRegistry public immutable qkbRegistry;

    error NotVerifiedUkrainian(address caller);

    constructor(IQKBRegistry _registry) {
        qkbRegistry = _registry;
    }

    modifier onlyVerifiedUkrainian() {
        if (!qkbRegistry.isVerified(msg.sender)) revert NotVerifiedUkrainian(msg.sender);
        _;
    }
}
