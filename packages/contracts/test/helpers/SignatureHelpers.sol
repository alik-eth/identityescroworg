// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @notice Single source of truth for the QKB `expire` digest. Mirrors the
///         encoding done inside `ZkqesRegistry.expire`; off-chain fixture
///         generators should import this file (or duplicate the encoding
///         verbatim) to stay in lock-step.
library SignatureHelpers {
    string internal constant EXPIRE_DOMAIN = "QKB_EXPIRE_V1";

    function expireDigest(address pkAddr, uint256 chainId, uint64 boundAt) internal pure returns (bytes32) {
        return keccak256(abi.encode(EXPIRE_DOMAIN, pkAddr, chainId, boundAt));
    }
}
