// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @notice Whitelisted declaration digests as emitted by the circuit's
///         `Bits256ToField`: sha256(declaration) interpreted as a
///         big-endian 256-bit integer, reduced mod the BN254 scalar field p.
///         These are NOT assumed to be raw sha256 bytes32 — raw digests may
///         overflow p, so the circuit reports them reduced. The
///         contract-side whitelist must match the
///         circuit's actual field-element output.
///
///         Raw sha256 references (pre-reduction):
///           EN sha256: 007889dc58abf061ca1ba9d64a3cee02365c41eada133d028c51d4c7d0471084
///           UK sha256: fef523c6bee57ac2969d1bce6583f9b112a4859192cb7368929b4795654dfa90
///
///         BN254 scalar field p:
///           0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
library DeclarationHashes {
    /// @dev sha256("...EN canonical declaration...") mod p.
    bytes32 internal constant EN = 0x007889dc58abf061ca1ba9d64a3cee02365c41eada133d028c51d4c7d0471084;

    /// @dev sha256("...UK canonical declaration...") mod p.
    bytes32 internal constant UK = 0x0cff9b8858ed59f1fd0bbf3dddfd3fdf49a0fc27322c40923f317bb1b54dfa8b;

    function isAllowed(bytes32 h) internal pure returns (bool) {
        return h == EN || h == UK;
    }
}
