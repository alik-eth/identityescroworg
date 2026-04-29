// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @title  Groth16VerifierV5 — STUB. Always returns true.
/// @notice Replaced by the real ceremony output before mainnet.
/// @dev    Until the real verifier lands, integration tests assume the
///         caller supplied a valid (proof, publicSignals) pair from a
///         trusted source. Public-signal layout is the V5 14-element shape
///         frozen at orchestration §2.1 — DO NOT change the array width
///         when the real verifier is pumped in (snarkjs auto-generated
///         output already matches `uint[14] input`).
///
///         The real Groth16Verifier shipped by circuits-eng's ceremony
///         (post-§14 of their plan) is one file replacement:
///           rm src/Groth16VerifierV5.sol
///           cp <ceremony-out>/verifier.sol src/Groth16VerifierV5.sol
///         No registry or other contract changes required because the
///         interface (a, b, c, input) is already correct.
contract Groth16VerifierV5 {
    /// @notice Stub-verifier accept-all. Real verifier returns the result of
    ///         the BN254 pairing equation per Groth16.
    /// @param  a     Proof element A (pi_a)        — uint256[2]
    /// @param  b     Proof element B (pi_b)        — uint256[2][2]
    /// @param  c     Proof element C (pi_c)        — uint256[2]
    /// @param  input The 14 public signals per V5 spec §0.1:
    ///                [0]  msgSender
    ///                [1]  timestamp
    ///                [2]  nullifier
    ///                [3]  ctxHashHi
    ///                [4]  ctxHashLo
    ///                [5]  bindingHashHi
    ///                [6]  bindingHashLo
    ///                [7]  signedAttrsHashHi
    ///                [8]  signedAttrsHashLo
    ///                [9]  leafTbsHashHi
    ///                [10] leafTbsHashLo
    ///                [11] policyLeafHash
    ///                [12] leafSpkiCommit
    ///                [13] intSpkiCommit
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[14] calldata input
    ) external pure returns (bool) {
        // Silence unused-arg warnings without burning gas.
        a; b; c; input;
        return true;
    }
}
