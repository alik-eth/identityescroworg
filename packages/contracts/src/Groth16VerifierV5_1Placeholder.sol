// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @title  Groth16VerifierV5_1Placeholder — accepts all proofs.
/// @notice TEMPORARY placeholder while circuits-eng's V5.1 stub ceremony
///         is in flight. Matches the snarkjs-generated 19-public-input
///         verifier ABI so the registry compiles + tests can exercise the
///         V5.1 register/rotateWallet flows against synthetic public
///         signals.
///
///         Lead will pump `Groth16VerifierV5_1Stub.sol` (real ceremony
///         output, 19-field public-input array) into this same `src/`
///         directory; the registry's import flips one line, and this
///         placeholder file is deleted in the same commit.
///
/// @dev    DO NOT use in production deploys. The Deploy script logs a
///         loud warning when the placeholder is wired in, mirroring the
///         §5-stub safety pattern.
contract Groth16VerifierV5_1Placeholder {
    /// @notice Accept-all stub. Real verifier returns the result of the
    ///         BN254 pairing equation per Groth16.
    /// @param  a     Proof element A (pi_a) — uint256[2]
    /// @param  b     Proof element B (pi_b) — uint256[2][2]
    /// @param  c     Proof element C (pi_c) — uint256[2]
    /// @param  input The 19 public signals per V5.1 spec / orchestration §1.1:
    ///                [0]  msgSender
    ///                [1]  timestamp
    ///                [2]  nullifier              (V5.1: Poseidon₂(walletSecret, ctxHash))
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
    ///                [14] identityFingerprint   (V5.1 NEW)
    ///                [15] identityCommitment    (V5.1 NEW)
    ///                [16] rotationMode          (V5.1 NEW: 0 = register, 1 = rotate)
    ///                [17] rotationOldCommitment (V5.1 NEW; = identityCommitment under register)
    ///                [18] rotationNewWallet     (V5.1 NEW; = msgSender under register)
    function verifyProof(
        uint256[2]    calldata a,
        uint256[2][2] calldata b,
        uint256[2]    calldata c,
        uint256[19]   calldata input
    ) external pure returns (bool) {
        // Silence unused-arg warnings without burning gas.
        a; b; c; input;
        return true;
    }
}
