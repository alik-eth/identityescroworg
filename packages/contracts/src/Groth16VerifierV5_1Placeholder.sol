// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @title  Groth16VerifierV5_1Placeholder — accept-all gate for the
///         contracts package's SYNTHETIC unit-test surface. NOT for
///         production. Production uses a real ceremonied Groth16 verifier
///         deployed separately and passed via GROTH16_VERIFIER_ADDR.
/// @notice Three Groth16 verifier roles coexist intentionally:
///           - This placeholder (always-true, 19-input shape) — wired
///             into the synthetic unit tests (`ZkqesRegistryV5.t.sol`,
///             `ZkqesRegistryV5.register.t.sol`, `ZkqesRegistryV5_1.t.sol`,
///             `ZkqesCertificate.v5.t.sol`, `DeployV5.fork.t.sol`),
///             which exercise register/rotateWallet flows against
///             SYNTHETIC public signals computed off-circuit. Those
///             signals don't satisfy the real BN254 pairing equation;
///             accept-all is the only practical gate that keeps the
///             unit-test surface focused on the contract logic the
///             tests are actually verifying (mappings, gates,
///             reverts, Merkle climbs).
///           - `Groth16VerifierV5_1Stub.sol` (real BN254 pairing,
///             snarkjs-generated from circuits-eng's V5.1 single-
///             contributor STUB ceremony) — wired into the real-tuple
///             integration test (`RealTupleGasSnapshot.t.sol`) for
///             real-pairing gas measurement. Same shape as production
///             but different verification key, so production proofs
///             would reject under the stub and vice versa.
///           - Production verifier (deployed separately after the
///             multi-contributor Phase-2 ceremony at circuits-eng §11)
///             — wired by setting GROTH16_VERIFIER_ADDR before running
///             DeployV5.s.sol.
///
///         The Deploy script (DeployV5.s.sol) uses THIS placeholder
///         (always-true) ONLY when GROTH16_VERIFIER_ADDR is unset —
///         dev/anvil convenience. Production deploys MUST pass
///         GROTH16_VERIFIER_ADDR pointing at the real ceremonied verifier.
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
