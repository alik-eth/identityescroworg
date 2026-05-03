// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

/// @title  Groth16VerifierV5_2Placeholder — accept-all gate for the
///         contracts package's SYNTHETIC unit-test surface. NOT for
///         production. Production uses a real ceremonied Groth16 verifier
///         deployed separately and passed via GROTH16_VERIFIER_ADDR.
/// @notice Three Groth16 verifier roles coexist intentionally (mirrors
///         the V5.1 placeholder pattern):
///           - This placeholder (always-true, 22-input shape) — wired
///             into the synthetic V5.2 unit tests, which exercise
///             register/rotateWallet flows against SYNTHETIC public
///             signals computed off-circuit. Those signals don't
///             satisfy the real BN254 pairing equation; accept-all is
///             the only practical gate that keeps the unit-test surface
///             focused on the contract logic the tests are actually
///             verifying (mappings, gates, reverts, Merkle climbs,
///             keccak-derived address bind).
///           - `Groth16VerifierV5_2Stub.sol` (real BN254 pairing,
///             snarkjs-generated from circuits-eng's V5.2 single-
///             contributor STUB ceremony) — wired into the real-tuple
///             integration test for real-pairing gas measurement. Same
///             shape (uint[22]) as production but different verification
///             key.
///           - Production verifier (deployed separately after the
///             multi-contributor Phase-2 ceremony) — wired by setting
///             GROTH16_VERIFIER_ADDR before running DeployV5_2.s.sol.
///
///         A future `DeployV5_2.s.sol` (T4 implementation task) will use
///         THIS placeholder (always-true) ONLY when `GROTH16_VERIFIER_ADDR`
///         is unset — dev/anvil convenience, mirroring the V5.1 deploy
///         pattern. Production deploys MUST pass `GROTH16_VERIFIER_ADDR`
///         pointing at the real ceremonied verifier; the script will log
///         a loud warning when the placeholder is wired in.
///         (Until DeployV5_2.s.sol lands, this placeholder is referenced
///         only by V5.2 unit tests + the future integration suite.)
///
/// @dev    V5.2 layout vs V5.1:
///           - Slot [0] msgSender DROPPED (no longer circuit-emitted; the
///             contract derives it via keccak(bindingPkX/Y) on-chain).
///           - V5.1 slots 1..18 shift down to V5.2 slots 0..17.
///           - 4 new slots [18..21]: bindingPkXHi, bindingPkXLo,
///             bindingPkYHi, bindingPkYLo (each Bits2Num(128)-packed
///             from parser.pkBytes — see V5.2 spec §"Construction").
///
/// @dev    DO NOT use in production deploys. The Deploy script logs a
///         loud warning when the placeholder is wired in, mirroring the
///         §5-stub safety pattern.
contract Groth16VerifierV5_2Placeholder {
    /// @notice Accept-all stub. Real verifier returns the result of the
    ///         BN254 pairing equation per Groth16.
    /// @param  a     Proof element A (pi_a) — uint256[2]
    /// @param  b     Proof element B (pi_b) — uint256[2][2]
    /// @param  c     Proof element C (pi_c) — uint256[2]
    /// @param  input The 22 public signals per V5.2 spec / amendment §"Public-signal layout":
    ///                [0]  timestamp              (V5.1 slot 1, shifted down)
    ///                [1]  nullifier              (V5.1 slot 2; Poseidon₂(walletSecret, ctxHash))
    ///                [2]  ctxHashHi
    ///                [3]  ctxHashLo
    ///                [4]  bindingHashHi
    ///                [5]  bindingHashLo
    ///                [6]  signedAttrsHashHi
    ///                [7]  signedAttrsHashLo
    ///                [8]  leafTbsHashHi
    ///                [9]  leafTbsHashLo
    ///                [10] policyLeafHash
    ///                [11] leafSpkiCommit
    ///                [12] intSpkiCommit
    ///                [13] identityFingerprint
    ///                [14] identityCommitment
    ///                [15] rotationMode           (0 = register, 1 = rotateWallet)
    ///                [16] rotationOldCommitment
    ///                [17] rotationNewWallet      (under register-mode: == derivedAddr from bindingPk)
    ///                [18] bindingPkXHi           (V5.2 NEW; upper 128 bits of parser.pkBytes[1..33])
    ///                [19] bindingPkXLo           (V5.2 NEW; lower 128 bits of parser.pkBytes[1..33])
    ///                [20] bindingPkYHi           (V5.2 NEW; upper 128 bits of parser.pkBytes[33..65])
    ///                [21] bindingPkYLo           (V5.2 NEW; lower 128 bits of parser.pkBytes[33..65])
    function verifyProof(
        uint256[2]    calldata a,
        uint256[2][2] calldata b,
        uint256[2]    calldata c,
        uint256[22]   calldata input
    ) external pure returns (bool) {
        // Silence unused-arg warnings without burning gas.
        a; b; c; input;
        return true;
    }
}
