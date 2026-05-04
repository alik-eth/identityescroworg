pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";

/// @notice Canonical SPKI commitment per V5 spec §0.2.
///         SpkiCommit(spki) = Poseidon₂(Poseidon₆(xLimbs), Poseidon₆(yLimbs)).
///
/// @dev    Pure refactor of V4's inline construction at
///         ZkqesPresentationEcdsaLeaf.circom:290-299, factored into a reusable
///         template so the V5 main circuit can instantiate it twice (once for
///         the leaf SPKI commit, once for the intermediate). Witness side runs
///         the same Poseidon parameters (BN254, iden3) as the TS reference
///         impl in scripts/spki-commit-ref.ts and the Solidity Foundry impl in
///         arch-contracts/src/lib/P256Verify.sol — three implementations
///         gated against the parity fixture at fixtures/spki-commit/v5-parity.json.
template SpkiCommit() {
    signal input  xLimbs[6]; // 6×43-bit LE limbs of the P-256 X coordinate
    signal input  yLimbs[6]; // 6×43-bit LE limbs of the P-256 Y coordinate
    signal output commit;

    component packX = Poseidon(6);
    for (var i = 0; i < 6; i++) packX.inputs[i] <== xLimbs[i];

    component packY = Poseidon(6);
    for (var i = 0; i < 6; i++) packY.inputs[i] <== yLimbs[i];

    component combine = Poseidon(2);
    combine.inputs[0] <== packX.out;
    combine.inputs[1] <== packY.out;

    commit <== combine.out;
}
