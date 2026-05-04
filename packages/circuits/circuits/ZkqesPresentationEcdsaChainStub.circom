pragma circom 2.1.9;

// ZkqesPresentationEcdsaChainStub — DEV-ONLY placeholder with the 5-signal
// public layout of ZkqesPresentationEcdsaChain post-split-proof pivot.
// Wired so that downstream contract + web consumers can integrate against
// a real (but trivial) Groth16 verifier today, while the ~3.2M-constraint
// real Chain ceremony runs later on a Fly VM. At deploy time only the
// verifier bytecode swaps — the Solidity ABI is identical
// (`verifyProof(uint[2], uint[2][2], uint[2], uint[5])`).
//
// Public signals (5, same order as the real Chain per orchestration §2.2 —
// leafSpkiCommit declared LAST so snarkjs emits it at publicSignals[2]
// matching contracts-eng's chainArr[2]):
//   input  rTL, algorithmTag, leafSpkiCommit
//
// algorithmTag is constrained LITERALLY to 1 (ECDSA path) so the stub
// reflects the real circuit's literal. The RSA-path chain stub (when it
// lands) constrains algorithmTag === 0 and shares this ABI.
//
// DO NOT DEPLOY TO PRODUCTION.

template ZkqesPresentationEcdsaChainStub() {
    signal input rTL;
    signal input algorithmTag;
    signal input leafSpkiCommit;

    // Literal: this circuit is the ECDSA path. Prevents a prover from
    // swapping the tag at witness time — mirrors the real Chain circuit.
    algorithmTag === 1;

    // Non-linear binding so snarkjs has ≥ 1 quadratic constraint. Ties
    // the dummy to leafSpkiCommit so contracts-eng's integration tests
    // that exercise the leaf/chain equality check have a meaningful
    // R1CS dependency on the glued signal.
    signal dummyQuad;
    dummyQuad <== leafSpkiCommit * leafSpkiCommit;
}

component main {public [rTL, algorithmTag, leafSpkiCommit]}
    = ZkqesPresentationEcdsaChainStub();
