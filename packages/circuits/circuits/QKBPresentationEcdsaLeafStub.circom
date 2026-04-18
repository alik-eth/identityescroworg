pragma circom 2.1.9;

// QKBPresentationEcdsaLeafStub — DEV-ONLY placeholder with the 13-signal
// public layout of QKBPresentationEcdsaLeaf post-split-proof pivot. Wired
// so that downstream contract + web consumers can integrate against a
// real (but trivial) Groth16 verifier today, while the expensive
// ~7.68M-constraint real ceremony runs later on a Fly VM. At deploy time
// only the verifier bytecode swaps — the Solidity ABI is identical
// (`verifyProof(uint[2], uint[2][2], uint[2], uint[13])`).
//
// Public signals (13, same order and declaration pattern as the real
// Leaf per orchestration §2.1 — leafSpkiCommit declared LAST so snarkjs
// emits it at publicSignals[12] matching contracts-eng's leafArr[12]):
//   input  pkX[4], pkY[4], ctxHash, declHash, timestamp, nullifier,
//          leafSpkiCommit
//
// This circuit asserts NOTHING about the inputs beyond a trivial quadratic
// binding (needed because snarkjs refuses ceremonies on zero-constraint
// systems). DO NOT DEPLOY TO PRODUCTION.

template QKBPresentationEcdsaLeafStub() {
    signal input pkX[4];
    signal input pkY[4];
    signal input ctxHash;
    signal input declHash;
    signal input timestamp;
    signal input nullifier;
    signal input leafSpkiCommit;

    // Non-linear binding so snarkjs has ≥ 1 quadratic constraint to run a
    // ceremony against. Multiplies leafSpkiCommit by itself so the stub's
    // R1CS depends on the 13th public signal — otherwise a prover could
    // pick arbitrary values for pkX/pkY/etc. and still produce a valid
    // proof (which is acceptable for a stub, but this documents intent).
    signal dummyQuad;
    dummyQuad <== leafSpkiCommit * leafSpkiCommit;
}

component main {public [pkX, pkY, ctxHash, declHash, timestamp, nullifier, leafSpkiCommit]}
    = QKBPresentationEcdsaLeafStub();
