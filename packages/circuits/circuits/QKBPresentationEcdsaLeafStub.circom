pragma circom 2.1.9;

// QKBPresentationEcdsaLeafStub — DEV-ONLY placeholder with the same public
// signal layout as QKBPresentationEcdsaLeaf. Wired so that downstream
// contract + web consumers can integrate against a real (but trivial)
// Groth16 verifier today, while the expensive 7.6M-constraint ceremony runs
// later on a rented high-memory VPS. At deploy time, only the verifier
// bytecode swaps — the ABI is identical.
//
// Public signals (same order as the full circuit):
//   output leafSpkiCommit
//   input  pkX[4], pkY[4], ctxHash, declHash, timestamp
//
// This circuit asserts NOTHING about the inputs beyond a trivial linear
// combination. DO NOT DEPLOY TO PRODUCTION.

template QKBPresentationEcdsaLeafStub() {
    signal input pkX[4];
    signal input pkY[4];
    signal input ctxHash;
    signal input declHash;
    signal input timestamp;
    signal output leafSpkiCommit;

    // Trivial non-zero binding so the circuit has at least one R1CS
    // constraint (snarkjs refuses ceremonies on zero-constraint systems).
    var acc = ctxHash + declHash + timestamp;
    for (var i = 0; i < 4; i++) {
        acc += pkX[i] + pkY[i];
    }
    leafSpkiCommit <== acc;
}

component main {public [pkX, pkY, ctxHash, declHash, timestamp]}
    = QKBPresentationEcdsaLeafStub();
