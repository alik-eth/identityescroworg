pragma circom 2.1.9;

// ZkqesPresentationRsaStub — DEV-ONLY placeholder with the Phase-2 14-signal
// public layout. Identical ABI to ZkqesPresentationEcdsaStub; only the
// algorithmTag literal differs (0 = RSA). Downstream verifier dispatch on
// the contracts side selects between the two compiled verifier contracts at
// runtime by reading `publicSignals[12]`.
//
// See ZkqesPresentationEcdsaStub.circom for the full public-signal layout.
// algorithmTag is CONSTANT = 0 in this circuit.

template ZkqesPresentationRsaStub() {
    signal input pkX[4];
    signal input pkY[4];
    signal input ctxHash;
    signal input rTL;
    signal input declHash;
    signal input timestamp;
    signal input algorithmTag;
    signal input nullifier;

    // Literal: this circuit is the RSA path.
    algorithmTag === 0;

    // Non-linear binding so snarkjs has ≥ 1 quadratic constraint to run
    // a ceremony against. Kept INTERNAL — NOT a public output — so the
    // compiled verifier is verifyProof(..., uint[14]), matching the frozen
    // Phase-2 ABI.
    signal dummyQuad;
    dummyQuad <== nullifier * nullifier;
}

component main {public [pkX, pkY, ctxHash, rTL, declHash, timestamp, algorithmTag, nullifier]}
    = ZkqesPresentationRsaStub();
