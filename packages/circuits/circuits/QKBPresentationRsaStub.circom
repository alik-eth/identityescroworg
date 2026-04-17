pragma circom 2.1.9;

// QKBPresentationRsaStub — DEV-ONLY placeholder with the Phase-2 14-signal
// public layout. Identical ABI to QKBPresentationEcdsaStub; only the
// algorithmTag literal differs (0 = RSA). Downstream verifier dispatch on
// the contracts side selects between the two compiled verifier contracts at
// runtime by reading `publicSignals[12]`.
//
// See QKBPresentationEcdsaStub.circom for the full public-signal layout.
// algorithmTag is CONSTANT = 0 in this circuit.

template QKBPresentationRsaStub() {
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

    signal output stubCommit;
    var acc = ctxHash + rTL + declHash + timestamp + algorithmTag + nullifier;
    for (var i = 0; i < 4; i++) {
        acc += pkX[i] + pkY[i];
    }
    stubCommit <== acc;
}

component main {public [pkX, pkY, ctxHash, rTL, declHash, timestamp, algorithmTag, nullifier]}
    = QKBPresentationRsaStub();
