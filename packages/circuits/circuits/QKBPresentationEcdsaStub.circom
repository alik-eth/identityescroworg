pragma circom 2.1.9;

// QKBPresentationEcdsaStub — DEV-ONLY placeholder with the Phase-2 14-signal
// public layout. Wired so that downstream contract + web consumers can
// integrate against a real (but trivial) Groth16 verifier while the expensive
// ~10.5 M-constraint ECDSA ceremony runs on Fly. At deploy time only the
// verifier bytecode swaps — the ABI is identical.
//
// Public-signal order (spec §14.3 / orchestration §2.2 — FROZEN):
//   [0..3]   pkX[4]          secp256k1 X limbs, 64-bit LE
//   [4..7]   pkY[4]          secp256k1 Y limbs, 64-bit LE
//   [8]      ctxHash         Poseidon(ctxBytes) or 0 if empty
//   [9]      rTL             trusted-list Merkle root
//   [10]     declHash        packed 256-bit SHA-256 of declaration (mod p)
//   [11]     timestamp       Unix seconds, uint64
//   [12]     algorithmTag    LITERAL 1 in this circuit (ECDSA variant)
//   [13]     nullifier       Poseidon(Poseidon(serial‖issuer), ctxHash)
//
// This circuit asserts NOTHING about the inputs beyond the algorithmTag
// literal + a trivial quadratic binding kept as an internal signal. The
// compiled verifier is verifyProof(..., uint[14]) — matching the frozen
// Phase-2 ABI. DO NOT DEPLOY TO PRODUCTION.

template QKBPresentationEcdsaStub() {
    signal input pkX[4];
    signal input pkY[4];
    signal input ctxHash;
    signal input rTL;
    signal input declHash;
    signal input timestamp;
    signal input algorithmTag;
    signal input nullifier;

    // Literal: this circuit is the ECDSA path. Prevents a prover from
    // swapping the tag at witness time.
    algorithmTag === 1;

    // Non-linear binding so snarkjs has ≥ 1 quadratic constraint to run
    // a ceremony against (zero-constraint systems are rejected). Kept as
    // an INTERNAL signal — NOT a public output — so the compiled verifier
    // is verifyProof(..., uint[14]), matching the frozen Phase-2 ABI.
    signal dummyQuad;
    dummyQuad <== nullifier * nullifier;
}

component main {public [pkX, pkY, ctxHash, rTL, declHash, timestamp, algorithmTag, nullifier]}
    = QKBPresentationEcdsaStub();
