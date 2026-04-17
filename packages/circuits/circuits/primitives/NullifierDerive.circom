pragma circom 2.1.9;

// NullifierDerive — Phase-2 QIE nullifier primitive.
//
// Per spec §14 of `docs/superpowers/specs/2026-04-17-qie-phase2-design.md`,
// the per-user-per-context nullifier is a two-step Poseidon:
//
//   secret    = Poseidon( subjectSerialLimbs[0..3], issuerCertHash )   // arity 5
//   nullifier = Poseidon( secret, ctxHash )                            // arity 2
//
// Rationale:
//   * `subjectSerialLimbs` is the AlgorithmTag-independent per-user identifier
//     extracted by `X509SubjectSerial`, packed as 4 × 64-bit LE limbs so it
//     round-trips through BN254 without modular reduction (a 32-byte serial
//     fits in 4 × 64 = 256 bits; real EU QES serials are ≤ 20 bytes).
//   * `issuerCertHash` is the Poseidon hash of the intermediate cert DER
//     (same construction as the flattener's `canonicalizeCertHash`) — it
//     binds `secret` to the CA, so a revoked / rotated issuer forces a
//     different nullifier universe even for the same subject.
//   * `secret` is computed with a commit-before-context step so that
//     callers can optionally expose `secret` for long-lived commitments
//     while keeping the context-specific `nullifier` separate.
//   * The two-step split (rather than a single 6-input hash) matches the
//     spec exactly and lets the QIE aggregate secrets across contexts
//     without recomputing the inner hash.
//
// No domain-separation tags are added here: the outer context hash
// (`ctxHash`) is itself already a hash of domain-specific bytes, and the
// two arity values (5 and 2) are themselves distinguishing for Poseidon.

include "circomlib/circuits/poseidon.circom";

template NullifierDerive() {
    signal input subjectSerialLimbs[4];
    signal input issuerCertHash;
    signal input ctxHash;
    signal output secret;
    signal output nullifier;

    component h1 = Poseidon(5);
    h1.inputs[0] <== subjectSerialLimbs[0];
    h1.inputs[1] <== subjectSerialLimbs[1];
    h1.inputs[2] <== subjectSerialLimbs[2];
    h1.inputs[3] <== subjectSerialLimbs[3];
    h1.inputs[4] <== issuerCertHash;
    secret <== h1.out;

    component h2 = Poseidon(2);
    h2.inputs[0] <== secret;
    h2.inputs[1] <== ctxHash;
    nullifier <== h2.out;
}
