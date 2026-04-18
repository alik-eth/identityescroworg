pragma circom 2.1.9;

// NullifierDerive — Phase-2 QIE nullifier primitive.
//
// Person-level construction, amended 2026-04-18 (see
// `docs/superpowers/specs/2026-04-18-person-nullifier-amendment.md`):
//
//   secret    = Poseidon( subjectSerialLimbs[0..3], subjectSerialLen )  // arity 5
//   nullifier = Poseidon( secret, ctxHash )                              // arity 2
//
// Rationale:
//   * `subjectSerialLimbs` is the per-person identifier (ETSI EN 319 412-1
//     §5.1.3 semantics identifier in OID 2.5.4.5 — `PNOUA-…`, `PNODE-…`,
//     `TINPL-…`, etc.) extracted by `X509SubjectSerial`, packed as 4 × 64-bit
//     LE limbs. Stable across QES renewals because the national identifier
//     does not change when a cert is rotated.
//   * `subjectSerialLen` is hashed alongside the limbs to prevent
//     padding-collision attacks between identifiers of different natural
//     byte-lengths (8-byte EDRPOU vs 10-byte РНОКПП vs 14-byte `PNODE-…`
//     vs 16-byte `TINUA-…`). Without it, a hypothetical collision between
//     the LE-limb packing of one identifier and the padded-zero suffix of
//     a shorter identifier could produce identical nullifiers.
//   * No `issuerCertHash` input (removed in the 2026-04-18 amendment):
//     binding the nullifier to the issuing QTSP would make it QTSP-scoped,
//     defeating Sybil resistance when a person switches between QTSPs
//     (common in practice — e.g. Diia → PrivatBank → Masterkey in UA).
//   * The two-step split (rather than a single 6-input hash) lets callers
//     expose `secret` for long-lived commitments while keeping the
//     context-specific `nullifier` separate.
//
// No domain-separation tags are added here: the outer context hash
// (`ctxHash`) is itself already a hash of domain-specific bytes, and the
// two arity values (5 and 2) are themselves distinguishing for Poseidon.

include "circomlib/circuits/poseidon.circom";

template NullifierDerive() {
    signal input subjectSerialLimbs[4];
    signal input subjectSerialLen;
    signal input ctxHash;
    signal output secret;
    signal output nullifier;

    component h1 = Poseidon(5);
    h1.inputs[0] <== subjectSerialLimbs[0];
    h1.inputs[1] <== subjectSerialLimbs[1];
    h1.inputs[2] <== subjectSerialLimbs[2];
    h1.inputs[3] <== subjectSerialLimbs[3];
    h1.inputs[4] <== subjectSerialLen;
    secret <== h1.out;

    component h2 = Poseidon(2);
    h2.inputs[0] <== secret;
    h2.inputs[1] <== ctxHash;
    nullifier <== h2.out;
}
