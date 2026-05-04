pragma circom 2.1.9;

// X509SubjectSerial — extract the subject RDN's serialNumber attribute
// value from a leaf certificate DER buffer, packed into 4 × 64-bit LE limbs.
//
// Purpose (Phase-2 QIE, spec §14):
//   The per-credential-namespace QES nullifier is keyed on the leaf certificate's
//   subject.serialNumber attribute (OID 2.5.4.5). This is a CHOICE of
//   DirectoryString — PrintableString / UTF8String / IA5String — whose
//   content bytes encode the national PII identifier (UA РНОКПП, PL PESEL,
//   EE Personal Code, …). Real Diia QES uses PrintableString with ASCII
//   "TINUA-<10 digits>" (16 bytes); all in-scope EU QES subject serials
//   fit in 20 bytes, so 32 bytes is a safe MAX that still packs into a
//   single Poseidon-5 input (4 × uint64 + 1 extra field = 5 inputs).
//   This is intentionally not treated as a universal human identifier:
//   eIDAS/QTSP trust establishes credential validity, while cross-country
//   natural-person deduplication must be handled by a higher identity-escrow
//   layer if an application needs it.
//
// Caller contract:
//   * `leafDER[MAX_CERT]` — raw cert DER, zero-padded to MAX_CERT.
//   * `subjectSerialValueOffset` — byte offset within leafDER where the
//     VALUE (content) bytes of the serialNumber string object begin.
//     Witness-supplied (O(n²) in-circuit ASN.1 walk would blow the constraint
//     budget); the parent circuit re-hashes leafDER via a separate primitive
//     to bind this offset to the cert the leaf signature verifies over.
//   * `subjectSerialValueLength` — number of content bytes, must be in
//     [1, 32]. Any bytes at positions ≥ length that the Multiplexer happens
//     to pull from the DER tail are FORCED to zero before packing, so the
//     limbs are a deterministic function of (serial content bytes) only.
//
// Output:
//   * `subjectSerialLimbs[4]` — 4 × uint64 LE limbs, zero-padded. Byte i of
//     the serial becomes bits [(i%8)*8 .. (i%8)*8+7] of limb[i\8]. This is
//     the same packing convention used for pkX/pkY in secp256k1 (4×64-bit
//     LE), chosen here so the same helpers can build the witness.
//
// Security notes:
//   * Byte-range check (Num2Bits(8)) is applied AFTER masking to zero for
//     out-of-range positions, so the DER tail cannot supply a ≥ 256 value.
//   * Length ≥ 1 is enforced (prevents a prover collapsing different users
//     onto the "empty serial" nullifier universe).
//   * Length ≤ 32 is enforced (otherwise the limbs truncate and different
//     serials could collide; rejected at witness time).
//
// Constraint cost (dominant):
//   32 × Multiplexer(1, MAX_CERT) — same per-byte cost as the existing
//   SPKI coordinate extractors in ZkqesPresentationEcdsaLeaf. For MAX_CERT=2048
//   this is ~32 × 2048 = ~65 k linear constraints plus byte-range R1CS,
//   well under 0.1 M of the 8 M circuit budget.

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";

template X509SubjectSerial(MAX_CERT) {
    var MAX_SERIAL = 32;

    signal input leafDER[MAX_CERT];
    signal input subjectSerialValueOffset;
    signal input subjectSerialValueLength;
    signal output subjectSerialLimbs[4];
    // rawBytes[i] = leafDER[subjectSerialValueOffset + i] for i ∈ [0, MAX_SERIAL).
    // Exposed (post-2026-04-30) so the V5 main circuit's leafTbs ↔ leafCert
    // byte-consistency gate (§6.9) can compare against leafTbs's bytes at
    // the corresponding offset without re-running the Multiplexer extract.
    // Existing witness layout for subjectSerialLimbs[0..3] (witness[1..4])
    // is unchanged — outputs follow declaration order, so rawBytes[0..31]
    // occupies witness[5..36].
    signal output rawBytes[MAX_SERIAL];

    // Length sanity: 1 ≤ length ≤ MAX_SERIAL.
    component lenGeq1 = GreaterEqThan(8);
    lenGeq1.in[0] <== subjectSerialValueLength;
    lenGeq1.in[1] <== 1;
    lenGeq1.out === 1;

    component lenLeq = LessEqThan(8);
    lenLeq.in[0] <== subjectSerialValueLength;
    lenLeq.in[1] <== MAX_SERIAL;
    lenLeq.out === 1;

    // 1. Pull MAX_SERIAL bytes from leafDER at offset+i.
    component pick[MAX_SERIAL];
    for (var i = 0; i < MAX_SERIAL; i++) {
        pick[i] = Multiplexer(1, MAX_CERT);
        for (var j = 0; j < MAX_CERT; j++) pick[i].inp[j][0] <== leafDER[j];
        pick[i].sel <== subjectSerialValueOffset + i;
        rawBytes[i] <== pick[i].out[0];
    }

    // 2. Mask positions ≥ length to zero. mask[i] = (i < length) as 0/1.
    //    Then bytes[i] = mask[i] * rawBytes[i]. Quadratic but MAX_SERIAL=32,
    //    trivial cost.
    component mask[MAX_SERIAL];
    signal bytes[MAX_SERIAL];
    for (var i = 0; i < MAX_SERIAL; i++) {
        mask[i] = LessThan(8);
        mask[i].in[0] <== i;
        mask[i].in[1] <== subjectSerialValueLength;
        bytes[i] <== mask[i].out * rawBytes[i];
    }

    // 3. Byte-range [0..255]. Only meaningful after masking — positions
    //    ≥ length are now zero regardless of what the DER pointer held.
    component byteCheck[MAX_SERIAL];
    for (var i = 0; i < MAX_SERIAL; i++) {
        byteCheck[i] = Num2Bits(8);
        byteCheck[i].in <== bytes[i];
    }

    // 4. Pack into 4 × uint64 LE limbs. Byte bytes[l*8 + 0] is the
    //    LOW-order byte of limb[l] (little-endian within limb).
    for (var l = 0; l < 4; l++) {
        var acc = 0;
        for (var b = 7; b >= 0; b--) {
            acc = acc * 256 + bytes[l * 8 + b];
        }
        subjectSerialLimbs[l] <== acc;
    }
}
