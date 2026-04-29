pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/bitify.circom";

/// @notice Extracts the messageDigest Attribute's inner OCTET STRING (32 bytes)
///         from a DER-encoded CAdES `signedAttrs` SET OF Attribute, per V5
///         spec §0.3 / spec v5 (commit 1c14f0f).
///
/// @dev    DESIGN: fixed-shape verification at a witnessed offset, NOT a
///         position-agnostic SET OF walker.
///
///         At the witnessed `mdAttrOffset` (a private input), the template
///         asserts the next 17 bytes byte-equal the canonical messageDigest
///         Attribute prefix, then extracts the 32 OCTET STRING content bytes:
///
///           30 2F                                  Attribute SEQUENCE (47B body)
///           06 09 2A 86 48 86 F7 0D 01 09 04       OID id-messageDigest
///                                                  (1.2.840.113549.1.9.4)
///           31 22                                  SET (34B body)
///           04 20                                  OCTET STRING (32B content)
///           [32 bytes]                             messageDigest value
///
/// SOUNDNESS DEPENDENCY:
///
///   This template is sound ONLY because the parent circuit elsewhere asserts
///
///       sha256(bytes[0..length))  ==  signedAttrsHash (public input)
///
///   and `signedAttrsHash` is itself bound (via the leaf-cert ECDSA gate +
///   EIP-7212 on-chain) to the bytes the QES actually signed. Together those
///   constraints fix `bytes[]` to the EXACT wire bytes Diia signed; the
///   prover cannot manipulate content at any offset.
///
///   The 17-byte messageDigest prefix is distinctive (the id-messageDigest
///   OID alone is 9 high-entropy ASN.1 bytes). For Diia's CAdES-X-L profile
///   the marker appears uniquely at byte 60 of signedAttrs. We further
///   constrain `mdAttrOffset < 256` to limit the search space against
///   future emit-format drift; the bound is generous (Diia's actual is 60).
///
///   If the upstream `sha256(bytes) == signedAttrsHash` gate is ever removed
///   or weakened, this fixed-shape walker becomes insufficient and must be
///   replaced by a position-agnostic SET OF walker.
///
/// SHA-256 LOCK:
///
///   The constants `04 20` (OCTET STRING with 32-byte payload) and `31 22`
///   (SET length 34 = 32 + OID/header overhead) hard-code the messageDigest
///   length to 32 bytes. A future migration to SHA-512 would change those
///   to `04 40` and `31 42`, requiring a new template + new ceremony.
template SignedAttrsParser(MAX_SA) {
    signal input  bytes[MAX_SA];
    signal input  length;          // actual signedAttrs length in [0, MAX_SA]
    signal input  mdAttrOffset;    // byte index of the messageDigest Attribute SEQUENCE tag
    signal output messageDigestBytes[32];

    // ---------------------------------------------------------------------
    // 1. Range-check `length <= MAX_SA` and `mdAttrOffset < 256`.
    //    Sha256Var requires the same `length` bound upstream; this is
    //    defence in depth + a clean witness contract for the standalone
    //    test wrapper.
    // ---------------------------------------------------------------------
    component lengthRange = Num2Bits(16);   // MAX_SA = 1536 < 2^16
    lengthRange.in <== length;
    component lengthFitsMax = LessThan(16);
    lengthFitsMax.in[0] <== length;
    lengthFitsMax.in[1] <== MAX_SA + 1;     // length < MAX_SA+1, i.e. ≤ MAX_SA
    lengthFitsMax.out === 1;

    component offsetBound = Num2Bits(8);    // mdAttrOffset < 2^8 = 256
    offsetBound.in <== mdAttrOffset;

    // mdAttrOffset + 49 ≤ length: the full Attribute fits within signedAttrs.
    component fitsInside = LessThan(16);
    fitsInside.in[0] <== mdAttrOffset + 49;
    fitsInside.in[1] <== length + 1;
    fitsInside.out === 1;

    // ---------------------------------------------------------------------
    // 2. Byte-equality against the canonical 17-byte prefix at mdAttrOffset.
    //    Multiplexer(1, MAX_SA) selects bytes[mdAttrOffset + i] for each
    //    of 17 prefix slots and 32 OCTET-STRING-content slots.
    // ---------------------------------------------------------------------
    var PREFIX_LEN = 17;
    var EXPECTED_PREFIX[17] = [
        0x30, 0x2f,                                                       // Attribute SEQUENCE (47)
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, // OID id-messageDigest
        0x31, 0x22,                                                       // SET (34)
        0x04, 0x20                                                        // OCTET STRING (32)
    ];

    component prefixPick[17];
    for (var i = 0; i < PREFIX_LEN; i++) {
        prefixPick[i] = Multiplexer(1, MAX_SA);
        for (var j = 0; j < MAX_SA; j++) {
            prefixPick[i].inp[j][0] <== bytes[j];
        }
        prefixPick[i].sel <== mdAttrOffset + i;
        prefixPick[i].out[0] === EXPECTED_PREFIX[i];
    }

    // ---------------------------------------------------------------------
    // 3. Extract 32 messageDigest content bytes at mdAttrOffset+17..+48.
    // ---------------------------------------------------------------------
    component mdPick[32];
    for (var i = 0; i < 32; i++) {
        mdPick[i] = Multiplexer(1, MAX_SA);
        for (var j = 0; j < MAX_SA; j++) {
            mdPick[i].inp[j][0] <== bytes[j];
        }
        mdPick[i].sel <== mdAttrOffset + 17 + i;
        messageDigestBytes[i] <== mdPick[i].out[0];
    }
}
