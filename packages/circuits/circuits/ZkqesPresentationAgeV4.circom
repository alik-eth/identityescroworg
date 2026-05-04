pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

// ZkqesPresentationAgeV4 — age qualification proof for QKB/2 bindings.
// Public signals (3, in on-chain order):
//   [0] dobCommit       = Poseidon(dobYmd, sourceTag)
//   [1] ageCutoffDate   YYYYMMDD integer (public input)
//   [2] ageQualified    1 iff dobYmd <= ageCutoffDate
//
// Private inputs:
//   dobYmd      normalized YYYYMMDD of the holder's DOB
//   sourceTag   identifier of the extractor profile (must match the leaf proof)
//
// dobCommit and ageQualified are public INPUTS rather than template outputs
// so the public-signal index order follows `component main { public [...] }`
// exactly (outputs would otherwise land at indices 0..1, breaking the
// IGroth16AgeVerifierV4 calldata layout shipped in contracts-eng M3.2).
//
// The circuit is country-agnostic; one ceremony + one verifier serve every
// country registry. The leaf proof binds dobCommit; this circuit re-opens it
// and asserts the age predicate over the pre-image (dobYmd, sourceTag).

template ZkqesPresentationAgeV4() {
    signal input dobCommit;
    signal input ageCutoffDate;
    signal input ageQualified;

    signal input dobYmd;
    signal input sourceTag;

    // 1. Re-commit: dobCommit === Poseidon(dobYmd, sourceTag).
    component h = Poseidon(2);
    h.inputs[0] <== dobYmd;
    h.inputs[1] <== sourceTag;
    dobCommit === h.out;

    // 2. Age predicate: ageQualified === (dobYmd <= ageCutoffDate).
    //    32 bits is plenty for YYYYMMDD (max 99999999).
    component cmp = LessEqThan(32);
    cmp.in[0] <== dobYmd;
    cmp.in[1] <== ageCutoffDate;
    ageQualified === cmp.out;
}

component main {public [dobCommit, ageCutoffDate, ageQualified]}
    = ZkqesPresentationAgeV4();
