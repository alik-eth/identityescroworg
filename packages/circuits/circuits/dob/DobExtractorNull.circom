pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";

// Null extractor: emits dobSupported=0 unconditionally. Links into the leaf
// template for countries that don't extract DOB. MAX_DER parameter matches the
// leaf's MAX_CERT.
template DobExtractor() {
    signal input leafDER[2048];
    signal input leafDerLen;

    signal output dobYmd;
    signal output sourceTag;
    signal output dobSupported;

    dobYmd       <== 0;
    sourceTag    <== 0;
    dobSupported <== 0;

    // Bind leafDER inputs so the compiler doesn't prune them (keeps the
    // extractor signature uniform across countries).
    signal _sink;
    _sink <== leafDerLen * 0;
}

component main = DobExtractor();
