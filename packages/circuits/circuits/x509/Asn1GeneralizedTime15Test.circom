pragma circom 2.1.9;

// Top-level harness for testing Asn1GeneralizedTime15 on a 1024-byte buffer.
include "./X509Parse.circom";

template Main() {
    signal input bytes[1024];
    signal input offset;
    signal output content[15];
    component s = Asn1GeneralizedTime15(1024);
    for (var i = 0; i < 1024; i++) s.bytes[i] <== bytes[i];
    s.offset <== offset;
    for (var i = 0; i < 15; i++) content[i] <== s.content[i];
}

component main = Main();
