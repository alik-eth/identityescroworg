pragma circom 2.1.9;

// Top-level instantiation for testing PoseidonChunkHash on the pinned
// 839-byte cert from the flattener (test-ca.der). Used for the
// cross-implementation cross-check.

include "./PoseidonChunkHash.circom";

template Main() {
    signal input bytes[839];
    signal output out;
    component h = PoseidonChunkHash(839);
    for (var i = 0; i < 839; i++) h.bytes[i] <== bytes[i];
    out <== h.out;
}

component main = Main();
