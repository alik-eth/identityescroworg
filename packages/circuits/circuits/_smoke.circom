pragma circom 2.1.9;

template Smoke() {
    signal input a;
    signal output b;
    b <== a + 1;
}

component main = Smoke();
