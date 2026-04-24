pragma circom 2.1.6;

include "./primitive.circom";

template HarnessHelper() {
    signal input in;
    signal output out;
    component p = HarnessPrimitive();
    p.a <== in;
    out <== p.b;
}
