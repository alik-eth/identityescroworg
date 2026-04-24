pragma circom 2.1.6;

include "./helper.circom";

template HarnessMain() {
    signal input x;
    signal output y;
    component h = HarnessHelper();
    h.in <== x;
    y <== h.out;
}
