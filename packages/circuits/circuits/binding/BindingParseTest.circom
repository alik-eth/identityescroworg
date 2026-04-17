pragma circom 2.1.9;

// Top-level test instantiation for BindingParse at MAX_B = 1024.
include "./BindingParse.circom";

component main = BindingParse(1024);
