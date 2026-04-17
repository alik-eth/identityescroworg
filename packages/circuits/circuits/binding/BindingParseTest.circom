pragma circom 2.1.9;

// Top-level test instantiation for BindingParse at MAX_B = 2048
// (per spec amendment b800521 widening MAX_B from 1024 to 2048 so
// the UK declaration plus JCS envelope fits).
include "./BindingParse.circom";

component main = BindingParse(2048);
