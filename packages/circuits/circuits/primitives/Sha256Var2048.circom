pragma circom 2.1.9;

// Top-level test instantiation of Sha256Var at MAX_BYTES = 2048.
// Used by test/primitives/sha256.test.ts.

include "./Sha256Var.circom";

component main = Sha256Var(2048);
