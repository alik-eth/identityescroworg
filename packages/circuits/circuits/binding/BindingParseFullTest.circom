pragma circom 2.1.9;

// Top-level test instantiation for BindingParseFull.
//   MAX_B           = 2048   (per spec amendment b800521)
//   MAX_CTX         = 256    bytes (covers any practical dApp tag)
//   MAX_DECL        = 1024   bytes (covers UK declaration at 905 B)
//   MAX_TS_DIGITS   = 20     bytes (full uint64 range)

include "./BindingParseFull.circom";

component main = BindingParseFull(2048, 256, 1024, 20);
