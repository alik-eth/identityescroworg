pragma circom 2.1.9;

// Top-level test wrapper for the legacy V2Core parser.
//   MAX_B           = 1024   (V5 MAX_BCANON; spec amendment 768→1024 in flight)
//   MAX_CTX         = 256    bytes
//   MAX_TS_DIGITS   = 20     bytes (full uint64 range)
//
// Same template as the original BindingParseV2Core; this wrapper exists only
// to give circom_tester a `component main` to instantiate. The Fast refactor
// (§6.0a Phase 3) lands as a sibling template + sibling test wrapper; both
// wrappers run identical witness inputs so the parity test is byte-exact.

include "./BindingParseV2Core.circom";

component main = BindingParseV2Core(1024, 256, 20);
