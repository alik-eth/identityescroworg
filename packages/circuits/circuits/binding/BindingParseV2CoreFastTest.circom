pragma circom 2.1.9;

// Top-level test wrapper for the Fast (one-Decoder + K-EscalarProduct
// shifted-view) V2Core parser. Instantiated at V5 sizing — keep parameters
// identical to BindingParseV2CoreLegacyTest.circom so the parity test can
// feed both wrappers the same witness inputs.

include "./BindingParseV2CoreFast.circom";

component main = BindingParseV2CoreFast(1024, 256, 20);
