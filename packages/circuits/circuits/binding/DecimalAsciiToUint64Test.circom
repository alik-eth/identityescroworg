pragma circom 2.1.9;

include "./BindingDecimal.circom";

// MAX_DIGITS = 20 covers full uint64 range.
component main = DecimalAsciiToUint64(20);
