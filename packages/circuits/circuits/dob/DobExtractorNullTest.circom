pragma circom 2.1.9;

// Test-only wrapper: pins `component main` so the null extractor can be
// compiled + witnessed standalone. Production circuits pull `DobExtractor`
// through `DobExtractorNull.circom` (template-only) via an include in the
// per-country leaf wrapper.
include "./DobExtractorNull.circom";

// MAX_DER = 1536 mirrors the leaf circuit's MAX_CERT (production sizing).
component main = DobExtractor(1536);
