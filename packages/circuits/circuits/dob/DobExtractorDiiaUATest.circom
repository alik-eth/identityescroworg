pragma circom 2.1.9;

// Test-only wrapper: pins `component main` so the Diia UA extractor can be
// compiled + witnessed standalone. Production circuits pull `DobExtractor`
// through `DobExtractorDiiaUA.circom` (template-only) via an include in
// `QKBPresentationEcdsaLeafV4_UA.circom`.
include "./DobExtractorDiiaUA.circom";

// MAX_DER = 1536 mirrors the leaf circuit's MAX_CERT (production sizing).
component main = DobExtractor(1536);
