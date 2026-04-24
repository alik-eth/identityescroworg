pragma circom 2.1.9;

// UA-specialized wrapper for the unified V4 leaf template. Links the Diia
// OID 2.5.29.9 extractor. One per-country wrapper per supported jurisdiction.
include "./dob/DobExtractorDiiaUA.circom";
include "./QKBPresentationEcdsaLeafV4.circom";

// QKBPresentationEcdsaLeafV4_UA — the ceremonial circuit compiled for the UA
// registry. Swap DobExtractorDiiaUA for another DobExtractor* include to mint
// a different country's leaf.
