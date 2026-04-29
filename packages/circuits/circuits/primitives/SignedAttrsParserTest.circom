pragma circom 2.1.9;

include "./SignedAttrsParser.circom";

// MAX_SA = 1536 per V5 spec v5 (commit 1c14f0f) — sized for real Diia
// CAdES-X-L signedAttrs (~1388 B observed) with 10% headroom.
component main = SignedAttrsParser(1536);
