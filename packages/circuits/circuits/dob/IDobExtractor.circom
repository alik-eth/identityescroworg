pragma circom 2.1.9;

// DOB Extractor plug contract (doc-only — circom has no interfaces).
//
// Every concrete DOB extractor must expose the following template signature:
//
//   template DobExtractor() {
//     signal input  leafDER[MAX_DER];     // X.509 leaf cert DER bytes
//     signal input  leafDerLen;           // actual byte length within leafDER
//     signal output dobYmd;               // normalized YYYYMMDD integer
//                                          //   (e.g. 19900815 for 1990-08-15;
//                                          //    0 when dobSupported=0)
//     signal output sourceTag;            // compile-time constant identifying
//                                          // the profile (e.g. 1 = Diia UA,
//                                          // 2 = ETSI standard, 0 = null)
//     signal output dobSupported;         // 1 if extraction succeeded; 0 else
//   }
//
// MAX_DER is fixed at the leaf circuit level (MAX_CERT = 2048 in V4). Extractors
// must assume leafDER is zero-padded beyond leafDerLen and MUST NOT read past
// leafDerLen.
//
// The leaf circuit computes:
//   dobCommit = Poseidon(dobYmd, sourceTag)
// and exposes dobCommit + dobSupported as public signals 14 and 15. When
// dobSupported=0, dobCommit is Poseidon(0, 0) = a fixed sentinel — registry
// reads dobSupported to decide whether dobCommit is meaningful.
