pragma circom 2.1.9;

// v2 — person-level nullifier (subjectSerialLen replaces issuerCertHash).
// Bumping this comment invalidates the test-cache hash computed by
// `test/helpers/compile.ts` over this file's bytes; the include chain
// is not hashed recursively, so the top-level file must change when the
// included NullifierDerive.circom interface changes.
include "./NullifierDerive.circom";

component main = NullifierDerive();
