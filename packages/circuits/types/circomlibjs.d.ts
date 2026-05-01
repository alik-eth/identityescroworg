// circomlibjs ships no type declarations as of v0.1.7. Existing in-repo usage
// (V4 witness builders + V5 spki-commit-ref.ts) wraps the imported `buildPoseidon`
// in a narrow local interface that captures only the surface we touch
// (see `test/integration/witness-builder.ts` for the canonical shape). This
// ambient declaration silences `TS7016 — Could not find a declaration file`
// for the package globally so each call site does not need a per-import shim.
declare module 'circomlibjs';
