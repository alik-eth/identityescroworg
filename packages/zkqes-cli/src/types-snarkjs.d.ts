// Minimal type stub for `snarkjs` — the upstream package ships no
// types.  We only consume two surfaces (`wtns.calculate` and
// `groth16.verify`); the structural type in `src/server/http.ts`
// imposes the actual contract via `as unknown as SnarkjsModule`.
//
// Mirrors the historical pattern from V4 zkqes-cli (removed in 03a068e).
// Keep this file intentionally small — adding more stubs creates
// drift with the upstream package's actual API surface.

declare module 'snarkjs';
