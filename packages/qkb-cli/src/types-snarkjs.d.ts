// Ambient module declaration for snarkjs — the package ships no .d.ts
// and we only consume a narrow surface (groth16.fullProve, wtns.calculate).
// Typed at the callsite via `as unknown as { ... }` casts.
declare module 'snarkjs';
