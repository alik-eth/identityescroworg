# @qkb/sdk

Qualified Key Binding (QKB) SDK — verify QES, build proofs, register on-chain.

> **Status:** v0.1.0-dev. Scaffold only — modules are being extracted from
> `packages/web/src/lib` incrementally. The public API is empty until
> extraction lands.

## Roadmap

- `binding/` — QKB/2.0 schema, JCS canonicalization, Poseidon policy-leaf digest
- `cert/` — CAdES-BES detached signature parser + off-circuit QES verify
- `dob/` — pluggable date-of-birth extractors (Diia UA, RFC 3739)
- `policy/` — depth-16 Poseidon Merkle policy tree + inclusion proofs
- `witness/` — 16-signal leaf witness builder
- `registry/` — V4 register-call calldata + error selectors
- `prover/` — `IProver` interface + Mock/Snarkjs/Rapidsnark implementations
- `artifacts/` — SHA-verified ceremony URL fetcher
- `country/` — country routing config (UA today, EE planned)
- `errors/` — `QkbError` taxonomy

## Entry points

- `@qkb/sdk` — pure types + utilities (works in any runtime)
- `@qkb/sdk/browser` — adds `crypto.subtle` + `Worker`-based prover
- `@qkb/sdk/node` — adds Node `crypto` + `worker_threads`-based prover

## License

GPL-3.0-or-later.
