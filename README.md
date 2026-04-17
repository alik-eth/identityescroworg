# identityescroworg — QKB + QIE

Qualified Key Binding (QKB) and Qualified Identity Escrow (QIE), built on eIDAS 2.0 (Regulation (EU) 2024/1183) primitives.

- Design spec: [`docs/superpowers/specs/2026-04-17-qkb-phase1-design.md`](docs/superpowers/specs/2026-04-17-qkb-phase1-design.md)
- Implementation plans: [`docs/superpowers/plans/`](docs/superpowers/plans/)
- Ceremony: [`docs/ceremony/`](docs/ceremony/)

## Phase 1 scope

QKB only. Escrow (QIE) is deferred to Phase 2.

## Packages

- `packages/lotl-flattener` — offline CLI; EU LOTL → Poseidon Merkle CA set (`trusted-cas.json`, `root.json`).
- `packages/circuits` — Circom circuits for `R_QKB`, Groth16 artifacts, `Verifier.sol`.
- `packages/contracts` — `QKBVerifier` library + `QKBRegistry` reference contract (Foundry).
- `packages/web` — TanStack Router static SPA; binding generator, in-browser prover, registry client.

## Prerequisites

- Node 20.11.x (`.nvmrc`)
- pnpm 9.1.x
- Foundry (forge/cast/anvil)
- circom 2.1.9

## Getting started

```bash
pnpm install
pnpm test       # run all package tests
pnpm lint
```

## License

TBD (MIT recommended for reference implementation, compatible with upstream `@zk-email/circuits` and snarkjs).
