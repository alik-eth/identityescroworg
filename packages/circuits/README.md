# @qkb/circuits

Circom 2 circuits implementing relation `R_QKB` for the QKB Phase 1 design.

See `docs/superpowers/specs/2026-04-17-qkb-phase1-design.md` and
`docs/superpowers/plans/2026-04-17-qkb-circuits.md`.

## Prerequisites

- Node 20.x (matches root `.node-version`)
- pnpm 9.x
- circom 2.1.9 (install via `scripts/install-circom.sh`)

## Tasks

```bash
pnpm install              # from repo root
pnpm --filter @qkb/circuits test
```

## Layout

- `circuits/` — Circom sources (sub-circuits under `primitives/`, `x509/`,
  `binding/`, `secp/`)
- `test/` — Mocha + circom_tester unit & integration tests
- `inputs/` — fixture builders (real `.p7s` → witness JSON)
- `ceremony/` — compile / setup / export scripts and transcript
- `build/` — generated artifacts (gitignored)
- `fixtures/` — committed test vectors
