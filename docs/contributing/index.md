# Contributing

How V5 amendments get built. The pattern repeats across every phase: spec → orchestration plan → per-worker plans → dispatch.

## Worktree layout

The team operates in dedicated worktrees per worker, never sharing CWD. Concretely:

- `flattener-eng` — `packages/lotl-flattener`
- `circuits-eng` — `packages/circuits`
- `contracts-eng` — `packages/contracts`
- `web-eng` — `packages/web` + `packages/sdk`
- `qie-eng` — `packages/qie-{core,agent,cli}` (Phase 2)

Lead operates in the main checkout. See `CLAUDE.md` at the repo root for the full orchestration playbook.

## Plan-driven execution

Every phase has:

- One **design spec** at `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md` (brainstorming output).
- One **orchestration plan** at `docs/superpowers/plans/YYYY-MM-DD-<topic>-orchestration.md` — interface contracts, dispatch order, merge strategy, lead-side scaffold steps.
- One **per-worker plan** at `docs/superpowers/plans/YYYY-MM-DD-<topic>-<worker>.md` — bite-sized TDD tasks, exact file paths, complete code.

Interface contracts in the orchestration plan are **frozen early**. Changes require explicit lead sign-off and a cross-worker broadcast.

## Recent orchestration plans

The plans tree is comprehensive but not curated; consult these as patterns when shipping a new amendment:

- V5 architecture (Phase 1 baseline)
- V5.1 wallet-bound nullifier amendment
- V5.2 keccak-on-chain amendment
- V5.3 OID-anchor amendment (in flight at time of writing)
- V5.4 QKB CLI-server (qkb serve)

Each amendment ships in 3-7 days end-to-end across spec → plan → dispatch → ceremony. The cadence is preserved by codex VERDICT in every commit footer + per-task verification gates.

## Coding standards

See `packages/<package>/CLAUDE.md` for package-specific invariants. The web package's CLAUDE.md (V5.16-V5.21 invariants) captures most cross-cutting rules.

Footer policy:

```
VERDICT: PASS (manual review; SKIP_CODEX_REVIEW=1 per worker
guidance — codex daemon corrupts git index).
```

every commit. No exceptions.

## Where to start

If you want to ship a single contained change: pick a [pending task](https://github.com/alik-eth/identityescroworg/issues) marked `good first contribution` and follow the per-worker dispatch pattern.

If you want to ship an amendment: read [V5 architecture](/specs/v5-architecture) end-to-end, then propose a spec via PR. Lead reviews, founder approves, dispatch follows.
