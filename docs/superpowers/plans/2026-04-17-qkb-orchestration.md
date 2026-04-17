# QKB Phase 1 — Orchestration

Date: 2026-04-17
Owner: team-lead (this session)
Workers: four long-lived teammates, one per subsystem
Spec: `docs/superpowers/specs/2026-04-17-qkb-phase1-design.md`

## Team topology

One team, four long-lived worker agents plus the team lead. **Workers are reused across all tasks in their subsystem — never killed, never respawned.** The lead talks to them via `SendMessage`; they pull tasks from the shared team task list.

| Agent name      | subagent_type      | Owns                                                 | Plan file                                   |
|-----------------|--------------------|------------------------------------------------------|---------------------------------------------|
| `flattener-eng` | `general-purpose`  | `packages/lotl-flattener`                            | `2026-04-17-qkb-lotl-flattener.md`          |
| `circuits-eng`  | `general-purpose`  | `packages/circuits`                                  | `2026-04-17-qkb-circuits.md`                |
| `contracts-eng` | `general-purpose`  | `packages/contracts`                                 | `2026-04-17-qkb-contracts.md`               |
| `web-eng`       | `general-purpose`  | `packages/web`                                       | `2026-04-17-qkb-web.md`                     |

Team name: `qkb-phase1`.

## Responsibilities split

**Team lead (me):**
1. Scaffold the monorepo (see §Scaffold) before any worker dispatches.
2. Populate shared fixtures under `/fixtures/` (real QES test certificates; pinned LOTL XML snapshot).
3. Create the team, spawn the four workers with their plan path in the initial prompt.
4. Coordinate cross-package boundaries (see §Interface contracts).
5. Review each completed task — run the worker's declared verification commands myself, inspect the diff, and only then greenlight the next task.
6. Produce the integrated proof fixture (real `.p7s` → witness → `proof.json`) that `contracts-eng` consumes.
7. Merge workers' work to `main` (each worker commits on a feature branch; lead rebases + merges).
8. Maintain a single root `CHANGELOG.md` of merged milestones.
9. Never terminate a worker; reuse them for follow-up work in their subsystem (Phase 1.1, Phase 2).

**Workers (each):**
1. Execute their assigned plan one task at a time.
2. Commit on every task (branch `feat/<package>`).
3. Between tasks, go idle. Team lead wakes them with the next task ID via `SendMessage`.
4. When a task cannot proceed due to an upstream dependency, mark the task blocked and message the lead.
5. Never modify files outside their package except to add fixtures under `/fixtures/` (only with lead approval).

## Dispatch order

All four workers are spawned **simultaneously** in a single message once the scaffold is in place. They proceed in parallel. Dependencies are enforced by task-level blocking, not by staggered spawning:

- `flattener-eng` → independent; starts immediately.
- `circuits-eng` → Tasks 1–6 are independent; Task 7 (main circuit integration) blocks on the team lead providing a fixture Merkle path derived from `flattener-eng` output (lead re-derives from the pinned snapshot to unblock).
- `contracts-eng` → Tasks 1–9 are independent; Task 10 (end-to-end registry test) blocks on `circuits-eng` producing a real `Verifier.sol` + proof fixture, delivered by the lead.
- `web-eng` → Tasks 1–7 are independent; Tasks 8–12 (integration, full flows) block progressively on the outputs of the other three workers.

## Interface contracts (frozen early)

Every worker reads this section before starting. Changes here require team-lead sign-off.

### 1. LOTL flattener output

Written to `packages/lotl-flattener/dist/output/`:

**`trusted-cas.json`**:
```json
{
  "version": 1,
  "lotlSnapshot": "YYYY-MM-DDTHH:MM:SSZ",
  "treeDepth": 16,
  "cas": [
    {
      "merkleIndex": 0,
      "certDerB64": "...",
      "issuerDN": "CN=...",
      "validFrom": 1700000000,
      "validTo": 1900000000,
      "poseidonHash": "0x..."
    }
  ]
}
```

**`root.json`**:
```json
{
  "rTL": "0x...",
  "treeDepth": 16,
  "builtAt": "YYYY-MM-DDTHH:MM:SSZ",
  "lotlVersion": "..."
}
```

### 2. Circuit public signals (order fixed)

13 field elements in this order, consumed identically by web (witness packer) and contracts (verifier wrapper):

```
[0..3]  pkX limbs (4 × uint64 packed into field elements, little-endian)
[4..7]  pkY limbs
[8]     ctxHash     (Poseidon of ctx bytes, or 0 if absent)
[9]     rTL         (Poseidon Merkle root from root.json)
[10]    declHash    (SHA-256 of declaration text, either EN or UK)
[11]    timestamp   (unix seconds, unsigned)
[12]    reserved    (= 0 in Phase 1; tag for future scheme extension)
```

### 3. Solidity `QKBVerifier.Inputs` layout

Exactly matches the above in solidity-equivalent types. See spec §6.1 (already frozen).

### 4. QKB artifact JSON bundle

Produced by web, verifiable offline by anyone:

```json
{
  "version": "QKB/1.0",
  "binding": { "bcanonB64": "...", "bcanonHash": "0x..." },
  "qes": { "cadesB64": "...", "leafCertDerB64": "...", "intCertDerB64": "..." },
  "proof": { "a": [...], "b": [[...], [...]], "c": [...] },
  "publicSignals": ["0x...", "..."],
  "circuitVersion": "qkb-presentation-v1",
  "trustedListRoot": "0x...",
  "builtAt": "YYYY-MM-DDTHH:MM:SSZ"
}
```

### 5. Error codes (shared taxonomy)

Web enforces, contracts mirror where relevant:
`binding.size`, `binding.field`, `binding.jcs`, `cades.parse`, `qes.sigInvalid`, `qes.digestMismatch`, `qes.certExpired`, `qes.unknownCA`, `qes.wrongAlgorithm`, `witness.offsetNotFound`, `witness.fieldTooLong`, `prover.wasmOOM`, `prover.cancelled`, `bundle.malformed`, `registry.rootMismatch`, `registry.alreadyBound`, `registry.ageExceeded`.

## Scaffold (team lead does this first)

Monorepo layout:

```
identityescroworg/
├── .editorconfig
├── .gitignore
├── .node-version              # 20.x
├── .nvmrc
├── biome.json                 # formatter + linter for TS
├── package.json               # pnpm workspaces root
├── pnpm-workspace.yaml
├── tsconfig.base.json
├── foundry.toml               # root Foundry config (referenced by packages/contracts)
├── .github/workflows/
│   ├── ci.yml                 # matrix: per package lint + test + build
│   └── reproducibility.yml    # nightly: rebuild circuit + SPA, hash-compare
├── docs/
│   ├── superpowers/{specs,plans}/
│   └── ceremony/              # trusted setup transcript
├── fixtures/
│   ├── qes-certs/             # sample real QES test certs (KICRF + 1 EU MS)
│   │   ├── ua-diia/leaf.pem, int.pem, root.pem, signed.p7s, binding.qkb.json
│   │   └── ee-sk/...
│   ├── lotl/
│   │   └── 2026-04-17-lotl.xml         # pinned snapshot
│   └── README.md
└── packages/
    ├── lotl-flattener/
    ├── circuits/
    ├── contracts/
    └── web/
```

Scaffold tasks (executed by lead, **not** by workers):

- [ ] `pnpm init` in root; add workspaces.
- [ ] `pnpm-workspace.yaml` listing `packages/*`.
- [ ] `tsconfig.base.json` with `strict: true`, `target: ES2022`, `module: ESNext`, `moduleResolution: Bundler`.
- [ ] `biome.json` enforcing 2-space indent + single-quote + trailing-comma-all.
- [ ] `.gitignore` covering `node_modules`, `dist`, `.turbo`, `out`, `cache`, `*.zkey`, `*.r1cs`, `*.wasm`.
- [ ] `foundry.toml` with `src = "packages/contracts/src"`, `out = "packages/contracts/out"`, `libs = ["packages/contracts/lib"]`.
- [ ] `.github/workflows/ci.yml` with jobs: `lint`, `test-flattener`, `test-circuits`, `test-contracts`, `test-web`. Each uses the package's own `pnpm run test`.
- [ ] Each package stub: `package.json` with `name: @qkb/<pkg>`, `scripts: { test, build, lint }`, empty `src/` + `tests/`.
- [ ] Populate `fixtures/qes-certs/` with at least one real test-QES signed sample before `circuits-eng` hits Task 7.
- [ ] Commit scaffold as a single commit `chore: scaffold monorepo` before any worker dispatch.

## Verification protocol (per completed task)

For each task a worker marks completed, the lead:

1. `git fetch && git checkout feat/<package>`
2. Run the task's declared verification commands verbatim.
3. Diff-review the patch (`git diff HEAD^`).
4. Check commit message matches the plan's commit text.
5. Post-condition checklist:
   - Tests added/updated match the task's test spec.
   - No files touched outside the owning package (except whitelisted fixtures).
   - No TODOs, commented-out code, or disabled tests.
6. On pass: `SendMessage` next task ID to the worker.
7. On fail: `SendMessage` with targeted feedback, reference to exact failing check, and expected fix. Worker iterates; lead re-verifies.

## Merge protocol

- Each worker lives on `feat/<package>` (e.g., `feat/circuits`).
- After each worker finishes their plan, lead rebases `feat/<package>` onto current `main` and does a fast-forward merge (or PR + squash if we've introduced GitHub).
- Cross-cutting changes (e.g., updating `Verifier.sol` in `contracts/` because `circuits/` re-ran ceremony) are done by the lead, not the workers.

## Milestones (team-level)

- **M1** — Scaffold merged, workers dispatched. (Lead)
- **M2** — `flattener-eng` ships `trusted-cas.json` + `root.json` from pinned snapshot.
- **M3** — `circuits-eng` ships green sub-circuit tests (no main yet).
- **M4** — `contracts-eng` ships `QKBVerifier` + `QKBRegistry` unit-tested against a stub verifier.
- **M5** — `circuits-eng` ships the main circuit + real ptau + `Verifier.sol`. Lead delivers real proof fixture.
- **M6** — `contracts-eng` integrates real `Verifier.sol` + passes end-to-end registry test.
- **M7** — `web-eng` ships Playwright happy path with mocked prover.
- **M8** — `web-eng` + lead: full real-prover integration run in-browser.
- **M9** — Sepolia deployment + public SPA build.

Workers stay alive after M9 for Phase 1.1 polish and Phase 2 scoping.

## Communication etiquette

- Short plain-text messages. No JSON status packets.
- Workers do not broadcast to `*`.
- Lead broadcasts only for interface-contract changes affecting multiple workers.
- Every task-completion message names the task ID and the commit SHA.
