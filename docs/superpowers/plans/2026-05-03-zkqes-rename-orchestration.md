# zkqes structural rename — orchestration plan

> **For agentic workers:** this plan drives a multi-worker rename train. Workers consume the surface-map analysis at `docs/superpowers/research/2026-05-03-zkqes-rename-analysis.md` (committed at `717abb0`) as the authoritative file/identifier inventory; this orchestration plan defines branching, sequencing, interface contracts, and merge order.

**Goal:** Land the full QKB/QIE/Identity Escrow → zkqes structural rename in one merge train, tagged `v0.6.0-zkqes-rename`, in roughly one calendar day of parallel worker dispatch.

**Architecture:** Single integration branch `chore/zkqes-rename-train` from main. Each worker takes a sub-branch, commits there, and lead merges them back into the train branch in interface-respecting order. Final merge from `chore/zkqes-rename-train` to `main` with `--no-ff` + tag.

**Tech stack:** Same as V5 — Circom 2.1.9, Foundry, TypeScript, pnpm workspaces, Vite, GitHub Actions, R2.

---

## 0. Locked decisions reference

See [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](../specs/2026-05-03-zkqes-rename-design.md) §1 for all 7 founder decisions and §3 for the 9 frozen consensus-critical bytes.

## 1. Branch structure

```
main
└── chore/zkqes-rename-train  (lead foundation pass committed here)
    ├── chore/zkqes-rename-flattener  (flattener-eng)
    ├── chore/zkqes-rename-circuits   (circuits-eng)
    ├── chore/zkqes-rename-contracts  (contracts-eng)
    └── chore/zkqes-rename-web        (web-eng)
```

Worker sub-branches all branched from `chore/zkqes-rename-train` AFTER the lead foundation pass commits. Workers merge back to `chore/zkqes-rename-train` in interface order (§3 below). Lead does CI + cookbook + docs sweep + QIE deletion on the train branch directly. Final `chore/zkqes-rename-train` merges to main as one `--no-ff` commit.

## 2. Interface contracts (frozen — workers MUST coordinate via lead before changing)

These are the cross-worker dependencies that cause merge conflicts if a worker deviates.

### 2.1 Package names — `@zkqes/*`

All workspace package `package.json` `"name"` fields:

| Old | New |
|---|---|
| `@qkb/sdk` | `@zkqes/sdk` |
| `@qkb/web` | `@zkqes/web` |
| `@qkb/circuits` | `@zkqes/circuits` |
| `@qkb/contracts` | `@zkqes/contracts` |
| `@qkb/contracts-sdk` | `@zkqes/contracts-sdk` |
| `@qkb/cli` | `@zkqes/cli` |
| `@qkb/lotl-flattener` | `@zkqes/lotl-flattener` |

`@qkb/qie-{core,agent,cli}` — **deleted**, not renamed (per spec §1.Q2).

### 2.2 SDK ABI exports

The web-eng track imports SDK ABI exports. The SDK rename must land first (or web-eng will break at typecheck). Concrete frozen names:

| Old SDK export | New SDK export |
|---|---|
| `qkbRegistryV5_1Abi` | `zkqesRegistryV5_1Abi` |
| `qkbRegistryV5_2Abi` | `zkqesRegistryV5_2Abi` |
| `identityEscrowNftAbi` | `zkqesCertificateAbi` |
| `QKB_DEPLOYMENTS` | `ZKQES_DEPLOYMENTS` |
| `QkbNetwork` (type) | `ZkqesNetwork` (type) |
| `QkbDeployment` (type) | `ZkqesDeployment` (type) |
| `QkbError` (class) | `ZkqesError` (class) |
| `CliProveError` | (unchanged — V5.4 CLI error class, not protocol-named) |
| `deploymentForChainId` | (unchanged — generic) |

### 2.3 Solidity contract names

The web-eng SDK ABI mirror filenames must match the new contract names. Frozen names:

| Old contract | New contract |
|---|---|
| `QKBRegistryV5_1.sol` | `ZkqesRegistryV5_1.sol` |
| `QKBRegistryV5_2.sol` | `ZkqesRegistryV5_2.sol` |
| `IdentityEscrowNFT.sol` | `ZkqesCertificate.sol` |
| `Groth16VerifierV5_1Stub.sol` | `Groth16VerifierV5_1Stub.sol` (verifier names — keep as-is, no QKB/QIE token) |
| `Groth16VerifierV5_2Stub.sol` | (same) |
| `QKBPresentationV5.circom` | `ZkqesPresentationV5.circom` |

### 2.4 Stub zkey filename family

| Old | New |
|---|---|
| `qkb-v5_2-stub.zkey` | `zkqes-v5_2-stub.zkey` |
| `qkb-v5_1-stub.zkey` | `zkqes-v5_1-stub.zkey` |
| `qkb-v5-stub.zkey` (legacy V5.0) | `zkqes-v5-stub.zkey` |

### 2.5 CLI binary

| Old | New |
|---|---|
| `qkb` (npm bin, brew formula) | `zkqes` |
| `qkb serve`, `qkb cache`, `qkb status`, `qkb version` | `zkqes serve`, etc. |

### 2.6 Frozen consensus-critical strings (DO NOT TOUCH)

See spec §3. Workers MUST NOT rename these. Each worker should grep their package for `qkb-rotate-auth-v1`, `qkb-personal-secret-v1`, `qkb-id-fingerprint-v1`, `qkb-walletsecret-v1`, `qkb-v5-walletsecret`, `qkb-binding-core/v1`, `qkb-policy-leaf/v1`, `QKB/2.0`, `QKB/1.0`, `qkb-default-ua` and add a `// frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3` comment next to each.

## 3. Dispatch sequence

### Phase 0 — lead foundation pass (~30 min, sequential)

Lead operates on `chore/zkqes-rename-train`. Touches root-level files only — does NOT enter package/ subdirs.

- [ ] **Step 0.1** Create train branch: `git checkout -b chore/zkqes-rename-train main`
- [ ] **Step 0.2** Cherry-pick commit `717abb0` if not already (analysis report — done; analysis is on main)
- [ ] **Step 0.3** Rewrite `BRAND.md` to reflect single-noun model. Drop the three-tier Q-table; document that the rename happened on 2026-05-03 reversing the 2026-05-03 morning lock; lock in the new noun + frozen-bytes invariant.
- [ ] **Step 0.4** Rewrite root `README.md` per single-noun model (drop "QKB", "Qualified Key Binding", "Identity Escrow"; lead with "zkqes — a zero-knowledge proof of a qualified electronic signature").
- [ ] **Step 0.5** Update root `package.json` `name` field (currently `identityescroworg`) to `zkqes`. Keep `private: true`.
- [ ] **Step 0.6** Sweep root `CLAUDE.md` for QKB/QIE/Identity Escrow references; rewrite the worker team table (drop `qie-eng` row), rewrite the worktrees section to reflect the new layout, drop QKB/QIE/Identity-Escrow references from prose, soften the "Phase 1 QKB / Phase 2 QIE" framing into single-track zkqes orchestration.
- [ ] **Step 0.7** Sweep root `Dockerfile.web` + `Caddyfile` + root `.env.example` for any QKB/QIE/identityescrow references.
- [ ] **Step 0.8** Update `package.json` script `"flatten": "pnpm --filter @qkb/lotl-flattener run cli"` → `"flatten": "pnpm --filter @zkqes/lotl-flattener run cli"`.
- [ ] **Step 0.9** Run `pnpm install` (will rewrite the lockfile to reflect the new top-level name; workers will further regenerate as their package.json files rename).
- [ ] **Step 0.10** Commit on train branch: `chore(rename): foundation pass — root files`. Do NOT push yet.

### Phase 1 — parallel worker dispatch (~3-4h wall, all workers in parallel)

All four workers branch from `chore/zkqes-rename-train` AFTER lead's Step 0.10 commit. Each works in their own worktree.

#### flattener-eng — `chore/zkqes-rename-flattener`

Smallest scope. Three files inside `packages/lotl-flattener/`.

- [ ] **F.1** `packages/lotl-flattener/package.json` `name`: `@qkb/lotl-flattener` → `@zkqes/lotl-flattener`
- [ ] **F.2** `packages/lotl-flattener/CLAUDE.md` — sweep QKB references (mostly comments + "Phase 1 QKB" framing), rewrite to single-noun
- [ ] **F.3** `packages/lotl-flattener/README.md` — same sweep
- [ ] **F.4** Verify: `pnpm -F @zkqes/lotl-flattener test && pnpm -F @zkqes/lotl-flattener build` from worktree
- [ ] **F.5** Commit + ping lead

#### circuits-eng — `chore/zkqes-rename-circuits`

Medium scope. Q3=freeze means **no circuit re-compile, no ceremony re-run**. Pure file + identifier rename.

- [ ] **C.1** `packages/circuits/package.json` `name`: `@qkb/circuits` → `@zkqes/circuits`
- [ ] **C.2** Rename Circom files per spec §2 + analysis report Section C:
  - `circuits/QKBPresentationV5.circom` → `circuits/ZkqesPresentationV5.circom` (and any V5_1, V5_2 variants)
  - All 8 template names referenced inside the .circom files (per analysis report)
- [ ] **C.3** Rename ceremony scripts: `ceremony/scripts/stub-v5*.sh` keep filename; rename `ZKEY` filename inside (`qkb-v5*-stub.zkey` → `zkqes-v5*-stub.zkey`). Also update `ceremony/v5_*/zkey.sha256` to reference new filename.
- [ ] **C.4** Rename pumped artifacts: `ceremony/v5_2/qkb-v5_2-stub.zkey` (gitignored) → ceremony script produces `zkqes-v5_2-stub.zkey` on next run; the COMMITTED proof-sample/public-sample/verification_key remain valid (same circuit, same vkey).
- [ ] **C.5** Sweep all `packages/circuits/{src,test,scripts}/` for `qkb` token in identifiers/comments. Add `// frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3` next to each occurrence of the 9 frozen tags.
- [ ] **C.6** `packages/circuits/CLAUDE.md` — full sweep + rewrite "Phase 1 QKB" framing to single-noun.
- [ ] **C.7** Verify: `pnpm -F @zkqes/circuits test` (slow, ~10 min). If failing on missing zkey filename, re-run `pnpm -F @zkqes/circuits ceremony:v5_2:stub` to regenerate with the new filename.
- [ ] **C.8** Commit per logical group (template renames / ceremony / docs) — 3-5 commits is fine. Ping lead.

#### contracts-eng — `chore/zkqes-rename-contracts`

Medium scope. ~24 Solidity file renames + every contract/library/interface decl + every deploy script + `IdentityEscrowNFT.sol` → `ZkqesCertificate.sol`.

- [ ] **K.1** `packages/contracts/package.json` `name`: `@qkb/contracts` → `@zkqes/contracts`
- [ ] **K.2** `packages/contracts-sdk/package.json` `name`: `@qkb/contracts-sdk` → `@zkqes/contracts-sdk`
- [ ] **K.3** Rename Solidity files per spec §2 + analysis report Section C:
  - `src/QKBRegistryV5.sol`, `src/QKBRegistryV5_1.sol`, `src/QKBRegistryV5_2.sol` → `Zkqes...`
  - `src/IdentityEscrowNFT.sol` → `src/ZkqesCertificate.sol` (Q1)
  - `src/CertificateRenderer.sol` — keep filename; sweep references inside
  - All 24 source/test/script Solidity files per analysis report
- [ ] **K.4** Update every `import` + every contract/library/interface decl to match new names.
- [ ] **K.5** Update deploy scripts (`script/Deploy*.s.sol`) — function names, contract type references.
- [ ] **K.6** Update `packages/contracts/MIGRATION.md` if it references QKB.
- [ ] **K.7** `packages/contracts/CLAUDE.md` — sweep + rewrite.
- [ ] **K.8** Sweep all `packages/contracts/{src,test,script}/` for the 9 frozen tags. Add freeze-comment next to each.
- [ ] **K.9** Regenerate `snapshots/gas-snapshot.txt` if the file format includes contract names (forge gas-report does — it'll rewrite on next test run).
- [ ] **K.10** Verify: `forge test -vv` from worktree (lead-side broken per #65; worker-side is the canonical verification).
- [ ] **K.11** Commit per logical group (contracts / verifier / NFT rename / deploy scripts / docs). Ping lead.

#### web-eng — `chore/zkqes-rename-web`

Largest scope. SDK ABI mirrors + i18n + components + routes + Dockerfile + everything else under `packages/web/` + `packages/sdk/` + `packages/qkb-cli/` (renaming the folder itself).

- [ ] **W.1** `packages/sdk/package.json` `name`: `@qkb/sdk` → `@zkqes/sdk`
- [ ] **W.2** `packages/web/package.json` `name`: `@qkb/web` → `@zkqes/web`. Drop `@qkb/qie-core` + `@qkb/qie-agent` deps (Q2 deletion).
- [ ] **W.3** `packages/qkb-cli/package.json` `name`: `@qkb/cli` → `@zkqes/cli`. `bin` entry: `qkb` → `zkqes`. Rename folder: `git mv packages/qkb-cli packages/zkqes-cli`.
- [ ] **W.4** Rename SDK ABI mirrors (`packages/sdk/src/abi/QKBRegistryV5*.ts` → `ZkqesRegistryV5*.ts`; `IdentityEscrowNFT.ts` → `ZkqesCertificate.ts`).
- [ ] **W.5** Rename SDK exports per spec §2 + interface contract §2.2 (every `qkbRegistry*Abi`, `identityEscrowNftAbi`, `QKB_DEPLOYMENTS`, `QkbNetwork`, etc.).
- [ ] **W.6** Sweep `packages/web/src/` for every QKB/QIE/Identity-Escrow reference. Components: `LandingHero.tsx`, `CliBanner.tsx`, `MintButton.tsx`, `MintNftStep.tsx`, `RotateWalletFlow.tsx`, `Step2GenerateBinding.tsx`, `Step4ProveAndRegister.tsx`, `FlyLauncherForm.tsx`, `DocumentFooter.tsx`. Routes: `index.tsx`, `integrations.tsx`, `ua/{cli,mint,submit}.tsx`, `ceremony/{contribute,status,verify}.tsx`. CLI presence: `useCliPresence.ts`, `cliFallbackProver.ts`. The `qkb` ↔ `zkqes` origin pin update in `src/server/origin-pin.ts` (already had `app.zkqes.org` from #59 — confirm correct). Routes' filenames stay (ua/* per CLAUDE.md V5 routes locked).
- [ ] **W.7** `packages/web/src/i18n/en.json` + `packages/web/src/i18n/uk.json` — sweep every value mentioning QKB / Qualified Key Binding / Identity Escrow / QIE. Translator-friendly: keep keys identical, change values to single-noun. (For UK: lowercase `zkqes` works in Cyrillic context as a Latin tech-noun.)
- [ ] **W.8** `packages/web/index.html` + `packages/web/public/404.html` — sweep meta tags, OG tags, title.
- [ ] **W.9** `packages/web/Dockerfile` + `packages/web/fly.toml` — sweep references.
- [ ] **W.10** `packages/web/PRIVACY.md` — sweep.
- [ ] **W.11** `packages/web/CLAUDE.md` — sweep + rewrite, but PRESERVE V5.21 (VITE_TARGET) and V5.22 (root-domain SPA fallback) invariants intact.
- [ ] **W.12** Sweep all `packages/{sdk,web,zkqes-cli}/src/` for the 9 frozen tags. Add freeze-comment next to each.
- [ ] **W.13** Verify: `pnpm -F @zkqes/sdk test && pnpm -F @zkqes/sdk build && pnpm -F @zkqes/web typecheck && VITE_TARGET=landing pnpm -F @zkqes/web build`
- [ ] **W.14** Commit per logical group (sdk / web src / web i18n / cli folder rename / dockerfile / docs). Ping lead.

### Phase 2 — lead merges workers back to train, in interface order (~30 min)

Order matters — SDK rename must precede web/contracts consumers:

- [ ] **M.1** Merge `chore/zkqes-rename-flattener` → `chore/zkqes-rename-train` (independent, can land first)
- [ ] **M.2** Merge `chore/zkqes-rename-circuits` → `chore/zkqes-rename-train`
- [ ] **M.3** Merge `chore/zkqes-rename-contracts` → `chore/zkqes-rename-train` (web-eng's SDK ABI mirrors depend on contracts naming being final)
- [ ] **M.4** Merge `chore/zkqes-rename-web` → `chore/zkqes-rename-train` (last — depends on contracts + sdk)
- [ ] **M.5** Smoke check from train branch: `pnpm install --frozen-lockfile=false && pnpm -r typecheck && pnpm -r build`. Expect lockfile changes to land in this commit.
- [ ] **M.6** Lockfile commit: `chore(rename): regenerate pnpm-lock.yaml`

### Phase 3 — lead CI + cookbook + ceremony-coord sweep (~1h)

On `chore/zkqes-rename-train` directly.

- [ ] **L.1** `.github/workflows/pages.yml` — sweep `@qkb/sdk` references → `@zkqes/sdk`. CNAME write step `zkqes.org` already correct.
- [ ] **L.2** `.github/workflows/pages-docs.yml` — sweep.
- [ ] **L.3** `.github/workflows/release-cli.yml` — sweep `@qkb/cli` → `@zkqes/cli`, brew formula references, GHCR image tag.
- [ ] **L.4** `scripts/dev-chain.sh` — sweep contract name references.
- [ ] **L.5** `scripts/sync-deployments.mjs` — sweep field names (`identityEscrowNftAbi` → `zkqesCertificateAbi`, etc.).
- [ ] **L.6** `scripts/ceremony-coord/.env.example` — `prove-identityescrow-org` bucket reference: ADD a comment noting Q5 decision (new `prove-zkqes-org` for V5+, old as historical mirror); leave the value to founder to flip.
- [ ] **L.7** `scripts/ceremony-coord/cookbooks/fly/{Dockerfile,launcher.sh,entrypoint.sh,README.md}` — sweep QKB references in docs/comments. Note: ceremony cookbook GHCR image references (`identityescroworg/qkb-ceremony` per spec §1.Q6 → `alik-eth/zkqes-ceremony`) — update tag references in launcher + README. **Do NOT update the digest pin** (still pointing at old image until founder rebuilds the image under new name).
- [ ] **L.8** Verify: `act` or eyeball-only on workflows.

### Phase 4 — lead docs sweep (~1h)

On `chore/zkqes-rename-train` directly.

- [ ] **D.1** Sweep `docs/superpowers/specs/2026-04-29-*.md`, `2026-04-30-*.md`, `2026-05-01-*.md`, `2026-05-03-*.md` (excluding the rename spec + analysis report which are intentionally about the rename). Update QKB/QIE/Identity Escrow language; insert a one-line "renamed 2026-05-03 — see specs/2026-05-03-zkqes-rename-design.md" header.
- [ ] **D.2** Sweep `docs/superpowers/plans/{same date prefixes}`.
- [ ] **D.3** Sweep `docs/marketing/2026-05-03-*` — these will need rewriting under new noun OR delete if obsolete (founder review on each).
- [ ] **D.4** Sweep `docs/.vitepress/config.mts` — title, description, social URLs, GitHub repo URL.
- [ ] **D.5** Rename `docs/cli-release-homebrew/Formula/qkb.rb` → `Formula/zkqes.rb`. Update `bin.install` and `tap` references.
- [ ] **D.6** Sweep `docs/cli-release.md`, `docs/integrations.md`, `docs/index.md`.
- [ ] **D.7** Sweep `docs/release-notes/*.md` — update prose references but DO NOT rewrite v0.5.x release notes' historical content (those reference the V5.x state at time of release; one-line "renamed in v0.6.0" header is enough).
- [ ] **D.8** Older specs/plans (pre-2026-04-29) get a header note only — don't rewrite content.

### Phase 5 — QIE deletion (~30 min)

On `chore/zkqes-rename-train` directly. Q2=delete locked.

- [ ] **Q.1** `git rm -r packages/qie-core/ packages/qie-agent/ packages/qie-cli/`
- [ ] **Q.2** `git rm -r deploy/mock-qtsps/`
- [ ] **Q.3** `git rm -r docs/qie/ fixtures/qie/`
- [ ] **Q.4** Drop `qie-eng` row from root `CLAUDE.md` worker team table.
- [ ] **Q.5** Confirm `pnpm-workspace.yaml` glob (`packages/*`) auto-resolves the deletion.
- [ ] **Q.6** Drop `@qkb/qie-*` build steps from `Dockerfile.web` (root) and `packages/web/Dockerfile` if still present.
- [ ] **Q.7** `pnpm install` — regenerate lockfile.
- [ ] **Q.8** Verify: full repo `pnpm test` + `forge test` + `pnpm -r build`.
- [ ] **Q.9** Commit: `chore(rename): delete QIE Phase-2 cluster (parked, no production use)`.

### Phase 6 — tag + release (~15 min)

- [ ] **T.1** Update `CHANGELOG.md` with rename entry.
- [ ] **T.2** Final commit on `chore/zkqes-rename-train`: `chore(rename): CHANGELOG entry`.
- [ ] **T.3** Merge `chore/zkqes-rename-train` → main with `--no-ff`, summary commit referencing spec/plan/analysis SHAs.
- [ ] **T.4** Tag `v0.6.0-zkqes-rename` annotated on the merge commit.
- [ ] **T.5** Push main + tag to origin.
- [ ] **T.6** Verify GH Pages workflow re-deploys cleanly under new package names.
- [ ] **T.7** Notify all workers of merge. Stay parked on their respective sub-branches; future feature work uses new noun from this point.

## 4. Artifact pumping (none required)

This is a rename, not a feature train. No fixture pumps between worktrees.

The one exception: web-eng's SDK ABI mirror filenames depend on contracts-eng's contract names. The interface contract (§2.3) freezes the names; both workers consume that frozen name independently. No live pump needed.

## 5. Rollback

If any worker hits a hard blocker (e.g., circuits-eng discovers a frozen tag we missed and renaming would break the circuit), lead aborts the train:

```bash
git checkout main
git branch -D chore/zkqes-rename-train chore/zkqes-rename-{flattener,circuits,contracts,web}
git worktree remove /data/Develop/qkb-wt-v5/zkqes-rename-{flattener,circuits,contracts,web}
```

Pre-existing artifacts on main (`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`, the orchestration plan, the analysis report) stay as research record. We can revisit the rename later or commit a smaller-scope fix.

## 6. Post-merge follow-ups (not part of the rename)

- Update `feedback_*.md` and `project_*.md` auto-memory entries to refer to new package names (lead-side, after merge).
- Update worker CLAUDE.md notes that mention the old worker team layout.
- Refresh marketer launch arc drafts (#58) using the new noun.
- Resume Phase B ceremony recruitment (#8) with copy referencing zkqes throughout.
