# zkqes structural rename — design spec

**Date:** 2026-05-03
**Status:** locked, dispatch-ready
**Surface map:** [`docs/superpowers/research/2026-05-03-zkqes-rename-analysis.md`](../research/2026-05-03-zkqes-rename-analysis.md) (committed at `717abb0`)
**Orchestration:** [`docs/superpowers/plans/2026-05-03-zkqes-rename-orchestration.md`](../plans/2026-05-03-zkqes-rename-orchestration.md)

## 0. Goal (one sentence)

Collapse the QKB / QIE / Identity Escrow three-tier brand hierarchy locked in `BRAND.md` (2026-05-03) into a single noun, **`zkqes`**, matching `zkqes.org` and `zk-QES` descriptor — with zero shipped-artifact migration cost (nothing on npm, nothing on Sepolia, no ceremony rounds run, all 5 V5.x tags preserved as immutable historical record).

## 1. Locked decisions (founder confirmed 2026-05-03)

| Q | Decision | Implication |
|---|---|---|
| **Q1** | `IdentityEscrowNFT.sol` → **`ZkqesCertificate.sol`** | Names what it actually is — on-chain attestation of the QES binding. Resolves `identityEscrowNftAbi` SDK export, `scripts/sync-deployments.mjs` field name, test files, i18n strings. |
| **Q2** | **Delete entirely** the QIE Phase-2 cluster | `packages/qie-{core,agent,cli}/`, `deploy/mock-qtsps/`, `docs/qie/`, `fixtures/qie/`, `qie-eng` row from CLAUDE.md. Verified: zero `web/src` imports of `@qkb/qie-*`. Drop `@qkb/qie-{core,agent}` deps from `packages/web/package.json`. Restore from git history if Phase 2 ever resumes. |
| **Q3** | **Freeze 9 consensus-critical domain-separation tags; rename 4 cosmetic** | See §3 below for the freeze/rename split. Reduces dispatch from ~2 days to ~1 day; preserves circuit + ceremony validity; documented as a ProtocolBytes invariant in CLAUDE.md so future amendments don't accidentally rename them. |
| **Q4** | **Keep schema `$id` URLs as-is**; 301-redirect at host level once `identityescrow.org` aliases to `zkqes.org` | JSON-Schema validators may dereference these URLs. Rewriting is unsafe (validator caches) and unnecessary (redirect handles it). |
| **Q5** | **New `prove-zkqes-org` R2 bucket for V5+; freeze old `prove-identityescrow-org` as historical mirror** | R2 buckets aren't renameable in place. V5 ceremony hasn't started, so creating fresh is cheap. V3/V4 historical artifacts at the old bucket remain reachable forever. |
| **Q6** | Org placeholders canonicalize to `alik-eth/zkqes` family | Source repo: `alik-eth/zkqes` (already renamed today). GHCR: `alik-eth/zkqes-ceremony`. Homebrew tap: `alik-eth/homebrew-zkqes`. npm scope: `@zkqes/*` (founder claims pre-publish). |
| **Q7** | CLI binary: **`zkqes serve`** | Affects Homebrew formula `bin.install`, npm `bin` entry, all i18n + docs + `CliBanner.tsx` + `useCliPresence.ts` (origin-pin probe must match new binary identity). |

## 2. Naming conventions

| Surface | Old | New |
|---|---|---|
| Protocol noun in code | `QKB` / `qkb` | **`Zkqes`** / **`zkqes`** |
| Workspace package scope | `@qkb/*` | **`@zkqes/*`** |
| CLI binary | `qkb` | **`zkqes`** |
| Solidity contracts | `QKBRegistryV5_2`, `QKBPresentationV5*` | **`ZkqesRegistryV5_2`**, **`ZkqesPresentationV5*`** |
| Circom templates | `QKBPresentationV5*`, `QKBLeaf*` | **`ZkqesPresentationV5*`**, **`ZkqesLeaf*`** |
| Stub zkey filenames | `qkb-v5_2-stub.zkey` family | **`zkqes-v5_2-stub.zkey`** family |
| ABI mirror filenames | `QKBRegistryV5_2.ts` etc. | **`ZkqesRegistryV5_2.ts`** etc. |
| TS exports | `QKB_DEPLOYMENTS`, `QkbNetwork`, `QkbDeployment`, `QkbError`, `qkbRegistryV5_2Abi`, `identityEscrowNftAbi`, etc. | **`ZKQES_DEPLOYMENTS`**, **`ZkqesNetwork`**, **`ZkqesDeployment`**, **`ZkqesError`**, **`zkqesRegistryV5_2Abi`**, **`zkqesCertificateAbi`** |
| GitHub repo | `alik-eth/identityescroworg` (renamed today to `alik-eth/zkqes`) | **`alik-eth/zkqes`** (in-repo references) |
| GHCR image | `identityescroworg/qkb-ceremony` | **`alik-eth/zkqes-ceremony`** |
| Homebrew tap | `qkb-eth/homebrew-qkb` | **`alik-eth/homebrew-zkqes`** |
| Browser CacheStorage namespace | `qkb-circuit-artifacts-v1` | **`zkqes-circuit-artifacts-v1`** |
| IPC schemas | `qkb-witness/v1`, `qkb-tsl-update-witness/v1`, `qkb-helper@<semver>` | **`zkqes-witness/v1`**, **`zkqes-tsl-update-witness/v1`**, **`zkqes-helper@<semver>`** |
| Public-facing copy | "QKB", "Qualified Key Binding", "Identity Escrow", "QIE", "Qualified Identity Escrow" | **"zkqes"** (lowercase noun, no expansion). Two-second descriptor when needed: "a zero-knowledge proof of a qualified electronic signature." |

## 3. Frozen consensus-critical bytes (DO NOT RENAME)

These string literals are hashed (keccak256 / SHA-256 / Poseidon) into circuit-public, contract-stored, or off-chain deterministically-derived values. Renaming any of them invalidates the V5.2/V5.3 circuit + the in-flight Phase B ceremony + every existing fixture. They were chosen at design time, never published in a way users can see, and remain protocol-internal.

**Frozen tags (keep `qkb-` prefix forever as protocol bytes):**

| Tag | Used in |
|---|---|
| `"qkb-rotate-auth-v1"` | `keccak256(tag ‖ chainId ‖ registry ‖ fingerprint ‖ newWallet)` for rotation-auth signature gate |
| `"qkb-personal-secret-v1"` | EOA `personal_sign(tag + …)` IKM for `walletSecret` derivation |
| `"qkb-id-fingerprint-v1"` | `FINGERPRINT_DOMAIN` field-element baked into V5 r1cs |
| `"qkb-walletsecret-v1"` (SCW) | SHA-256 salt for SCW-path walletSecret |
| `"qkb-v5-walletsecret"` (HKDF) | HKDF salt |
| `"qkb-binding-core/v1"` | Schema discriminator embedded in JCS-canonicalized binding |
| `"qkb-policy-leaf/v1"` | Same |
| `"QKB/2.0"`, `"QKB/1.0"` | `version` field in binding JSON |
| `"qkb-default-ua"` | UA policyId in `fixtures/declarations/ua/policy-v1.json` |

**Same posture for V4 schema discriminators** (`"qkb-v4-policy-root/v1"`, `"qkb-v4-trust-root/v1"`, `"qkb-v4-ua"`, `"qkb-v4-ceremony-urls/v1"`) — these anchor V4 historical fixtures and frozen Merkle roots.

**Where this gets enforced:** new CLAUDE.md invariant at the repo root (V6.1) — "ProtocolBytes constants in code are protocol-internal byte strings, not branding. They predate the rename and stay frozen. Comments next to each constant note: `// frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3`."

**What gets renamed (cosmetic, no protocol impact):**
- `qkb-circuit-artifacts-v1` → `zkqes-circuit-artifacts-v1` (browser cache key)
- `qkb-witness/v1` → `zkqes-witness/v1` (IPC schema)
- `qkb-tsl-update-witness/v1` → `zkqes-tsl-update-witness/v1` (IPC schema)
- `qkb-v5*-stub.zkey` filename family → `zkqes-v5*-stub.zkey`

## 4. Already-immutable surfaces (DO NOT REWRITE)

- 5 V5.x tags (`v0.5.1-pre-ceremony` through `v0.5.5-pre-ceremony`) and `v0.5.4-cli` — annotation text references QKB extensively. Tags are immutable. New tag (`v0.6.0-zkqes-rename`) carries new noun.
- Prior commit messages — git history is append-only; commit-message rewrites are force-pushes.
- Schema `$id` URLs — see Q4.
- V3/V4 R2 keys at `prove.identityescrow.org/{ecdsa-chain,age,ua-leaf-v4,ua-leaf-v4-v2}/` — see Q5.
- The 9 frozen consensus-critical tags above — see §3.

## 5. Worker assignment (4 parallel + 2 lead passes)

See orchestration plan for the dispatch sequence + branch structure. High-level scope per worker:

| Worker | Scope | Files (approx) |
|---|---|---|
| **flattener-eng** | `packages/lotl-flattener/` package.json + CLAUDE.md + README; nothing else of consequence | 3 files |
| **circuits-eng** | 8 Circom file/template renames + every reference + `stub-v5*.sh` filename family + `packages/circuits/CLAUDE.md` + circuit benchmarks. **Q3=freeze means no protocol re-compile** — only file/identifier renames. | ~25 files |
| **contracts-eng** | 24 Solidity file renames + every contract/library/interface/import decl + every deploy script + `IdentityEscrowNFT.sol` → `ZkqesCertificate.sol` (Q1) + `MIGRATION.md` + CLAUDE.md + gas-snapshot regenerate (cosmetic file-name only) | ~40 files |
| **web-eng** | 4 SDK ABI mirror renames + every `qkbRegistry*Abi` import sweep + `LandingHero.tsx` + i18n en.json + i18n uk.json + 6 routes + every `IdentityEscrowNFT` reference (Q1) + Dockerfile + fly.toml + `index.html` + `404.html` content (not the V5.22 `cp` step) + `PRIVACY.md` + CLAUDE.md | ~60 files |
| **lead foundation pass** | root `package.json`, `pnpm-workspace.yaml`, root `CLAUDE.md`, `BRAND.md` (rewritten), root `README.md` (re-sweep), `Dockerfile.web`, `Caddyfile`, root `.env.example`, `package.json` `flatten` script ref. | ~10 files |
| **lead CI + cookbook pass** | `.github/workflows/{pages,pages-docs,release-cli}.yml`, `scripts/ceremony-coord/{*,cookbooks/fly/*}`, `scripts/{dev-chain.sh,sync-deployments.mjs}`, GHCR repo creation outside repo. | ~30 files |
| **lead docs sweep** | `docs/superpowers/specs/{2026-04-29,2026-04-30,2026-05-01,2026-05-03}-*.md` (current spec corpus only — older specs get a header note), `docs/superpowers/plans/{same}`, `docs/marketing/*` (delete or supersede), `docs/.vitepress/config.mts`, `docs/cli-release-homebrew/Formula/qkb.rb` (rename file), `docs/cli-release.md`, `docs/release-notes/*`, `docs/integrations.md`, `docs/index.md`. Older specs/plans get a one-line "see commit X for rename baseline" note. | ~50 files |
| **lead QIE deletion** | drop `packages/qie-{core,agent,cli}/`, `deploy/mock-qtsps/`, `docs/qie/`, `fixtures/qie/`, `qie-eng` row from CLAUDE.md, drop `@qkb/qie-*` deps from web/package.json, drop CI build steps for qie packages | ~70 files (deletes) |

## 6. Tag + commit conventions

- Final tag: **`v0.6.0-zkqes-rename`** (annotated, signed) on the merge commit that lands the rename train back to main.
- Per-worker commits use the worker's package CLAUDE.md scope prefix (e.g., `circuits(rename): rename QKBPresentationV5.circom → ZkqesPresentationV5.circom`).
- Final merge commit summarizes the four worker tracks, references the spec + orchestration plan + analysis report SHAs.
- CHANGELOG entry on the rename train branch.

## 7. Verification (per worker, before lead review)

- `pnpm install --frozen-lockfile` — green (workspace topology resolves under new package names)
- `pnpm -F @zkqes/<pkg> typecheck` — green
- `pnpm -F @zkqes/<pkg> test` — green
- `pnpm -F @zkqes/<pkg> build` — green where applicable
- For contracts-eng: `forge test` from the worker worktree (lead-side `forge test` from main is broken per task #65; that's a separate pre-existing issue and doesn't gate this rename)
- For circuits-eng: confirm zkey filename rename works in `stub-v5_2.sh` end-to-end
- For web-eng: `VITE_TARGET=landing pnpm -F @zkqes/web build` green + entry chunk size unchanged from V5.22 baseline
- ProtocolBytes invariant scan: `rg -n '^\s*const.*=\s*"qkb-' packages/{sdk,circuits,contracts}/src` returns the 9 frozen tags ONLY, no others. New invariant scan can be added to lint or CI in a follow-up.

## 8. Non-goals

- **Renaming the 9 frozen consensus-critical tags.** See §3.
- **Force-pushing or rewriting git history.** Old commits + tags retain historical names.
- **Renaming the GitHub repo back to `identityescroworg`.** It's now `alik-eth/zkqes` (renamed today); GitHub auto-redirects from the old URL, no source-side fix needed.
- **Migrating V3/V4 R2 artifacts to a new bucket.** The old bucket stays as-is.
- **Re-running Phase B ceremony.** Q3 freeze means circuit + ceremony stay valid.
- **Renaming `IdentityEscrowNFT` references in already-published release notes (`docs/release-notes/v0.5.3-contracts.md` etc.).** Those reference V5.x state at the time they were written; future release notes use the new name.
