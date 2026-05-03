# zkqes rename — surface analysis

**Author:** flattener-eng
**Date:** 2026-05-04
**Branch:** `chore/zkqes-rename-analysis`
**Worktree:** `/data/Develop/qkb-wt-v5/zkqes-rename-analysis`
**Base HEAD:** `c19ee47` (`docs(readme): patch 4 codex P2 findings from prior commit`)
**Scope:** Read-only enumeration. No source files edited.

---

## 0. Executive summary

The cheap-to-rename premise holds: nothing is on npm, nothing on Sepolia, ceremony has not started, all 8 `v0.5.x` tags are immutable history we leave untouched. But the structural surface is large — about **560 files** carry one or more of the rename tokens, ~736 raw `@qkb/` references, ~239 raw `identityescrow.org` URLs, plus consensus-critical domain-separation strings (`"qkb-rotate-auth-v1"`, `"qkb-personal-secret-v1"`, `"qkb-id-fingerprint-v1"`, `"qkb-binding-core/v1"`, …) that change keccak / Poseidon hashes if rewritten. The biggest single decision the founder needs to make first is **whether to rename those domain-separation tags or freeze them as protocol constants** — it gates whether the rename is a 1-day sweep or a 3-day sweep with full re-fixture + re-KAT regeneration.

### Headline counts

| Bucket | Files | Notes |
|---|---:|---|
| **A. Public-facing copy** | 36 | READMEs (3), BRAND.md, CHANGELOG.md, marketing drafts (5), LandingHero + 8 user-visible SPA components (CliBanner, MintButton, MintNftStep, RotateWalletFlow, Step2GenerateBinding, Step4ProveAndRegister, FlyLauncherForm, DocumentFooter), 7 routes (index.tsx, integrations.tsx, ua/{cli,mint,submit}, ceremony/{contribute,status,verify}), i18n (en+uk), 2 web meta files (index.html, 404.html), web PRIVACY.md, Homebrew formula, vitepress config, root README + package.json + docs/index.md, 2 release-note files |
| **B. Code identifiers** | ~55 | 8 Solidity contract decls, 3 libraries, 2 interfaces, 8 Circom templates, ~34 TS exports/types/constants (includes the previously-missed `QKB_DEPLOYMENTS`, `QkbNetwork`, `QkbDeployment`, `QkbError`, `CLI_BANNER_DISMISSED_KEY` SDK + web exports — see B.3) |
| **C. File and folder names** | 92 | 4 worktree-root packages (`qkb-cli`, `qie-core`, `qie-agent`, `qie-cli`), 24 `QKB*.sol` source/test files, 8 `QKBPresentation*.circom`, 4 `IdentityEscrow*.sol` source/test files, 4 SDK ABI files, 1 zkey filename family (`qkb-v5_2-stub.zkey`) |
| **D. Package manifest names** | 11 | 9 `@qkb/*` packages + 1 root + scope across consumers |
| **E. Configuration / CI / scripts** | 26 | 3 GitHub workflows, root `Caddyfile`, 2 `Dockerfile.web` (root + web/), `packages/web/fly.toml`, `packages/web/Dockerfile`, `deploy/mock-qtsps/{docker-compose.yml,Dockerfile.agent,deploy.sh,.env.example}`, `scripts/{ceremony-coord/*,sync-deployments.mjs,dev-chain.sh}`, ceremony cookbooks under `scripts/ceremony-coord/cookbooks/fly/`, `.env.example` |
| **F. Comments / docstrings / JSDoc** | ~120 | spread across packages — counted but not exhaustively listed (rename target follows the symbol they describe) |
| **G. CLAUDE.md / orchestration / spec / plan docs** | 56 | 7 CLAUDE.md, 17 specs, 38 plans, 5 handoffs, 1 notes, 1 evaluation |
| **H. Already-immutable** | — | 8 git tags (`v0.1.0-phase1`, `v0.2.0-phase2*`, `v0.5.{1,2,3,4,5}-pre-ceremony` / `-cli`), all prior commit messages, the schema `"$id"` URLs (see §1.I.4), R2 object keys already published if any (§1.I.5) |
| **I. Edge / ambiguous** | 17 | Domain-separation tags (consensus-critical), schema `$id` URLs, GitHub repo + org name, CLI binary name vs npm package vs Homebrew formula, `IdentityEscrowNFT` rename target, QIE package fate |

**Total file count across all buckets:** 562 unique files matched by the case-insensitive token sweep below. The per-bucket numbers above are *categorization* counts, not coverage counts — many files belong to several buckets at once (e.g. `packages/web/src/components/ua/v5/MintNftStep.tsx` is bucket A *and* B *and* F). Sum of column ≈ 360 because of that overlap.

### Token totals (case-insensitive, ripgrep, ignoring `pnpm-lock.yaml` + `.git/` + `*.zkey/r1cs/wasm/sym`)

| Token | Files | Hits |
|---|---:|---:|
| `qkb` | 514 | (not counted — exceeds report budget) |
| `qie` | 111 | … |
| `identityescrow` (path/string) | 142 | … |
| `identityescroworg` | 23 | 53 |
| `identityescrow.org` (domain) | 74 | 239 |
| `@qkb/` (npm scope) | 173 | 736 |
| `qualified key binding` | 17 | ~25 |
| `qualified identity escrow` | 14 | ~22 |

(Per-file counts captured in `/tmp/zkqes-rename/file-counts.txt` during analysis; not committed.)

---

## 1. Bucket-by-bucket

### A. Public-facing copy (24 files)

Anything an outside reader sees: the SPA, marketing pages, READMEs, the BRAND/CHANGELOG, ceremony recruitment copy, the docs.zkqes.org VitePress site. **Rename target throughout: `zkqes` (descriptor) + reword phrases like "Qualified Key Binding", "Identity Escrow project", "QIE" out of the marketing voice.**

| File | Hits | Suggested target | Notes |
|---|---:|---|---|
| `README.md` | 15 | `# zkqes` (drop "QKB — Qualified Key Binding"); rewrite §1.1 protocol description; replace `@qkb/web`, `@qkb/circuits`, `QKBRegistryV5_2`, `IdentityEscrowNFT` references with `zkqes-*` equivalents | Lines 1, 7, 17, 22-30, 36, 94, 96, 102-113. Lead-owned. |
| `BRAND.md` | 16 | **Rewrite the table.** "Protocol noun" was QKB → now `zkqes`. "Project umbrella" was Identity Escrow → likely fold into `zkqes` (collapse to one noun per dispatch). Drop "QIE Phase 2 design line" row entirely if QIE is parked + renamed. | Lines 12-15, 19-30, 39-49, 55-64. Lead-owned. The brand decision in the same file is reversed — needs a new entry recording the reversal date + rationale, otherwise future readers will be confused. |
| `CHANGELOG.md` | 14 | Treat as historical record (bucket H-adjacent). Add a single new entry: `## v0.6.0 — zkqes rename` describing what moved. Don't rewrite prior entries. | Lines 9, 31, 64. |
| `package.json` (root) | 3 | `"name": "zkqes"` (was `identityescroworg`) and rewrite `"description"` to drop QKB+QIE tagline. | Lines 2, 5, 15 (`"flatten"` script also references `@qkb/lotl-flattener`). |
| `docs/index.md` | 5 | VitePress homepage. Update CTA text + `link: 'https://zkqes.org'` already correct. | Mostly correct already. |
| `docs/marketing/2026-05-03-branding-decision.md` | 14 | **Either delete or supersede** — this whole file argues against the rename that just happened. Replace with a 1-page "decision reversed 2026-05-04" stub or move under `docs/superpowers/research/` as historical. | All 14 hits are the argued-position; the file is now stale. |
| `docs/marketing/2026-05-03-task-21-branding-recommendation.md` | 28 | Same fate — historical. Move under `research/` or delete. | All hits are the argued-position. |
| `docs/marketing/2026-04-30-ceremony-drafts/ceremony-announcement-thread.md` | 9 | Rewrite each "QKB" → "zkqes". Affects launch X-thread copy. Translator/marketer review. | Pre-recruitment so cheap to rewrite. |
| `docs/marketing/2026-04-30-ceremony-drafts/signup-email.md` | 7 | Same — rewrite. | Pre-recruitment. |
| `docs/contributing/index.md` | 3 | Surface refs to repo URL + worker dispatch language. | Lines including `github.com/alik-eth/identityescroworg` (= bucket I.6). |
| `docs/integrations.md` | 12 | Public docs — replace `@qkb/contracts-sdk`, `IQKBRegistry`, `IdentityEscrowNFT.isVerified()` with renamed equivalents or keep "for ABI compat" footnote | Coupled to bucket B + D. |
| `packages/web/index.html` | 3 | `<title>QKB — Qualified Key Binding</title>`, `<meta og:title>`, description meta. → `<title>zkqes — zero-knowledge proof of qualified electronic signature</title>` | Lines 14, 16, 29. Lead-owned with web-eng. |
| `packages/web/public/404.html` | 3 | Same `<title>` + GH-Pages comment that mentions `/identityescroworg/`. | Lines 5, 8, 12. |
| `packages/web/PRIVACY.md` | 5 | User-facing privacy page — "QKB" → "zkqes" throughout. | web-eng-owned. |
| `packages/web/README.md` | 11 | "Static SPA for Qualified Key Binding (QKB)" → "Static SPA for zkqes". | web-eng-owned. |
| `packages/web/src/components/LandingHero.tsx` | 6 | Lines 12-13 are noun comments; line 81 + 226 + 234 + 242 are user-visible English strings. Translator review for the umbrella heading at line 234 (`{t('zkqes.umbrellaHeading', 'About Identity Escrow')}` — note the i18n key is already namespaced `zkqes.*`, just the fallback English text needs updating). | web-eng-owned. |
| `packages/web/src/i18n/en.json` | 22 | Public copy strings. Bulk rewrite needed for: keys `cli.title`, `cli.runBody`, `cli.verifyBody`, `cli.troubleManifestBody`, `cliPromo.title/body/cta`, `rotation.warningBody`, `rotation.body`, `rotation.authHashLabel`, `ceremony.fileAriaStub/Final`, `ceremony.framing`, `zkqes.umbrellaHeading`, `zkqes.umbrellaBody`, plus `closing` at line 17. | web-eng + translator review. |
| `packages/web/src/i18n/uk.json` | 21 | Mirror of `en.json` — Ukrainian translator pass needed. Same key set. | web-eng + UK translator. |
| `packages/web/src/routes/integrations.tsx` | 9 | Public integrations page surface. | web-eng-owned. |
| `packages/web/src/routes/ua/cli.tsx` | 17 | CLI install page — `QKB CLI` heading + every `qkb serve` invocation in copy. | web-eng-owned. |
| `packages/web/src/routes/ua/mint.tsx` | 8 | Mint flow copy. | web-eng-owned. |
| `packages/web/src/routes/ceremony/contribute.tsx` | 4 | Ceremony recruitment page — `qkb-v5_2-stub.zkey` URL refs. | web-eng-owned. |
| `packages/web/src/routes/ceremony/verify.tsx` | 5 | Ceremony verification page. | web-eng-owned. |
| `docs/cli-release-homebrew/Formula/qkb.rb` | 14 | Homebrew formula. `class Qkb < Formula` → `class Zkqes < Formula`, `desc`, `homepage "https://identityescrow.org"` → `https://zkqes.org`, file URL pattern `qkb-darwin-arm64` → `zkqes-darwin-arm64`, binary install rename. **Tap repo `qkb-eth/homebrew-qkb` also renames** — see bucket I.6. | Lead-owned. |
| `docs/cli-release.md` | 19 | CLI release docs. | Lead-owned. |
| `docs/release-notes/v0.5.2-contracts.md` | 14 | Historical release note — keep as-is OR add a forward note. | Bucket H-adjacent. |
| `docs/release-notes/v0.5.3-contracts.md` | 15 | Same. | Bucket H-adjacent. |
| `docs/.vitepress/config.mts` | 27 | docs.zkqes.org config — currently excludes `qie/**` + many spec files by name, references `Identity Escrow contributors` in copyright footer at line 273. Needs sweep + new exclusion list (or none if QIE-deleted). | Lead-owned. |
| `packages/web/src/routes/index.tsx` | 1 | Line 178: visible English copy `'This is identity escrow. Every-day pseudonymity for the holder; recoverable accountability for the state. The same trust structure as the qualified electronic signature itself — preserved on-chain.'` Translator + copywriter pass. | web-eng-owned. |
| `packages/web/src/components/ua/v5/CliBanner.tsx` | 3 | Lines 2, 6 are NatSpec; line 25 `export const CLI_BANNER_DISMISSED_KEY = 'qkb.cliBanner.dismissed'` — localStorage key, renaming invalidates existing dismissals (cosmetic, low risk). | web-eng-owned. Bucket B-adjacent. |
| `packages/web/src/components/ua/v5/Step2GenerateBinding.tsx` | 4 | Lines 30, 45 (`a.download = 'binding.qkb2.json'`), 55, 62 — visible filename `binding.qkb2.json` plus `QKB/2.0` schema string in user-visible JSON download. **Schema string is consensus-critical (§3.Q3).** Filename is cosmetic — rename to `binding.zkqes2.json` is free. | web-eng-owned. |
| `packages/web/src/components/ua/v5/Step4ProveAndRegister.tsx` | 5 | Lines 15, 19, 39, 48, 206: imports + comments referring to `qkbRegistryV5_2Abi` + `QKBRegistryV5_2`. Mostly bucket B follow-on. | web-eng-owned. |
| `packages/web/src/components/ua/v5/RotateWalletFlow.tsx` | 9 | Lines 7, 41, 59, 72: `qkbRegistryV5_2Abi` import + comments referencing `QKBRegistryV5_2.t.sol`. Bucket B follow-on. | web-eng-owned. |
| `packages/web/src/components/ua/v5/MintNftStep.tsx` | 9 | Lines 8, 16, 18, 33, 42, 43, 58, 59, 123: `IdentityEscrowNFT` references throughout the visible mint flow. Resolves with §3.Q1. | web-eng-owned. |
| `packages/web/src/components/MintButton.tsx` | 8 | Lines 7-10, 30, 38, 48-49: `identityEscrowNftAbi`, `qkbRegistryV4Abi`, `qkbRegistryV5_1Abi` imports + on-chain wiring of the mint button user-visible action. Bucket B + D follow-on. | web-eng-owned. |
| `packages/web/src/components/ceremony/FlyLauncherForm.tsx` | 1 | Line 170: visible placeholder URL `placeholder="https://prove.identityescrow.org/upload/round-3.zkey?sig=…"` in the ceremony contribution form. | web-eng-owned. |
| `packages/web/src/components/DocumentFooter.tsx` | 1 | Line 2: `import { deploymentForChainId } from '@qkb/sdk';` Bucket D follow-on; cosmetic for footer. | web-eng-owned. |
| `packages/web/src/routes/ceremony/status.tsx` | 1 | Line 6: NatSpec `Production feed: https://prove.identityescrow.org/ceremony/status.json`. | web-eng-owned. |
| `packages/web/src/routes/ua/submit.tsx` | 2 | URL refs. | web-eng-owned. |

**Translator workload (en + uk):** every key in `packages/web/src/i18n/{en,uk}.json` containing the word "QKB", "qkb", or "Identity Escrow" / "IdentityEscrowNFT". Per ripgrep that's 22 strings in `en.json` and 21 in `uk.json`. **Plus** the inline English string at `packages/web/src/routes/index.tsx:178` (no i18n key — hard-coded fallback).

### B. Code identifiers (~50 declarations)

These are the actual Solidity contracts, libraries, interfaces, Circom templates, and TypeScript exports whose **names** carry the token. Tests reference them, ABIs encode them, public APIs document them.

#### B.1 Solidity contracts — `packages/contracts/src/` and `packages/contracts/test/`

| Decl | File | Line | Suggested rename |
|---|---|---:|---|
| `contract QKBRegistry` | `src/QKBRegistry.sol` | 20 | `ZkqesRegistry` |
| `contract QKBRegistryV3` | `src/QKBRegistryV3.sol` | 36 | `ZkqesRegistryV3` |
| `contract QKBRegistryV4` | `src/QKBRegistryV4.sol` | 12 | `ZkqesRegistryV4` |
| `contract QKBRegistryV5` | `src/QKBRegistryV5.sol` | 46 | `ZkqesRegistryV5` |
| `contract QKBRegistryV5_2` | `src/QKBRegistryV5_2.sol` | 72 | `ZkqesRegistryV5_2` ← currently the *only* contract slated for Sepolia. Rename has the highest payoff here. |
| `contract IdentityEscrowNFT is ERC721` | `src/IdentityEscrowNFT.sol` | 15 | **founder Q** — `ZkqesCertificate`? `ZkqesNFT`? `ZkqesCredential`? See §3.Q1. |
| `contract QKBGroth16VerifierEcdsaLeaf` | `src/verifiers/QKBGroth16VerifierEcdsaLeaf.sol` | 23 | `ZkqesGroth16VerifierEcdsaLeaf` |
| `contract QKBGroth16VerifierEcdsaChain` | `src/verifiers/QKBGroth16VerifierEcdsaChain.sol` | 23 | `ZkqesGroth16VerifierEcdsaChain` |
| `contract QKBGroth16VerifierStubEcdsa` | `src/verifiers/QKBGroth16VerifierStubEcdsa.sol` | 23 | `ZkqesGroth16VerifierStubEcdsa` |
| `contract QKBGroth16VerifierStubRsa` | `src/verifiers/QKBGroth16VerifierStubRsa.sol` | 23 | `ZkqesGroth16VerifierStubRsa` |
| `contract QKBGroth16VerifierStubEcdsaLeaf` | `src/verifiers/dev/QKBGroth16VerifierStubEcdsaLeaf.sol` | 23 | `ZkqesGroth16VerifierStubEcdsaLeaf` |
| `contract QKBGroth16VerifierStubEcdsaChain` | `src/verifiers/dev/QKBGroth16VerifierStubEcdsaChain.sol` | 23 | `ZkqesGroth16VerifierStubEcdsaChain` |
| `library QKBVerifier` | `src/QKBVerifier.sol` | 58 | `ZkqesVerifier` |
| `library QKBVerifierV2` | `src/QKBVerifierV2.sol` | 26 | `ZkqesVerifierV2` |
| `library QKBVerifierV4Draft` | `src/QKBVerifierV4Draft.sol` | 56 | `ZkqesVerifierV4Draft` |
| `interface IQKBRegistry` | `src/IdentityEscrowNFT.sol` | 7 | `IZkqesRegistry` ← duplicate decl; see B.3 |
| `interface IQKBRegistry` | `packages/contracts-sdk/src/IQKBRegistry.sol` | 22 | `IZkqesRegistry` (file rename: `IZkqesRegistry.sol`) |

Plus 22 `contract Q*Test`/`contract IdentityEscrowNFT*Test` declarations in `packages/contracts/test/` — file names listed in bucket C; declaration names follow the package convention.

#### B.2 Circom templates — `packages/circuits/circuits/`

| Template | File | Suggested rename |
|---|---|---|
| `template QKBPresentationV5()` | `QKBPresentationV5.circom` | `template ZkqesPresentationV5()` (file: `ZkqesPresentationV5.circom`) ← V5 production circuit |
| `template QKBPresentationEcdsaLeaf()` | `QKBPresentationEcdsaLeaf.circom` | `ZkqesPresentationEcdsaLeaf` |
| `template QKBPresentationEcdsaLeafV4()` | `QKBPresentationEcdsaLeafV4.circom` | `ZkqesPresentationEcdsaLeafV4` |
| `template QKBPresentationEcdsaLeafStub()` | `QKBPresentationEcdsaLeafStub.circom` | `ZkqesPresentationEcdsaLeafStub` |
| `template QKBPresentationEcdsaChain()` | `QKBPresentationEcdsaChain.circom` | `ZkqesPresentationEcdsaChain` |
| `template QKBPresentationEcdsaChainStub()` | `QKBPresentationEcdsaChainStub.circom` | `ZkqesPresentationEcdsaChainStub` |
| `template QKBPresentationRsaStub()` | `QKBPresentationRsaStub.circom` | `ZkqesPresentationRsaStub` |
| `template QKBPresentationAgeV4()` | `QKBPresentationAgeV4.circom` | `ZkqesPresentationAgeV4` |

Plus the `_UA` variant `QKBPresentationEcdsaLeafV4_UA.circom` (template name implied; not grepped).

#### B.3 TypeScript exports / types / constants

| Symbol | File | Line | Suggested rename |
|---|---|---:|---|
| `qkbRegistryV4Abi` | `packages/sdk/src/index.ts` | 249 | `zkqesRegistryV4Abi` |
| `qkbRegistryV5_1Abi` | `packages/sdk/src/index.ts` | 250 | `zkqesRegistryV5_1Abi` |
| `qkbRegistryV5_2Abi` | `packages/sdk/src/index.ts` | 251 | `zkqesRegistryV5_2Abi` |
| `identityEscrowNftAbi` | `packages/sdk/src/index.ts` | 252 | depends on §3.Q1 |
| `QKB_DEPLOYMENTS` | `packages/sdk/src/deployments.ts` | 23 | `ZKQES_DEPLOYMENTS` — re-exported from `index.ts:243`. Public registry-address map. |
| `QkbDeployment` (type) | `packages/sdk/src/deployments.ts` | — | `ZkqesDeployment` — re-exported from `index.ts:245`. |
| `QkbNetwork` (type) | `packages/sdk/src/deployments.ts` | 55 | `ZkqesNetwork` — re-exported from `index.ts:246`. |
| `QkbError` (class) | `packages/sdk/src/errors/index.ts` | — | `ZkqesError` — re-exported from `index.ts:9`. Public error-taxonomy class. |
| `CLI_BANNER_DISMISSED_KEY = 'qkb.cliBanner.dismissed'` | `packages/web/src/components/ua/v5/CliBanner.tsx` | 25 | `'zkqes.cliBanner.dismissed'`. **localStorage key** — renaming silently re-shows the banner to existing dismiss-cookie holders. Cosmetic. |
| `IQKBRegistry public immutable qkbRegistry` | `packages/contracts-sdk/src/Verified.sol` | 10 | `IZkqesRegistry public immutable zkqesRegistry` |
| `BINDING_V2_SCHEMA = 'qkb-binding-core/v1'` | `packages/sdk/src/binding/index.ts` | 19 | **CONSENSUS-CRITICAL — see §3.Q3.** Rename or freeze? |
| `POLICY_LEAF_V1_SCHEMA = 'qkb-policy-leaf/v1'` | `packages/sdk/src/binding/index.ts` | 20 | Same. |
| `CACHE_NAME = 'qkb-circuit-artifacts-v1'` | `packages/sdk/src/artifacts/index.ts` | 65 | Browser CacheStorage namespace. Renaming invalidates existing user caches. Rename to `zkqes-circuit-artifacts-v1` is safe (cache miss = re-download). |
| `FINAL_ZKEY_KEY = 'qkb-v5-final.zkey'` | `scripts/ceremony-coord/src/r2.ts` | 63 | `zkqes-v5-final.zkey` (R2 object key). Cheap because not yet published. |
| `'qkb-rotate-auth-v1'` (string literal in i18n + spec + handoffs) | various | various | **CONSENSUS-CRITICAL — see §3.Q3.** Used in `keccak256("qkb-rotate-auth-v1" ‖ chainId ‖ …)` for rotation authorization hash. Renaming changes hash → invalidates all in-flight rotation signatures. |
| `'qkb-personal-secret-v1'` | spec + web | — | Same — used in `walletSecret` derivation. Renaming changes every derived secret. |
| `'qkb-id-fingerprint-v1'` (FINGERPRINT_DOMAIN) | spec | — | Same — circuit-level domain-separation tag. Renaming requires re-compile of V5 circuit (changes the field-element constant). |
| `'qkb-walletsecret-v1'` (HKDF salt) | spec | — | Same. |
| `'qkb-v5-walletsecret'` (HKDF salt) | spec | — | Same. |
| `'qkb-default-ua'` (policyId) | `fixtures/declarations/ua/policy-v1.json` + sdk tests | — | Changes the policy-leaf hash → changes Merkle path → changes trust root. |
| `'qkb-tsl-update-witness/v1'` | trustless-eIDAS spec (parked) | — | Parked spec; only relevant if trustless-eIDAS is unparked. |
| `'qkb-witness/v1'` | qkb-cli design spec | — | Local IPC schema between SPA and `qkb serve`. Cheap to rename if both ends rename together. |
| `qkb-flatten` (`bin` entry) | `packages/lotl-flattener/package.json` | 7 | `zkqes-flatten` |

**For full enumeration of all string-literal hits:** `rg -n "'qkb-|\"qkb-" --hidden -g '!pnpm-lock.yaml' -g '!.git/**' -g '!node_modules/**'` — ~50 hits, all flagged in §3.Q3.

### C. File and folder names (92 paths)

#### C.1 Top-level packages (folder rename)

| Path | Suggested target | Notes |
|---|---|---|
| `packages/qkb-cli/` | `packages/zkqes-cli/` | All consumers: `package.json` `bin` entry, `pnpm-workspace.yaml` (currently uses glob `packages/*` so no edit), `.github/workflows/release-cli.yml` (~10 path refs), `packages/web/test/fixtures/qkb-cli-0.5.2-pre.tgz`, `packages/web/package.json` `@qkb/cli` dep, `docs/cli-release-homebrew/Formula/qkb.rb`. |
| `packages/qie-core/` | **founder Q** — delete or rename to `packages/zkqes-escrow-core/`? See §3.Q2. |
| `packages/qie-agent/` | Same Q. |
| `packages/qie-cli/` | Same Q. |

`packages/{circuits,contracts,contracts-sdk,lotl-flattener,sdk,web}/` keep their names — none of those paths carry a QKB/QIE/IE token. Internal `package.json` `"name"` field changes (bucket D).

#### C.2 Solidity files — `packages/contracts/src/`

```
src/QKBRegistry.sol             → src/ZkqesRegistry.sol
src/QKBRegistryV3.sol           → src/ZkqesRegistryV3.sol
src/QKBRegistryV4.sol           → src/ZkqesRegistryV4.sol
src/QKBRegistryV5.sol           → src/ZkqesRegistryV5.sol
src/QKBRegistryV5_2.sol         → src/ZkqesRegistryV5_2.sol
src/QKBVerifier.sol             → src/ZkqesVerifier.sol
src/QKBVerifierV2.sol           → src/ZkqesVerifierV2.sol
src/QKBVerifierV4Draft.sol      → src/ZkqesVerifierV4Draft.sol
src/IdentityEscrowNFT.sol       → founder Q (§3.Q1)
src/verifiers/QKBGroth16VerifierEcdsaLeaf.sol         → ZkqesGroth16VerifierEcdsaLeaf.sol
src/verifiers/QKBGroth16VerifierEcdsaChain.sol        → ZkqesGroth16VerifierEcdsaChain.sol
src/verifiers/QKBGroth16VerifierStubEcdsa.sol         → ZkqesGroth16VerifierStubEcdsa.sol
src/verifiers/QKBGroth16VerifierStubRsa.sol           → ZkqesGroth16VerifierStubRsa.sol
src/verifiers/dev/QKBGroth16VerifierStubEcdsaLeaf.sol → ZkqesGroth16VerifierStubEcdsaLeaf.sol
src/verifiers/dev/QKBGroth16VerifierStubEcdsaChain.sol → ZkqesGroth16VerifierStubEcdsaChain.sol
```

#### C.3 Solidity test files — `packages/contracts/test/`

```
test/QKBRegistry.admin.t.sol         → test/ZkqesRegistry.admin.t.sol
test/QKBRegistry.escrow.t.sol        → test/ZkqesRegistry.escrow.t.sol
test/QKBRegistry.expire.t.sol        → test/ZkqesRegistry.expire.t.sol
test/QKBRegistry.isActiveAt.t.sol    → test/ZkqesRegistry.isActiveAt.t.sol
test/QKBRegistry.nullifier.t.sol     → test/ZkqesRegistry.nullifier.t.sol
test/QKBRegistry.register.t.sol      → test/ZkqesRegistry.register.t.sol
test/QKBRegistryV3.admin.t.sol       → test/ZkqesRegistryV3.admin.t.sol
test/QKBRegistryV3.escrow.t.sol      → test/ZkqesRegistryV3.escrow.t.sol
test/QKBRegistryV3.expire.t.sol      → test/ZkqesRegistryV3.expire.t.sol
test/QKBRegistryV3.isActiveAt.t.sol  → test/ZkqesRegistryV3.isActiveAt.t.sol
test/QKBRegistryV3.nullifier.t.sol   → test/ZkqesRegistryV3.nullifier.t.sol
test/QKBRegistryV3.register.t.sol    → test/ZkqesRegistryV3.register.t.sol
test/QKBRegistryV4.t.sol             → test/ZkqesRegistryV4.t.sol
test/QKBRegistryV5.register.t.sol    → test/ZkqesRegistryV5.register.t.sol
test/QKBRegistryV5.t.sol             → test/ZkqesRegistryV5.t.sol
test/QKBRegistryV5_1.t.sol           → test/ZkqesRegistryV5_1.t.sol
test/QKBRegistryV5_2.t.sol           → test/ZkqesRegistryV5_2.t.sol
test/QKBVerifier.t.sol               → test/ZkqesVerifier.t.sol
test/QKBVerifier.fuzz.t.sol          → test/ZkqesVerifier.fuzz.t.sol
test/QKBGroth16VerifierStub.integration.t.sol → test/ZkqesGroth16VerifierStub.integration.t.sol
test/IdentityEscrowNFT.t.sol         → founder Q (§3.Q1)
test/IdentityEscrowNFT.v5.t.sol      → founder Q (§3.Q1)
```

Plus contracts-sdk:
```
packages/contracts-sdk/src/IQKBRegistry.sol → packages/contracts-sdk/src/IZkqesRegistry.sol
```

#### C.4 Circom files — `packages/circuits/circuits/`

```
QKBPresentationV5.circom              → ZkqesPresentationV5.circom
QKBPresentationEcdsaLeaf.circom       → ZkqesPresentationEcdsaLeaf.circom
QKBPresentationEcdsaLeafV4.circom     → ZkqesPresentationEcdsaLeafV4.circom
QKBPresentationEcdsaLeafV4_UA.circom  → ZkqesPresentationEcdsaLeafV4_UA.circom
QKBPresentationEcdsaLeafStub.circom   → ZkqesPresentationEcdsaLeafStub.circom
QKBPresentationEcdsaChain.circom      → ZkqesPresentationEcdsaChain.circom
QKBPresentationEcdsaChainStub.circom  → ZkqesPresentationEcdsaChainStub.circom
QKBPresentationRsaStub.circom         → ZkqesPresentationRsaStub.circom
QKBPresentationAgeV4.circom           → ZkqesPresentationAgeV4.circom
```

Plus auto-generated verifier outputs in `packages/circuits/ceremony/` (5 `QKB*.sol` files) and `packages/circuits/fixtures/integration/{ecdsa-leaf,ecdsa-chain}/` (2 `QKB*.sol` files) — these regenerate on next ceremony pass and inherit the new template name automatically; no manual rename needed if the source `.circom` is renamed first.

#### C.5 SDK ABI mirror files — `packages/sdk/src/abi/`

```
packages/sdk/src/abi/QKBRegistryV4.ts   → ZkqesRegistryV4.ts
packages/sdk/src/abi/QKBRegistryV5_1.ts → ZkqesRegistryV5_1.ts
packages/sdk/src/abi/QKBRegistryV5_2.ts → ZkqesRegistryV5_2.ts
packages/sdk/src/abi/IdentityEscrowNFT.ts → founder Q (§3.Q1)
```

#### C.6 Test fixture file

```
packages/web/test/fixtures/qkb-cli-0.5.2-pre.tgz → zkqes-cli-0.5.2-pre.tgz
```
Referenced from `packages/web/package.json:47` `"@qkb/cli": "file:./test/fixtures/qkb-cli-0.5.2-pre.tgz"`.

#### C.7 zkey filename family — `packages/circuits/ceremony/{v5,v5-stub,v5_1,v5_2,v5_3,scripts}/`

```
qkb-v5-stub.zkey            → zkqes-v5-stub.zkey
qkb-v5_1-stub.zkey          → zkqes-v5_1-stub.zkey
qkb-v5_2-stub.zkey          → zkqes-v5_2-stub.zkey
qkb-v5_3-stub.zkey          → zkqes-v5_3-stub.zkey
qkb-v5-final.zkey           → zkqes-v5-final.zkey  (post-Phase-B)
qkb-v5_2-vkey.json          → zkqes-v5_2-vkey.json
qkb-v5_2.wasm               → zkqes-v5_2.wasm
qkb-v5.r1cs                 → zkqes-v5.r1cs
```

These names are referenced in:
- `packages/circuits/ceremony/scripts/stub-v5*.sh` (5 files; ~12 hits each)
- `packages/circuits/benchmarks/v5_2-prove-bench.sh`, `serve-fixtures.mjs`
- `packages/qkb-cli/src/commands/cache.ts` (lines 7-15 — sample output text)
- `packages/qkb-cli/test/integration/{serve-prove-roundtrip,failure-modes}.test.ts` (zkey path constants)
- `packages/qkb-cli/test/unit/cache-commands.test.ts:161` (`writeFile(join(circuitsDir, 'qkb-v5.2.zkey'), …)`)
- `packages/qkb-cli/README.md` (lines 48-50)
- `packages/circuits/ceremony/v5{,-stub,_1,_2,_3}/{README.md,zkey.sha256}`
- `packages/circuits/CLAUDE.md` (lines 543, 695)
- `scripts/ceremony-coord/src/r2.ts:63` (the `FINAL_ZKEY_KEY` const)
- `scripts/ceremony-coord/{README.md,scripts/publish-status.ts}`
- `scripts/ceremony-coord/cookbooks/fly/contrib.env.example:13` (`R1CS_URL=https://prove.identityescrow.org/ceremony/qkb-v5.r1cs`)
- `packages/web/src/i18n/{en,uk}.json` lines 309-310 (file aria labels)
- `docs/superpowers/specs/2026-05-03-qkb-helper-design.md` (lines 393-427)
- `docs/superpowers/plans/2026-05-03-qkb-{cli-server,helper}-orchestration.md` (lines 63-92, 98-244)
- `docs/superpowers/plans/2026-04-29-v5-architecture-{circuits,orchestration}.md` (zkey output filenames in compile/setup commands)

If renaming the zkey filenames goes ahead, the change is bucketed E + G + A; the zkey *bytes* are unchanged.

#### C.8 QIE folders + fixtures (deletion pending §3.Q2)

```
packages/qie-core/    (28 files)
packages/qie-agent/   (35 files)
packages/qie-cli/     (5 files)
deploy/mock-qtsps/    (10 files)
docs/qie/             (2 files: 15-legal-instruments.md, 16-operational-model.md)
fixtures/qie/         (3 files: agents/.gitkeep, arbitrators/.gitkeep, hybrid-kat.json)
```

Plus `docs/superpowers/specs/2026-04-17-qie-*.md` (3) and `docs/superpowers/plans/2026-04-17-qie-*.md` (8) — these are historical research artifacts; lead's previous direction (CLAUDE.md memory `project_split_proof_pivot`) parked QIE. **Recommend: keep specs/plans under `docs/superpowers/` as historical record (bucket H), delete the live packages + Docker scaffolding only.** Decision flagged §3.Q2.

### D. Package manifest names (`package.json` `"name"` + `dependencies`)

| Manifest | Current name | Suggested target | Consumers |
|---|---|---|---|
| `package.json` (root) | `"identityescroworg"` | `"zkqes"` | None (it's the workspace root). |
| `packages/circuits/package.json` | `@qkb/circuits` | `@zkqes/circuits` | Workflows (pages.yml line 86), scripts in ~20 docs/plans. |
| `packages/contracts/package.json` | `@qkb/contracts` | `@zkqes/contracts` | CLAUDE.md, scripts. |
| `packages/contracts-sdk/package.json` | `@qkb/contracts-sdk` | `@zkqes/contracts-sdk` | `docs/integrations.md`. |
| `packages/lotl-flattener/package.json` | `@qkb/lotl-flattener` | `@zkqes/lotl-flattener` | Root `package.json:15` `"flatten": "pnpm --filter @qkb/lotl-flattener run cli"`, root README, scripts. |
| `packages/qkb-cli/package.json` | `@qkb/cli` | `@zkqes/cli` | `packages/web/package.json:47`, `.github/workflows/release-cli.yml` (~5 hits), Homebrew formula, all CLI design docs. |
| `packages/sdk/package.json` | `@qkb/sdk` | `@zkqes/sdk` | `packages/web/package.json:23`, `.github/workflows/pages.yml:64`, `Dockerfile.web:27`, `packages/web/Dockerfile:32`. |
| `packages/web/package.json` | `@qkb/web` | `@zkqes/web` | All CI workflows, root scripts, all CLAUDE.md, docs. |
| `packages/qie-core/package.json` | `@qkb/qie-core` | **§3.Q2** | If kept: `@zkqes/escrow-core`. If deleted: drop `packages/web/package.json:22`, `.github/workflows/pages.yml:62`, `Dockerfile.web:25`, `packages/web/Dockerfile:30`, `deploy/mock-qtsps/Dockerfile.agent:32`, `deploy/mock-qtsps/docker-compose.yml:17`. |
| `packages/qie-agent/package.json` | `@qkb/qie-agent` | **§3.Q2** | If kept: `@zkqes/escrow-agent`. If deleted: drop ~12 references same shape as qie-core. |
| `packages/qie-cli/package.json` | `@qkb/qie-cli` | **§3.Q2** | If kept: `@zkqes/escrow-cli`. If deleted: drop `deploy/mock-qtsps/.env.example:7`. |
| `scripts/ceremony-coord/package.json` | `@qkb/ceremony-coord` | `@zkqes/ceremony-coord` | Standalone subtree, low blast radius. |

`@qkb/` reverse-search across the worktree returns 173 files / 736 hits — that's the universe of `pnpm --filter @qkb/*` invocations, ABI imports, dependency graphs, and CI commands that need a sed pass. The pattern is mechanical.

### E. Configuration / CI / scripts (26 files)

| File | Hits | What changes |
|---|---:|---|
| `.github/workflows/pages.yml` | 8 | Lines 12, 21, 62-64, 72, 77, 81, 86, 88-89: `@qkb/qie-core build`, `@qkb/qie-agent build`, `@qkb/sdk build`, `@qkb/web build`, `prove.identityescrow.org/ceremony/status.json`, base-path comment. |
| `.github/workflows/pages-docs.yml` | 1 | Line 22 comment `Cloudflare Pages: connect to identityescroworg repo` — repo name (§3.Q6). |
| `.github/workflows/release-cli.yml` | 21 | Every line — `@qkb/cli`, `qkb-eth/identityescroworg`, `qkb-eth/homebrew-qkb`, `Formula/qkb.rb`, `qkb-${target}` artifact name, `qkb-bot` git author, `bot@identityescrow.org`. Heaviest CI rewrite. |
| `Caddyfile` | 0 | Generic — but the SPA it serves does need a re-build. No edits to this file. |
| `Dockerfile.web` (root) | 9 | Lines 16-28: `packages/qie-core`, `packages/qie-agent`, `@qkb/web…`, `@qkb/qie-core build`, `@qkb/qie-agent build`, `@qkb/sdk build`, `@qkb/web build`. |
| `packages/web/Dockerfile` | 9 | Same shape as root `Dockerfile.web`. |
| `packages/web/fly.toml` | 3 | Lines 1-5: `# Fly.io config for the QKB Identity Escrow static SPA.`, `# Production domain: identityescrow.org`, `app = "identityescrow"`. → `app = "zkqes"`. |
| `deploy/mock-qtsps/docker-compose.yml` | 22 | All `qie-agent:local` image refs, all `QIE_*` env keys (`QIE_AGENT_KEYS_PATH`, `QIE_AGENT_STORAGE`, `QIE_AGENT_PORT`, `QIE_RPC_URL`, `QIE_LOCAL_ADDRESSES_PATH`), `.well-known/qie-agent.json` healthcheck path, `pnpm -F @qkb/qie-core build && pnpm -F @qkb/qie-agent build` comment. **Whole file gone if §3.Q2 = delete.** |
| `deploy/mock-qtsps/Dockerfile.agent` | 18 | Same fate as above. |
| `deploy/mock-qtsps/Dockerfile.agent.dockerignore` | 4 | Same. |
| `deploy/mock-qtsps/.env.example` | 6 | Same. |
| `deploy/mock-qtsps/deploy.sh` | 6 | Lines 74, 85, 87, 91, 96, 97: `QKBRegistry`, `QIE_AUTHORITY_ADDRESS`, `QIE_REGISTRY_ADDRESS`. **Whole file probably gone if §3.Q2 = delete.** |
| `scripts/dev-chain.sh` | 2 | Lines 2, 61: comment + `pnpm -F @qkb/web dev` echo. |
| `scripts/sync-deployments.mjs` | 3 | Lines 24, 42, 43: `identityEscrowNft` field name (§3.Q1 follow-on). |
| `scripts/ceremony-coord/.env.example` | 3 | Lines 3, 7, 8: `bucket prove-identityescrow-org`, `R2_BUCKET=prove-identityescrow-org`, `R2_PUBLIC_BASE=https://prove.identityescrow.org`. R2 bucket rename is non-trivial — flag §3.Q5. |
| `scripts/ceremony-coord/src/r2.ts` | 3 | Line 36 default `https://prove.identityescrow.org`, line 37 comment, line 63 `FINAL_ZKEY_KEY = 'qkb-v5-final.zkey'`. |
| `scripts/ceremony-coord/README.md` | 11 | Bucket walkthrough — every URL example. |
| `scripts/ceremony-coord/scripts/publish-status.ts` | 1 | Line 9 comment about `qkb-v5-final.zkey`. |
| `scripts/ceremony-coord/cookbooks/fly/Dockerfile` | 3 | Lines 4, 9: `Published to: ghcr.io/identityescroworg/qkb-ceremony:v1`, OCI source label. |
| `scripts/ceremony-coord/cookbooks/fly/launcher.sh` | 11 | Line 39 `GHCR_IMAGE_REPO`, plus host examples. |
| `scripts/ceremony-coord/cookbooks/fly/launch.sh` | 1 | Source URL. |
| `scripts/ceremony-coord/cookbooks/fly/contrib.env.example` | 4 | `R1CS_URL=https://prove.identityescrow.org/ceremony/qkb-v5.r1cs`, `IMAGE=ghcr.io/identityescroworg/qkb-ceremony:v1`, etc. |
| `scripts/ceremony-coord/cookbooks/fly/entrypoint.sh` | 2 | URL refs. |
| `scripts/ceremony-coord/cookbooks/fly/fly.toml` | 2 | App name. |
| `scripts/ceremony-coord/cookbooks/fly/README.md` | 28 | All GHCR URLs (`ghcr.io/identityescroworg/qkb-ceremony`), `github.com/orgs/identityescroworg/packages` link, all `qkb-ceremony` image names. **Repo + org rename — see §3.Q6.** |
| `.env.example` (root) | 6 | `QKB_PROVER_WASM_URL_RSA`, `QKB_PROVER_ZKEY_URL_RSA`, `QKB_PROVER_WASM_URL_ECDSA`, `QKB_PROVER_ZKEY_URL_ECDSA`, `QKBRegistryV4 (UA) deploy`, `IdentityEscrowNFT deploy`. Env var names are external contracts (consumed by deploy scripts) — rename together. |

### F. Comments / docstrings / JSDoc (~120 occurrences)

These are NatSpec headers, JSDoc preambles, inline `//` comments referencing renamed symbols. Per the dispatch this bucket is "rename target follows the symbol they describe" — no separate enumeration needed. Sample, to verify the pattern:

- `packages/contracts/src/QKBRegistryV5_2.sol:34` — `/// @title  QKBRegistryV5_2 — V5.2 binding registry with on-chain keccak gate.`
- `packages/contracts/src/QKBRegistryV5_2.sol:35` — `/// @notice Implements \`IQKBRegistry\` (ABI-stable across V4↔V5↔V5.1↔V5.2;`
- `packages/contracts/src/QKBRegistryV5_2.sol:108` — `/// semantics that \`IdentityEscrowNFT\` and \`IQKBRegistry.isVerified()\``
- `packages/sdk/src/registry/registryV5_2.ts:1` — `// QKBRegistryV5.2 client-side types + calldata encoder.`
- `packages/sdk/src/registry/index.ts:6` — `* Draft QKBRegistryV4 bindings — policy-root successor surface.`
- `packages/contracts-sdk/src/IQKBRegistry.sol:4-15` — full NatSpec describing `IQKBRegistry`, `QKBRegistryV4/V5/V5.1/V5_2`, `IdentityEscrowNFT.isVerified()`.

`rg -n -i 'qkb|qie|identity\s*escrow' --type ts --type sol packages/ -g '*.sol' -g '*.ts' | wc -l` ≈ 1100 hits, dominated by code identifiers (B) + comments referencing them (F).

### G. CLAUDE.md / orchestration / spec / plan docs (56 files)

7 CLAUDE.md (root + 6 packages), all of `docs/superpowers/{specs,plans,handoffs,notes}/`, the marketing branding files, the evaluation. **Strategy:** rewrite all CLAUDE.md + `2026-04-29-v5-*` (current architecture) + `2026-05-03-*` (latest) docs to use `zkqes` throughout. Older specs / plans (`2026-04-17-*`, `2026-04-18-*`, `2026-04-19-*`, `2026-04-23-*`, `2026-04-24-*`, `2026-04-27-*`) are historical and likely safer to leave with QKB/QIE language + add a "rename note" header — they reference the old structural names because that's what existed at the time.

#### G.1 CLAUDE.md (7)

| File | Hits | Notes |
|---|---:|---|
| `CLAUDE.md` (root, the orchestration playbook) | 27 | Worker table at lines 24-28 references `packages/qie-{core,agent,cli}` + `packages/web` + `packages/contracts` etc. with `feat/qie-*` Phase 2 branches — the whole Phase 2 column is QIE-flavored. Also lines 213-214 the phase status. **Lead-owned**; significant rewrite if §3.Q2 = delete (drop the `qie-eng` row entirely + Phase 2 column). |
| `packages/circuits/CLAUDE.md` | 38 | All zkey + circuit invariants. circuits-eng-owned. |
| `packages/contracts/CLAUDE.md` | 67 | Heaviest CLAUDE.md hit. Title `# @qkb/contracts — Solidity for Qualified Key Binding + Qualified Identity Escrow` (line 1). contracts-eng-owned. |
| `packages/lotl-flattener/CLAUDE.md` | 11 | Light. flattener-eng-owned (mine). |
| `packages/qie-agent/CLAUDE.md` | 25 | Probably gone if §3.Q2 = delete. |
| `packages/qkb-cli/CLAUDE.md` | 37 | Renames in lockstep with `packages/qkb-cli/` rename. |
| `packages/web/CLAUDE.md` | 48 | web-eng-owned. |

#### G.2 Specs — `docs/superpowers/specs/` (17)

| File | Hits | Recommended treatment |
|---|---:|---|
| `2026-04-17-qkb-phase1-design.md` | 41 | Historical — keep + rename header note. |
| `2026-04-17-qie-phase2-design.md` | 71 | Historical. Move to `docs/superpowers/research/parked/` if §3.Q2 = delete. |
| `2026-04-17-qie-mvp-refinement.md` | 17 | Same. |
| `2026-04-18-person-nullifier-amendment.md` | 7 | Historical. |
| `2026-04-18-split-proof-pivot.md` | 9 | Historical. |
| `2026-04-19-qkb-cli-design.md` | 15 | Historical. |
| `2026-04-23-qkb-binding-v2-policy-root.md` | 20 | Historical. |
| `2026-04-24-per-country-registries-design.md` | 26 | Historical. |
| `2026-04-27-prod-frontend.md` | 67 | Historical. |
| `2026-04-27-trustless-eidas.md` | 30 | Historical (trustless-eIDAS deferred per CLAUDE.md memory). |
| `2026-04-29-v5-architecture-design.md` | 41 | **Current canonical V5 spec.** Full rename. |
| `2026-04-30-issuer-blind-nullifier-contract-review.md` | 23 | Current. Full rename. |
| `2026-04-30-wallet-bound-nullifier-amendment.md` | 55 | Current. Full rename — and the amendment defines the consensus-critical `"qkb-personal-secret-v1"` etc. tags (§3.Q3). |
| `2026-05-01-keccak-on-chain-amendment.md` | 3 | Current. Full rename. |
| `2026-05-01-keccak-on-chain-contract-review.md` | 10 | Current. Full rename. |
| `2026-05-03-qkb-helper-design.md` | 45 | Current — design for `qkb serve` (renamed `zkqes serve`?). Full rename. |
| `2026-05-03-v5_3-oid-anchor-amendment.md` | 11 | Current. Full rename. |

#### G.3 Plans — `docs/superpowers/plans/` (38)

I won't enumerate each — counts are in `/tmp/zkqes-rename/file-counts.txt`. Same treatment as specs: anything dated `2026-04-29-*`, `2026-04-30-*`, `2026-05-01-*`, `2026-05-03-*` is current and gets a full rename; older plans (especially `2026-04-17-qie-*`, `2026-04-17-qkb-*`, `2026-04-18-split-proof-*`, `2026-04-18-landing-page.md`) are historical and likely just need a header note.

Heaviest plan files by hit count:
- `2026-04-27-prod-frontend.md`: 341
- `2026-04-17-qie-qie.md`: 191
- `2026-04-24-per-country-registries.md`: 173
- `2026-04-27-trustless-eidas.md`: 148
- `2026-04-17-qie-mvp-refinement.md`: 136
- `2026-04-29-v5-architecture-circuits.md`: 107

#### G.4 Handoffs / notes (5 + 1)

`docs/handoffs/2026-04-30-{circuits,contracts,fly,web}-eng-summary.md` + `2026-05-03-v5_2-browser-prove-benchmark.md`. Historical handoffs — header note only, don't sweep body text.

`docs/superpowers/notes/2026-04-29-v5-circuits-eng-§6-0a-checkpoint.md`. Same.

#### G.5 Evaluation

`docs/evaluations/2026-04-29-keccak-on-chain-pivot-PARKED.md`: 2 hits, header note only.

### H. Already-immutable (DO NOT REWRITE)

1. **Git tags (8):** `v0.1.0-phase1`, `v0.2.0-phase2`, `v0.2.0-phase2-mvp-split-proof-stubs`, `v0.5.1-pre-ceremony`, `v0.5.2-pre-ceremony`, `v0.5.3-pre-ceremony`, `v0.5.4-cli`, `v0.5.5-pre-ceremony`. Lead's note said 5 V5.x tags; with the `phase1` + `phase2` tags it's 8. None get rewritten.
2. **All prior commit messages** — keep verbatim. Future commit log will start using `zkqes` after the rename merge lands.
3. **Schema `"$id"` URLs** in `fixtures/schemas/qkb-binding-v2-core.schema.json:3`, `qkb-binding-v2.schema.json:3`, `qkb-policy-leaf-v1.schema.json:3` are URL-shaped identifiers; downstream JSON-Schema validators look them up. **Suggest:** keep the `"$id"` URL pointing at `identityescrow.org/schemas/...` and 301-redirect to the new domain. The schema *filename* and the schema *body strings* (e.g. `"const": "qkb-binding-core/v1"`) are §3.Q3 (consensus-critical).
4. **R2 object keys already published** under `prove.identityescrow.org/{ecdsa-chain,age,ua-leaf-v4,ua-leaf-v4-v2}/...` — these are referenced from `fixtures/circuits/{chain,age,ua}/urls.json` for V3/V4 verifier flows still on Sepolia (V3/V4 contracts). **Suggest:** leave the V3/V4 ceremony URLs at the current host indefinitely; only V5 ceremony artifacts go to `prove.zkqes.org`.
5. **`v5_2-browser-prove-benchmark.md`** + the V5.1 benchmark `packages/circuits/benchmarks/v5_1-browser-fullprove-2026-05-01.md` are historical measurement records — header note only.

### I. Edge / ambiguous (founder questions queued in §3)

- I.1 — `IdentityEscrowNFT` rename target (§3.Q1)
- I.2 — QIE packages: delete or rename (§3.Q2)
- I.3 — Domain-separation tags: rename or freeze (§3.Q3) — **biggest single decision**
- I.4 — Schema `"$id"` URLs (§3.Q4)
- I.5 — `prove.identityescrow.org` R2 bucket migration (§3.Q5)
- I.6 — GitHub repo + org names: `alik-eth/identityescroworg`, `qkb-eth/identityescroworg`, `qkb-eth/homebrew-qkb`, GHCR `identityescroworg/qkb-ceremony` (§3.Q6) — confusingly there are *three* org names already in use as placeholders
- I.7 — CLI binary name: `qkb` → `zkqes`? (§3.Q7)
- I.8 — `fly.toml` `app = "identityescrow"` rename to `app = "zkqes"` requires Fly.io app rename + DNS re-attach
- I.9 — `qkb-bot` git author + `bot@identityescrow.org` git email
- I.10 — `qkb-eth` GitHub org placeholder for npm? Should it be `zkqes`, `zkqes-org`, `zkqes-eth`?
- I.11 — `_test-helpers/build-synth-cades.ts` and `packages/circuits/test/helpers/build-synth-cades.ts` — internal-only, follow whatever pattern QKB→zkqes uses
- I.12 — `pkAddress.ts` mentions `qkb` in CLAUDE.md preamble only — internal
- I.13 — `docs/qie/` user-visible operational + legal docs
- I.14 — `fixtures/qes/admin-binding.qkb.json` — fixture file name. The body contains `"version":"QKB/1.0"` (a versioned schema discriminator — see §3.Q3).
- I.15 — `fixtures/circuits/age/urls.json` references `prove.identityescrow.org/age/age_final.zkey` — keep at old domain for V3/V4? (see H.4)
- I.16 — `packages/web/test/fixtures/qkb-cli-0.5.2-pre.tgz` — vendored CLI tarball. Rename in lockstep with `packages/qkb-cli/` rename (bucket C.1) AND `@qkb/cli` package name (D).
- I.17 — `feat/qie-*` branches in remote `origin/feat/qie-circuits` etc. — Phase 2 branches that may or may not survive the rename. Lead's call.

---

## 2. Collisions / file-system conflicts

None of the suggested rename targets (`Zkqes*` for `QKB*`, `Izkqes*` for `IQKB*`, `zkqes*` for `qkb*`, `zkqes-cli` for `qkb-cli`) collide with any existing path or symbol in the worktree. Verified via:

```bash
rg -i 'zkqes' --type-not lock 2>/dev/null | wc -l
```

→ ~50 hits, all in BRAND.md / docs / i18n keys (`zkqes.umbrellaHeading`) / `zkqes.org` URLs / docs.zkqes.org config / GitHub workflows that already reference the new domain. None are filesystem paths or Solidity/Circom/TS top-level symbols.

The one near-collision: the i18n namespace `zkqes.*` in `packages/web/src/i18n/{en,uk}.json` (added during Task #21 branding work) already exists. Keys like `zkqes.umbrellaHeading` are good as-is, but if the rename now folds the "Identity Escrow umbrella" into "zkqes" at the noun level, the *value* of `umbrellaBody` needs a copy rewrite (it currently distinguishes between "QKB the protocol" and "Identity Escrow the project", which is the distinction being collapsed).

---

## 3. Key questions for founder

### Q1 — `IdentityEscrowNFT.sol` → ?

The contract is an ERC-721 minted on successful `register()` to a verified holder. It represents an on-chain attestation of the QES-anchored identity binding. It's not strictly an "escrow" in the threshold-recovery sense (that was QIE Phase 2, parked). Lead's lean is `ZkqesCertificate.sol`. Other options:

- `ZkqesCertificate` (cleanest semantically; matches what it actually is) — **recommend**
- `ZkqesCredential`
- `ZkqesNFT`
- `ZkqesBindingNFT`
- `BindingNFT`

Same Q resolves the `identityEscrowNftAbi` SDK export, the `scripts/sync-deployments.mjs` field name, the test file rename, and the i18n strings (`packages/web/src/i18n/en.json:157` etc.).

### Q2 — QIE packages: delete or rename?

`packages/qie-{core,agent,cli}` + `deploy/mock-qtsps/` + `docs/qie/` + `fixtures/qie/` are the Phase 2 escrow scaffolding. CLAUDE.md memory `project_split_proof_pivot` parked Phase 2. Lead's lean is **delete entirely**. Trade-offs:

- **Delete** (recommended): removes ~70 files of dead code, reduces every bucket's blast radius, simplifies the worker team (drop `qie-eng` from CLAUDE.md). Risk: if Phase 2 ever resumes, restore from git history (which is fine; the design is in spec docs, not just the code).
- **Rename to `@zkqes/escrow-*`**: keeps the option open at trivial cost. Risk: dead code rots silently and adds CI burden; the code already has the QIE-specific assumptions baked in (PRIVACY mode, threshold-Shamir, etc.) that the spec keeps amending.

The `packages/web/Dockerfile` + `Dockerfile.web` (root) + `pages.yml` workflow + `packages/web/package.json` consume `@qkb/qie-core` and `@qkb/qie-agent/browser` at build time. Need to verify whether the SPA actually imports from those at runtime or whether it's vestigial. If runtime imports exist, deletion needs a stub or rip-out PR before the rename pass.

**Concrete check before answering Q2:**
```bash
rg -n "from\s+'@qkb/qie-(core|agent)" packages/web/src 2>/dev/null
```
(I didn't run this — left for the dispatch following this report so the founder has a clean number when deciding.)

### Q3 — Domain-separation tags: rename or freeze?

The following string literals are hashed (keccak256 / SHA-256 / Poseidon) into circuit-public, contract-stored, or off-chain deterministically-derived values:

| Tag | Used in | What changes if renamed |
|---|---|---|
| `"qkb-rotate-auth-v1"` | `keccak256(tag ‖ chainId ‖ registry ‖ fingerprint ‖ newWallet)` for rotation-auth signature gate | Every in-flight rotation signature (none yet, since Sepolia not deployed) |
| `"qkb-personal-secret-v1"` | EOA `personal_sign(tag + …)` IKM for `walletSecret` derivation | Every existing `walletSecret` → every existing nullifier → every existing on-chain registration |
| `"qkb-id-fingerprint-v1"` | `FINGERPRINT_DOMAIN` in V5 circuit (field-element constant baked into r1cs) | Requires re-compile of V5.2/V5.3 circuit, re-ceremony, re-everything |
| `"qkb-walletsecret-v1"` (SCW) | SHA-256 salt for SCW-path walletSecret | Same as above |
| `"qkb-v5-walletsecret"` (HKDF) | HKDF salt | Same |
| `"qkb-binding-core/v1"` | Schema discriminator embedded in the JCS-canonicalized binding | Every existing `.qkb.json` binding fixture invalidated |
| `"qkb-policy-leaf/v1"` | Same | Every policy-leaf fixture |
| `"QKB/2.0"`, `"QKB/1.0"` | `version` field in binding JSON | Same |
| `"qkb-default-ua"` | UA policyId in `fixtures/declarations/ua/policy-v1.json` | Trust-root regeneration |
| `"qkb-v4-policy-root/v1"`, `"qkb-v4-trust-root/v1"`, `"qkb-v4-ua"`, `"qkb-v4-ceremony-urls/v1"` | Schema discriminators in V4 fixtures | V4 historical artifacts |
| `"qkb-circuit-artifacts-v1"` | Browser CacheStorage namespace | Cache miss → re-download on first visit (low-risk) |
| `"qkb-witness/v1"`, `"qkb-tsl-update-witness/v1"`, `"qkb-helper@<semver>"` | Local IPC schemas | Both ends rename together |
| `qkb-v5-final.zkey`, `qkb-v5_2-stub.zkey` family | R2 object key + filename | Republish (cheap, none uploaded) |

**Recommendation:** freeze the consensus-critical 9 tags (`qkb-rotate-auth-v1`, `qkb-personal-secret-v1`, `qkb-id-fingerprint-v1`, `qkb-walletsecret-v1`, `qkb-v5-walletsecret`, `qkb-binding-core/v1`, `qkb-policy-leaf/v1`, `QKB/2.0`, `qkb-default-ua`) as protocol constants — they were chosen at design time, never published in a way users can see, and renaming them would force a circuit re-compile + ceremony re-run + every fixture regenerated. Rename only the cosmetic 4 tags (`qkb-circuit-artifacts-v1`, `qkb-witness/v1`, `qkb-tsl-update-witness/v1`, the zkey filename family) where renaming is free.

If the founder wants a clean slate (no `qkb` substring anywhere in protocol bytes), the cost is roughly +1 day of circuits-eng + contracts-eng + flattener-eng coordinated work plus a fresh stub-ceremony pass.

### Q4 — Schema `"$id"` URLs

`fixtures/schemas/qkb-binding-v2-core.schema.json:3`: `"$id": "https://identityescrow.org/schemas/qkb-binding-v2-core.schema.json"` — same shape for two other schema files. JSON-Schema validators may dereference. **Suggest:** keep the URL as-is and 301-redirect at the host level once `identityescrow.org` becomes an alias for `zkqes.org`. Confirm.

### Q5 — `prove.identityescrow.org` R2 bucket

The R2 bucket is named `prove-identityescrow-org` per `scripts/ceremony-coord/.env.example:7`. R2 buckets are not renameable in place — migration is "create new bucket + copy objects + repoint DNS". For V5 ceremony (about to start), creating fresh `prove-zkqes-org` bucket from scratch is cheap. For V3/V4 historical artifacts already at `prove.identityescrow.org/{ecdsa-chain,age,ua-leaf-v4,ua-leaf-v4-v2}/`, leaving the old bucket in place permanently is also cheap. **Suggest:** new bucket for V5+, old bucket frozen as historical mirror. Confirm.

### Q6 — GitHub repo + org names

Three org placeholders are currently in source:

- `alik-eth/identityescroworg` (in `docs/.vitepress/config.mts:260`, `docs/contributing/index.md`, `docs/superpowers/plans/2026-04-18-landing-page.md`)
- `qkb-eth/identityescroworg` (in Homebrew formula, `release-cli.yml`, marketing drafts)
- `identityescroworg/qkb-ceremony` (GHCR — in `release-cli.yml`, all Fly cookbooks, web fly launcher form)
- `qkb-eth/homebrew-qkb` (Homebrew tap, in `release-cli.yml:120`)

What's the canonical post-rename layout? Suggested:
- Source repo: rename to `zkqes/zkqes` or keep `alik-eth/identityescroworg` and add 301 (lead's earlier note says "5 V5.x tags exist on origin and stay as immutable historical record")
- npm scope: `@zkqes/*` (founder needs to claim before rename PR lands — pre-flight check)
- GHCR: `zkqes/zkqes-ceremony`
- Homebrew tap: `zkqes/homebrew-zkqes`

Confirm each.

### Q7 — CLI binary name

Lead's lean: `zkqes serve`. Affects:
- Homebrew formula `bin.install binary_name => "qkb"` → `=> "zkqes"`
- npm `bin` entry in `packages/qkb-cli/package.json`
- Every `qkb serve`, `qkb cache`, `qkb status`, `qkb version` reference in i18n + docs + browser CliBanner.tsx + useCliPresence.ts (the SPA's CLI presence detection probes a fixed user-agent / origin pin — needs to match the new binary name)

Confirm.

---

## 4. Recommended dispatch order (lead's call, surfaced for context)

A multi-worker rename pass after the founder answers §3.Q1–Q7:

1. **Foundation pass (lead)** — root `package.json` rename, `pnpm-workspace.yaml` (no edit if globs intact), root `CLAUDE.md`, `BRAND.md`, root `README.md`, root `Dockerfile.web`, `Caddyfile` (no edit), root `.env.example`, root `package.json` `"flatten"` script ref. Update `pnpm-lock.yaml` once at the end.
2. **Parallel worker dispatches:**
   - **flattener-eng**: `packages/lotl-flattener/` `package.json` name + CLAUDE.md + README; nothing else in the package body has `qkb`/`qie`/`identityescrow` tokens of consequence.
   - **circuits-eng**: 8 Circom file renames + 8 template renames + every reference + ceremony scripts (`stub-v5*.sh`) zkey filename family + `packages/circuits/CLAUDE.md` + circuit benchmarks dir naming (none); plus regenerate stub artifacts so `Groth16VerifierV5_2Stub.sol` / `verification_key.json` match new naming if §3.Q3 = freeze (they don't touch protocol bytes). If §3.Q3 = rename, full re-compile cycle.
   - **contracts-eng**: 24 source/test/script Solidity file renames + every contract/library/interface decl + every deploy script + `IdentityEscrowNFT` resolution per §3.Q1 + `MIGRATION.md` + CLAUDE.md.
   - **web-eng**: 4 SDK ABI file renames + every `qkbRegistry*Abi` import sweep + `LandingHero.tsx` + i18n en.json + i18n uk.json + 6 routes (`ua/cli`, `ua/mint`, `ua/submit`, `ceremony/contribute`, `ceremony/status`, `ceremony/verify`) + every component referring to `IdentityEscrowNFT` (§3.Q1) + Dockerfile + fly.toml + `index.html` + `404.html` + `PRIVACY.md` + CLAUDE.md.
3. **CI + ceremony-coord + cookbooks (lead)** — `.github/workflows/{pages,pages-docs,release-cli}.yml`, `scripts/ceremony-coord/{*,cookbooks/fly/*}`, `scripts/{dev-chain.sh,sync-deployments.mjs}`, GHCR repo creation.
4. **Docs sweep (lead)** — `docs/superpowers/specs/{2026-04-29,2026-04-30,2026-05-01,2026-05-03}-*.md` (current spec corpus), `docs/superpowers/plans/{same date prefixes}`, `docs/marketing/2026-05-03-*` (delete or supersede), `docs/.vitepress/config.mts`, `docs/cli-release-homebrew/Formula/qkb.rb` (rename file), `docs/cli-release.md`, `docs/release-notes/*`, `docs/integrations.md`, `docs/index.md`. Older specs/plans get a header note only.
5. **QIE deletion** (if §3.Q2 = delete) — drop `packages/qie-{core,agent,cli}/`, `deploy/mock-qtsps/`, `docs/qie/`, `fixtures/qie/`, drop `qie-eng` row from CLAUDE.md, update `pnpm-workspace.yaml` if specific package paths listed (currently glob-based, no edit), drop CI build steps.
6. **Tag + release** — `v0.6.0-zkqes-rename` annotated tag, CHANGELOG entry, force CI green.

Estimated total worker hours, assuming §3.Q3 = freeze: **~16 worker-hours** wall-clock spread across 4 workers in parallel = 4-5 calendar hours active dispatch + 2 hours lead-side review + 2 hours docs sweep ≈ **1 day**.

If §3.Q3 = rename (consensus-critical tags too): **+ 8 worker-hours** for circuits-eng (re-compile) + ~4 hours for contracts-eng (test fixture regeneration) + 4 hours flattener-eng (root.json regen) ≈ **+1 day**.

---

## 5. What this report does NOT decide

- Translator wording for the 22 i18n strings in `en.json` + 21 in `uk.json` — translator pass after founder confirms §3.Q1–Q7.
- Whether to keep `identityescrow.org` as a permanent 301 alias (BRAND.md says yes; founder may flip).
- The exact PR shape: one mega-PR, four parallel worker PRs into a chore branch, or rolling merges. Lead's call.
- Whether the rename PR also closes Task #66 outright or whether some residue (rename of immutable artifacts post-Sepolia) lingers.
