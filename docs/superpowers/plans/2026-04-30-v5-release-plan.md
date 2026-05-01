# V5 Release Plan — Phases A through E

**Date:** 2026-04-30
**Status:** Drafted post-A1-implementation-complete
**Spec:** [`2026-04-29-v5-architecture-design.md`](../specs/2026-04-29-v5-architecture-design.md) at HEAD `def6270`
**Predecessor:** A1 V5 architecture (functionally complete; circuit + SDK + web + contracts + flattener all green)
**Total wall estimate:** ~3-4 weeks to Sepolia public launch · ~5-6 weeks to Base mainnet

---

## Overview

V5 architecture implementation is complete. What remains is the production rollout sequence: trusted-setup ceremony → live deploy → acceptance gate → frontend cutover → public launch. This plan covers the path from "implementation done" to "public launch on Sepolia," with mainnet as a separately-gated follow-on (Phase F).

The critical path runs through the multi-contributor Phase 2 ceremony (1-2 weeks), which the founder will recruit personally. Everything else is bounded engineering work.

```
Phase A (prep, parallel, ~5 days)
        │
        ▼
Phase B (ceremony, ~1-2 weeks wall)
        │
        ▼
Phase C (deploy, ~2-3 days)
        │
        ▼
Phase D (acceptance gate, ~1 day)
        │
        ▼
Phase E (cutover + launch, ~3-5 days)
        │
        ▼
[Sepolia public stable ≥ 1 week]
        │
        ▼
Phase F (Base mainnet, separately gated)
```

---

## Phase A — Pre-ceremony prep

**Goal:** Stand up coordination infrastructure + recruit ceremony contributors. Block before kicking off Phase B.

**Wall estimate:** 3-5 days, all tasks parallel-able.

### A1. /ceremony coordination page (web-eng)

- Owner: `web-eng`
- Tracker: Task #27 (in flight)
- Deliverables:
  - 4 routes: landing / contribute / status / verify
  - Civic-monumental aesthetic, EN + UK i18n
  - PC-flow instructions with copy-buttons (32 GB RAM requirement explicit)
  - Tri-state JSON-backed status feed (polled from R2 every 30s)
  - Browser-side sha256 verify-post-ceremony (Web Worker via `@noble/hashes`)
  - Playwright e2e for three states (not-started / in-progress / complete)
- Acceptance: 4/4 routes render civically on desktop + flagship mobile, all PC commands have copy-buttons, status JSON tri-state handled cleanly, Playwright green.

### A2. R2 ceremony bucket + coordination scripts (lead)

- Owner: `team-lead`
- New task to create
- Deliverables:
  - R2 bucket `prove.identityescrow.org/ceremony/` with public-read on artifacts + signed-write for uploads
  - Per-round signed upload URL generator script
  - Per-round download URL publisher
  - `status.json` publisher (admin updates manually after each contribution lands)
  - Per-contribution verification script: `snarkjs zkey verify` against the previous chain link
  - Round-0 zkey (admin's own contribution as the chain seed)
- Acceptance: signed-URL upload round-trips successfully with a test 2.2 GB file; verification script catches a tampered zkey; status.json renders correctly in web-eng's `/ceremony/status`.

### A3. Contributor recruitment (founder-driven)

- Owner: `founder` (handled personally)
- Out of scope for engineering team
- Target: 7-10 trusted core contributors
- Likely outreach pool: PSE, 0xPARC, Mopro, Anon Aadhaar team, Polygon ID, Worldcoin alumni, Lambdaclass, ETH Kyiv, individual ZK researchers
- No formal task; founder reports back when contributor list is confirmed
- Phase B can begin with as few as 5 confirmed contributors; later contributors can join mid-chain

### A4. Ceremony copy + tease tweet (marketer)

- Owner: `marketer`
- New task to dispatch
- Deliverables:
  - Sign-up email template (founder uses verbatim or adapts per contact)
  - Twitter/X announcement thread (separate from launch thread; goes out after 5+ contributors confirmed)
  - One-line tease for the project's social profile
- Acceptance: drafts saved under `docs/marketing/2026-04-30-ceremony-drafts/`. No publishing pre-Phase-B-kickoff.

### Phase A gate to Phase B

- A1 shipped + Playwright e2e green (3/3 states)
- A2 shipped: signed-URL round-trip works + verification script catches tampered zkey
- A3: 5+ contributors confirmed (founder reports back)
- A4 drafts saved

---

## Phase B — Ceremony runs

**Goal:** Execute the 7-10 contributor Phase 2 ceremony. Produce final production zkey + auto-generated verifier.sol.

**Wall estimate:** 7-14 days. Sequential per contributor (1/day average), with admin verification between each.

### B1. Round-0 (lead's seed contribution)

- Owner: `team-lead` + `circuits-eng`
- Deliverables:
  - circuits-eng generates round-0 zkey from V5 main 4.02M-constraint R1CS + pot23 ptau (already done at §8 stub, but re-run for production canonical chain)
  - Lead applies admin entropy as round-0 contribution
  - Upload to R2 round-0 endpoint
  - Update status.json: round=1, totalRounds=N, contributors=[admin]
- Acceptance: round-0 zkey verifies against R1CS + ptau via `snarkjs zkey verify`; status.json published.

### B2. Per-contribution loop (B2.1 through B2.N, where N = ~7-10)

For each contributor in turn:

1. **Founder** notifies the contributor that their round is open (via DM with their signed-upload URL pre-filled)
2. **Contributor** runs the 4-command flow (download → contribute → verify → upload). ~15-20 min wall.
3. **Lead** verifies the uploaded zkey:
   - Verify against R1CS + ptau
   - Verify chain integrity (this contribution builds on previous)
   - Compute attestation hash
4. **Lead** publishes the contribution to status.json (name, attestation, completedAt)
5. **Lead** signals next contributor's round is open

If a contribution fails verification (rare — usually ABI mismatch or transmission error): lead requests re-do; doesn't break chain.

If a contributor goes silent for >48h: lead skips, founder recruits a replacement.

### B3. Beacon

- Owner: `team-lead`
- After last individual contribution lands:
  - Pin a future Ethereum block (typically +24h after last contribution)
  - When that block lands, use its hash as the final ceremony entropy via `snarkjs zkey beacon`
  - Publishes the beacon block height + hash + final zkey sha256
- Trust: beacon block hash is cryptographically committed before any participant could grind it; binds setup to public timestamp
- Acceptance: beacon block confirmed, final zkey sha256 published, beacon proof saved to repo

### B4. Finalize + publish artifacts

- Owner: `team-lead` + `circuits-eng`
- Deliverables to commit / publish:
  - `Groth16VerifierV5.sol` (auto-generated from final zkey, drop-in replacement for `Groth16VerifierV5Stub.sol`)
  - `verification_key.json`
  - `qkb-v5-final.zkey` uploaded to R2 production URL `prove.identityescrow.org/qkb-v5-final.zkey`
  - `zkey.sha256` integrity reference
  - Attestation chain (every contributor + their hash) committed to `packages/circuits/ceremony/v5/contribution-log.md`
  - Beacon attestation: `packages/circuits/ceremony/v5/beacon-attestation.md`
- Acceptance: `groth16.verify` succeeds against final zkey + sample (witness, public, proof) triple; verifier.sol forge-compiles; all artifacts public.

### Phase B gate to Phase C

- All N rounds verified + published in status.json
- Beacon applied + verified
- Final zkey + verifier.sol + verification_key.json published
- Attestation chain complete
- Final zkey forge-builds against the V5 register contract test suite (smoke check before live deploy)

---

## Phase C — Post-ceremony deploy (Base Sepolia)

**Goal:** Live-deploy V5 contracts to Base Sepolia with the production verifier.

**Wall estimate:** 2-3 days, mostly sequential within the deploy itself.

### C1. Pump real Groth16VerifierV5.sol (lead)

- Owner: `team-lead` + `circuits-eng`
- Pump from `arch-circuits/packages/circuits/ceremony/v5/Groth16VerifierV5.sol` to `arch-contracts/packages/contracts/src/Groth16VerifierV5.sol`
- Replaces existing `Groth16VerifierV5Stub.sol`
- Single commit on `feat/v5arch-contracts`
- Acceptance: contracts-eng's full forge test suite passes against the new verifier.

### C2. Real-Diia LOTL reflatten (flattener-eng)

- Owner: `flattener-eng`
- Re-run flattener against current EU LOTL snapshot
- Compute `INITIAL_TRUST_ROOT` for deploy
- Compute `INITIAL_POLICY_ROOT` (V5 default policy leaf hash)
- Pump fresh `trusted-cas.json` + `root.json` to deploy fixtures
- Acceptance: deterministic root regen succeeds; values match what circuits-eng's witness builder expects.

### C3. Base Sepolia broadcast deploy (contracts-eng)

- Owner: `contracts-eng`
- Tracker: Task #15
- Pre-deploy checklist:
  - Admin wallet funded with Base Sepolia ETH (≥ 0.001 ETH per dry-run estimate; more is safer)
  - Env vars set: `PRIVATE_KEY`, `BASESCAN_API_KEY`, `BASE_SEPOLIA_RPC_URL`, `INITIAL_TRUST_ROOT` (from C2), `INITIAL_POLICY_ROOT` (from C2), `MINT_DEADLINE` (Unix seconds, ≥ 6 months out)
- Deploy:
  ```
  forge script script/DeployV5.s.sol:DeployV5 \
    --rpc-url $BASE_SEPOLIA_RPC_URL \
    --broadcast --verify \
    --etherscan-api-key $BASESCAN_API_KEY \
    -vv
  ```
- Post-deploy:
  - Capture deployed addresses
  - Verify on Basescan (PoseidonT3/T7 will need bytecode-only manual verification — flagged in contracts-eng's Task 15 prep)
  - Tag the deploy commit `v0.5.0-base-sepolia`
- Acceptance: all 4 contracts deployed (Groth16VerifierV5, QKBRegistryV5, IdentityEscrowNFT, plus PoseidonT3/T7 sub-contracts), all verified on Basescan.

### C4. Pump deployment fixtures (lead)

- Owner: `team-lead`
- Write `fixtures/contracts/base-sepolia.json` with deployed addresses
- Pump to web-eng worktree (`packages/sdk/src/deployments.ts` baseSepolia entry)
- Pump to flattener-eng + circuits-eng for awareness
- Acceptance: web-eng's V5 register flow can resolve `registryV5` address from `deployments.ts`.

### C5. Pump zkey + verifier URLs (web-eng)

- Owner: `web-eng`
- Update `circuitArtifacts.ts` with R2 production zkey URL (`prove.identityescrow.org/qkb-v5-final.zkey`)
- Pump `verification_key.json` from final ceremony to `packages/sdk/fixtures/v5/` (replacing stub)
- Real-fullProve E2E test (deferred from Task 13): wire up `e2e:real-prover` invocation that pulls real zkey, runs full prove, asserts byte-equality against the ceremony's final sample-proof
- Acceptance: real-prover E2E passes against live R2 zkey; SDK + web tests still green.

### Phase C gate to Phase D

- Deploy successful + verified on Basescan
- Fixtures pumped to all consumer worktrees
- Real-prover E2E green
- Admin wallet has remaining gas (for the founder dry-run in Phase D)

---

## Phase D — §9.4 acceptance gate

**Goal:** Hard gate before public launch. Cross-package smoke against live Base Sepolia, validates every spec acceptance criterion.

**Wall estimate:** ~1 day, lead-driven, multi-device.

### D1. Founder dry-run (lead + founder)

- Owner: `team-lead` + `founder`
- Tracker: Task #18
- Sequence:
  1. Founder generates fresh Diia QES on QKB/2.0 binding (real Diia mobile app)
  2. Pumps `.p7s` to laptop
  3. Visits `https://identityescrow.org/ua/registerV5` (still on Fly during Phase D — GH Pages migration is Phase E)
  4. Connects wallet (Sepolia)
  5. Generates V5 binding via Step 2 → witness via build-witness-v5 → proof via SnarkjsWorkerProver against real zkey
  6. Submits register tx → captures hash
  7. Visits `/ua/mint` → mints IdentityEscrowNFT №1 → captures hash
- Captures:
  - Register tx hash + gas used (must be ≤ 2.5M per spec)
  - Mint tx hash
  - Decoded `tokenURI(1)` SVG (must render civic-monumental certificate with real nullifier)
- Acceptance: full flow succeeds end-to-end; gas under cap; SVG renders correctly.

### D2. Multi-browser desktop smoke

- Owner: `team-lead`
- Repeat the founder flow's connect-and-prove path (mock-prover OK for repeat) on:
  - Chromium (latest)
  - Firefox (latest)
  - Safari (macOS, latest)
- Acceptance: 3/3 browsers complete the prove + register UX without errors. Doesn't need to actually broadcast (one register per nullifier — keep the founder's as the canonical first mint).

### D3. Mobile-browser flagship-gate validation

- Owner: `team-lead`
- Per spec acceptance criterion: full prove flow on Pixel 9 (Android 14+, Chrome 120+) AND iPhone 15 (iOS 17+, Safari) with `navigator.storage.persist()` granted.
- Out-of-gate device validation: confirm rerouting UX on:
  - Mid-range Android (UA-string-stub'd or real device)
  - iOS in-app WebView (Telegram or Instagram)
  - Older browser (Chrome 110, Safari 16)
- Acceptance: flagships complete the prove flow (or skip prove via mock — the gate is about the page reaching prove without OOM, not necessarily completing the multi-minute compute on phone). Out-of-gate devices reroute to `/ua/use-desktop` cleanly.

### D4. Soundness regression suite

- Owner: `team-lead`
- Run the full V5 acceptance regression suite per spec §Acceptance criteria:
  - Self-controlled `intSpki` paired with trusted-list entry → `BAD_TRUST_LIST`
  - Same nullifier registered to two wallets → second tx reverts `NULLIFIER_USED`
  - Binding with `policyLeafHash` not in policyRoot → `BAD_POLICY`
  - Mismatched `signedAttrs.messageDigest` vs binding → circuit fails to satisfy
  - Public-signal hash hi/lo limbs mismatched against calldata → `BAD_*_HI` / `BAD_*_LO`
  - SpkiCommit round-trip parity: leaf SPKI through contract `spkiCommit` matches circuit witness-side computation
- These are forge tests + e2e tests in respective packages; this gate just confirms they all run green against the live deploy state.
- Acceptance: 100% pass.

### Phase D gate to Phase E

- D1 success: founder mint #1 on Sepolia, captures published privately for launch reveal
- D2 + D3: cross-browser + flagship-mobile coverage clean
- D4: full regression suite green
- Critical: founder's mint is THE Sepolia launch artifact. From here, no more re-deploys to Sepolia (we don't want to invalidate this mint by replacing the registry).

---

## Phase E — Frontend cutover + public launch

**Goal:** Move frontend from Fly (currently scaled-to-0) to GitHub Pages on `identityescrow.org`. Execute public launch sequence.

**Wall estimate:** 3-5 days, parallel-able sub-tasks.

### E1. GitHub Pages migration (lead)

- Owner: `team-lead`
- Tracker: Task #17
- Deliverables:
  - GitHub Actions workflow `actions/deploy-pages` triggered on push to main + post-merge from `feat/v5arch-web`
  - Custom domain `identityescrow.org` configured (DNS already on Cloudflare; just CNAME to `<org>.github.io`)
  - Auto-issued Let's Encrypt cert via GH Pages
  - `coi-serviceworker` shim added if multithreaded snarkjs proving turns out to need `SharedArrayBuffer` (validate via desktop benchmark first; skip if single-threaded prove time is acceptable)
  - Fly app stays scaled-to-0 as ≥ 1-week rollback fallback
- Acceptance: `https://identityescrow.org/` returns 200 from GH Pages; HTTPS valid; multithreaded prove either works (with shim) or single-threaded path is documented; rollback to Fly is a 2-record DNS flip in CF.

### E2. Branding finalization (lead + founder)

- Owner: `founder` (decision) + `team-lead` (execution)
- Tracker: Task #21
- Founder decides:
  - Lock zk-QES (the protocol) vs Identity Escrow (the project) framing in spec / README / `BRAND.md`
  - Or leave at marketing-doc level only
- If locking: spec amendment + README update + marketer drafts updated to match
- Acceptance: framing decision made, propagated to all surfaces (or explicitly held at marketing-only).

### E3. Marketer drafts user review (founder)

- Owner: `founder`
- Tracker: Task #20
- Founder reads 6 drafts at `docs/marketing/2026-04-29-launch-drafts/`:
  - `positioning.md`, `launch-sequence.md`, `x-thread-launch.md`, `hn-post.md`, `faq.md`, `pre-launch-tease-1.md`
- Decides on:
  - Repo URL (currently placeholder `github.com/qkb-eth/identityescroworg`)
  - HN title pick (3 options offered)
  - Tease draft pick (A / B / C variants)
  - Audit framing terminology (currently "scope letter / pre-print / pending")
- Marketer applies decisions in a follow-up commit
- Acceptance: 6 drafts finalized; ready to publish on launch day.

### E4. Pre-launch tease (T-2 weeks before launch event)

- Owner: `founder`
- Single quotable paragraph from `pre-launch-tease-1.md`
- Posted to founder's existing social profile (X mainly)
- No product reveal — sets up the announcement to come
- Acceptance: tease lands; quotable; doesn't preempt the launch reveal.

### E5. Reveal (T-1 week before launch)

- Owner: `founder` + `marketer`
- Public spec reveal: the 2026-04-29 V5 architecture spec is published with ceremony attestation chain visible
- Repo public on GitHub (if not already)
- Open-source from day-one principle: README + LICENSE + CONTRIBUTING.md visible
- Acceptance: anyone can read the spec, browse the repo, verify the ceremony attestations, see the deployed contracts on Basescan.

### E6. Launch day

- Owner: `founder`
- Sequence (~1 hour):
  1. Founder mint #1 on Sepolia is already done from Phase D (or do it on launch day if you waited)
  2. Founder posts the launch X thread (10 tweets per `x-thread-launch.md` final)
  3. Founder posts to Hacker News with the agreed title from `hn-post.md`
  4. Founder posts to selected Ukrainian crypto Telegram / X channels per `launch-sequence.md`
  5. Status page on `/ceremony` shows complete chain; founder mint NFT visible on OpenSea testnet
- Acceptance: launch lands; community responds; first non-founder Ukrainian mint within 24-48h is the social proof gate.

### E7. Post-launch monitoring (T+1 week)

- Owner: `team-lead`
- Watch:
  - Mint count on Sepolia
  - Registry interaction telemetry
  - Any error reports (community channels, GitHub issues)
  - Mobile flagship-gate UX feedback (does the rerouting page work cleanly?)
- Triage gate to Phase F (mainnet): ≥ 1 week of stable Sepolia operation with no soundness or UX-breaking incidents
- Acceptance: 1-week soak completes without rollback or critical fixes.

### Phase E gate to Phase F

- 1-week Sepolia stable
- Founder mint visible + decoded SVG correct
- Audit complete OR explicit decision to ship without (audit terminology in marketing FAQ matches reality)
- No critical UX bugs surfaced by community

---

## Phase F — Base mainnet (separately gated)

**Goal:** Production mainnet deploy. Real ETH for gas, real money behind the registry.

**Wall estimate:** 1-2 days deploy + ongoing operations.

### F1. Mainnet deploy (contracts-eng)

- Same `DeployV5.s.sol` script, mainnet RPC + mainnet admin private key
- Pre-deploy: admin wallet funded with mainnet ETH (≥ 0.05 ETH); BASESCAN_API_KEY for verification; INITIAL_TRUST_ROOT + INITIAL_POLICY_ROOT same as Sepolia (or refreshed if EU LOTL rotated)
- Same `forge script ... --broadcast --verify`
- Tag: `v1.0.0-base-mainnet`
- Acceptance: 4 contracts deployed + verified.

### F2. Founder mint #1 on mainnet

- Owner: `founder`
- Real on-mainnet mint (the actual production launch event)
- Captures: register tx, mint tx, tokenURI(1) SVG
- These are the artifacts for the mainnet announcement
- Acceptance: NFT №1 minted to founder wallet; Basescan shows minted; OpenSea (mainnet) shows certificate.

### F3. Public mainnet announcement

- Owner: `founder` + `marketer`
- Updated launch thread + HN post pointing at mainnet
- Sepolia phase becomes the historical staging
- Acceptance: mainnet launch lives.

### F4. Gated by founder explicit go-ahead

Phase F is **NOT auto-triggered** by Phase E. Founder explicitly decides when to flip. This plan recommends ≥ 1 week Sepolia stable + audit closed (or documented as out-of-scope) before flipping.

---

## Risks + mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| Ceremony contributor goes silent mid-chain | Medium | 48h SLA per contributor; founder skips and recruits replacement; chain integrity unaffected |
| Beacon block reorg | Low | Use a 12-block-confirmed block hash; reorg risk on Ethereum L1 at 12+ confirmations is effectively zero |
| pot23 file actually pot28 (mislabeled) | Low | Verified at A2 setup time before round-0; if mismatch, re-fetch from canonical Hermez source |
| Mobile flagship gate fails on real Pixel 9 / iPhone 15 | Medium | Phase D flushes this; if either fails, narrow gate further (e.g., "Pixel 9 Pro only"), or surface as known limit and route everyone to desktop |
| Real-prover E2E fails with R2-hosted zkey | Low | Phase C5 catches this before Phase D; falls back to absolute-path zkey for now if R2 streaming is broken |
| Audit not complete by Phase F | High (likely) | Document as "audit pre-print pending" in launch copy + FAQ; keep Sepolia as the vetting ground |
| Community contribution to ceremony swamps coordination capacity | Low | Cap at 10 trusted core; Twitter call only after core is confirmed; can extend post-beacon if anyone wants to attest a derivative chain |

---

## Open decisions (founder-side)

These are the gating items not in any worker's scope:

1. **§11 ceremony go-ahead.** Required to enter Phase B.
2. **Recruitment list.** Founder-driven; report back when 5+ confirmed.
3. **Branding lock (#21).** zk-QES vs Identity Escrow framing in formal docs vs marketing-only.
4. **Marketer drafts review (#20).** 7 sub-decisions across 6 files.
5. **Pre-launch tease timing.** T-2 weeks before launch event; defines launch date countdown.
6. **Audit posture for launch.** Ship-without-audit + clear FAQ language, or hold for pre-print first.
7. **Mainnet flip (Phase F).** When (and whether) to graduate from Sepolia.

---

## Tracker references

| Phase | Tasks |
|-------|-------|
| A | #27 (web /ceremony page); A2 + A4 = new tasks at dispatch time |
| B | #8 (circuits §11 ceremony) |
| C | #15 (contracts Base Sepolia deploy); pumping = lead inline |
| D | #18 (Sepolia E2E §9.4 acceptance gate) |
| E | #17 (GH Pages migration); #20 (marketer drafts review); #21 (branding finalization); #19 (spec review — close) |
| F | New task at gate-flip time |

Closed tasks for the V5 architecture (1-26 sans pending): see team todo list.

---

## End-state

**Sepolia public launch (end of Phase E):**

- `https://identityescrow.org/` live on GH Pages
- V5 contracts deployed on Base Sepolia, all verified on Basescan
- Final production zkey on `prove.identityescrow.org/qkb-v5-final.zkey`
- 7-10 contributor ceremony attested + chain published
- Founder mint #1 visible on Sepolia
- Public spec + repo + LICENSE
- Launch thread + HN post + community channels live
- 1-week soak gate before Phase F

**Mainnet (end of Phase F):**

- Same end-state on Base mainnet
- Sepolia stays as historical staging
- Audit pre-print or completed audit attached to FAQ

That is V1 of the project.
