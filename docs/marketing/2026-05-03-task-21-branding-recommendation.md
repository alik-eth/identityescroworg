# Task #21 — Branding Recommendation

**Author:** marketer
**Date:** 2026-05-03
**Decision owner:** founder
**Surfaces touched if locked:** README.md, package.json, packages/*/CLAUDE.md, V5 spec body, BRAND.md (new), marketing drafts under `docs/marketing/`

---

## Honest preface

I owe a correction. My 2026-04-29 launch drafts locked **zk-QES + Identity Escrow** as the public framing because the founder DM'd me mid-dispatch with that pivot. In the four days since, canonical surfaces moved the other way and consolidated on **QKB + Identity Escrow + QIE**. My Codex review on 2026-05-01 flagged Codex's QKB/QIE usage as a "naming regression" — that claim is no longer correct. The Codex drafts are actually consistent with where the rest of the repo currently sits; my marketing drafts are the ones that drifted.

This document audits the surfaces, lays out three options honestly, and recommends one.

## Audit — where each name lives today

| Surface | Current taxonomy |
|---|---|
| `README.md` | Title `# QKB — Qualified Key Binding`; "project line is named **Identity Escrow**"; Phase 2 = QIE |
| `package.json` description | `QKB + QIE — Qualified Key Binding with Qualified Identity Escrow. Phase 1: QKB core.` |
| `packages/contracts/CLAUDE.md` | `# @qkb/contracts — Solidity for Qualified Key Binding + Qualified Identity Escrow` |
| Package names | `@qkb/web`, `@qkb/contracts`, `@qkb/sdk`, `@qkb/cli`, `@qkb/contracts-sdk` |
| Contract names | `QKBRegistry`, `QKBRegistryV5_1`, `QKBVerifier`, `IQKBRegistry`, `IdentityEscrowNFT` |
| Circuit names | `QKBPresentationV5.circom`, `BindingParseV2Core` |
| Spec corpus (16 files) | Uniformly `QKB` / `QIE` in titles, headers, body |
| V5 spec | Title `# V5 Architecture Design`; body uses `QKB` 30+ times; **does not** use the string "QKB Identity Escrow" anywhere |
| `BRAND.md` | does not exist |
| `docs/marketing/2026-04-29-launch-drafts/` | `zk-QES` (protocol) + `Identity Escrow` (project) |
| `docs/marketing/2026-04-30-ceremony-drafts/` | `zk-QES Phase 2 ceremony` |
| `docs/2026-05-01-{landing,ceremony,governance}*.md` (Codex) | `QKB` (V1) + `QIE` (Phase 2) |

**Net:** every canonical surface uses **QKB / QIE**. Only the marketing drafts I wrote use **zk-QES**. The drift is concentrated in `docs/marketing/`.

## The three options

### Option A — Lock QKB + Identity Escrow + QIE

Catch the marketing drafts up to where the rest of the repo already sits.

**Effort:** low. Sweep the nine marketing files (six launch drafts, three ceremony drafts) with a rename. Salvage Sections 4 + 9 of the Codex landing outline, fold them in. Leave README, package.json, specs, package names, contract names, circuit names untouched.

**Trade-off:** "QKB" is opaque to a first-time reader. "Qualified Key Binding" doesn't telegraph what the protocol does in two seconds the way "zk-QES" does. The HN post + X thread + landing eyebrow lose immediate legibility.

### Option B — Lock zk-QES + Identity Escrow (revert canonical surfaces)

Push the founder's 2026-04-29 DM directive through to every surface.

**Effort:** very high. Rename `@qkb/*` packages → `@zkqes/*` (or pick a scope), rename `QKBRegistry` → `ZkQesRegistry`, rename `QKBPresentationV5.circom`, sweep 16 specs, sweep 8+ CLAUDE.md files, update all import paths, regenerate ABIs, possibly invalidate the Phase 2 ceremony tooling that's currently mid-flight (#28, #42), force a contracts-eng re-deploy of test fixtures.

**Trade-off:** highest brand quality and clearest public-facing legibility, but the timing is terrible — V5.1 is `v0.5.1-pre-ceremony`-tagged and ceremony coordination is in progress (#8 pending, #15 gated on #8). A package-rename storm during ceremony recruitment risks contributor confusion and breaks pre-baked CLI commands at `/ceremony/contribute`.

### Option C — Hybrid: zk-QES public-facing, QKB internal codename

The standard internal-codename / public-brand split. Specs, packages, contracts, circuits, CLAUDE.md files all stay QKB. Public surfaces (README, landing page, marketing copy) lead with **zk-QES**. QIE stays the codename for the Phase 2 design line; "Identity Escrow" stays the public umbrella name for the project.

**Effort:** medium. Touch:
- `README.md` — rewrite the title + lede to lead with zk-QES, keep "QKB" as a parenthetical codename ("the V1 protocol, internally codenamed QKB").
- `package.json` description — rewrite.
- New `BRAND.md` at repo root — defines the split explicitly so future contributors know which name belongs where.
- Marketing drafts — already use zk-QES; no change.
- Codex landing outline — needs a rename pass plus the salvage of Sections 4 + 9.
- Specs, packages, contract names, circuit names — **untouched.** Engineers read codenames; that surface is engineer-facing.

**Trade-off:** the README has to teach the split once, then carry it. Outsiders briefly see two names ("zk-QES" in copy, "@qkb/*" in install commands) and have to register that they refer to the same thing. Industry precedent (WebKit/Safari, Chromium/Chrome, Project Athena/Kerberos) suggests this is well-tolerated.

## Recommendation: Option C

Three reasons:

1. **Codenames are structurally locked.** `@qkb/*` packages, `QKBRegistry*` contracts, and `QKBPresentationV5.circom` appear in ABIs, deploy fixtures, ceremony commands published at `/ceremony/contribute`, and contributor-facing CLI invocations. Renaming them mid-ceremony has high regression risk and zero functional benefit.

2. **Public-facing names should describe what the thing does.** "zk-QES" parses in two seconds for anyone who knows what a qualified electronic signature is. "QKB" requires an explanation. The launch arc is targeting ZK-literate readers (HN, X, Ukrainian crypto, eIDAS observers); they will all parse "zk-QES" instantly.

3. **The split is the cheapest reconciliation.** Marketing drafts already use zk-QES. README + package.json description + a new BRAND.md absorb the change. Specs and code stay where they are. The Codex landing outline rewrites cleanly under this taxonomy.

## Spec rename question (specifically asked in the brief)

> "Check whether the V5 spec name needs amendment from 'QKB Identity Escrow' → 'zk-QES V5'."

The V5 spec is currently titled `# V5 Architecture Design`. It does not use the string "QKB Identity Escrow" as a name anywhere in body. The brief's premise (that the spec is titled "QKB Identity Escrow") is not accurate against the current file.

Under Option C: spec stays `# V5 Architecture Design`; body keeps `QKB` as the codename. No rename.
Under Option A: same — no rename needed for the title.
Under Option B: title becomes `# zk-QES V5 Architecture Design` and body sweeps QKB → zk-QES.

## If C is picked, concrete next actions

1. Founder confirms C.
2. Marketer drafts a `BRAND.md` at repo root that defines the split explicitly (one page, civic-monumental voice, the canonical reference).
3. Marketer rewrites `README.md` title + lede + "Try it" + "Documents" sections to lead with zk-QES, keeping QKB as a parenthetical codename. README becomes the public-facing front door.
4. Marketer updates `package.json` description.
5. Marketer salvages Codex landing outline (Sections 4 + 9) and writes a proper landing-page outline under `docs/marketing/`.
6. Codex governance note remains rejected on its own merits (unsanctioned scope, not a naming issue) — Task #21 doesn't unblock it.
7. Tracker #21 closes.

If A is picked, concrete next actions are simpler: marketer sweeps `docs/marketing/` for `zk-QES` → `QKB` and `Identity Escrow (project)` → `QKB / Identity Escrow / QIE` per README phrasing.

If B is picked, this becomes a multi-worker rename storm and should be split into a separate orchestration plan, not folded into Task #21.

## What this does not address

- The Codex governance bootstrap note is a scope problem, not a naming problem. It stays rejected regardless of which taxonomy wins.
- File placement of the Codex drafts (`docs/` rather than `docs/exploratory/`) is a separate hygiene call; flag remains live.
