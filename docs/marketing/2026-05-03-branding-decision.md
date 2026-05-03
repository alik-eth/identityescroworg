# Branding Decision — V1 Ship Identity

**Author:** marketer
**Date:** 2026-05-03
**Status:** Recommendation for founder. Not locked. Founder picks final.
**Decision deadline:** before Phase B ceremony recruitment goes wide.

---

## TL;DR

| Axis | Recommendation | Engineering cost |
|---|---|---|
| Protocol name (V1 ship) | **Keep `QKB`** as the noun. Use `zk-QES` as a descriptor in copy. | ~0 (sweep 9 marketing drafts only) |
| Project-line name | **Keep `Identity Escrow`** as the project umbrella. Sharpen copy so V1 scope is unambiguous. | 0 |
| Domain + repo | **No change.** `identityescrow.org` + `identityescroworg` stay. | 0 |

The cheapest path that resolves both the lead's escrow-overpromising concern and the audience-resonance question.

---

## Recommendation 1 — Protocol name: keep `QKB`

`QKB` is structurally locked into shipped artifacts: `@qkb/cli` on npm, `@qkb/sdk` consumed by the SPA, `QKBRegistryV5_2.sol` about to deploy on Base Sepolia, the `qkb serve` CLI-server merging now, `qkb-v5.r1cs` referenced in already-published ceremony commands at `/ceremony/contribute`, `v0.5.1-pre-ceremony` and `v0.5.2-pre-ceremony` tags published. Renaming this surface mid-ceremony is high-risk for zero functional benefit. Public-facing legibility is solved instead by leading with `zk-QES` as a **descriptor** in marketing copy: "QKB is a zero-knowledge protocol over qualified electronic signatures." The PSE / 0xPARC / Mopro / Anon Aadhaar audience parses `zk-QES` in the descriptor in two seconds; the noun stays `QKB`. WebKit/Safari pattern, applied to a one-page README sentence.

## Recommendation 2 — Project-line name: keep `Identity Escrow`, sharpen the V1 scope language

The lead's critique is fair on its surface — V5.2 ships pure binding registration with no escrow primitive, so the project name promises a feature the V1 doesn't deliver. But "identity escrow" has two valid readings: (a) the property that any state-issued credential exhibits — the issuer retains the ability to identify a holder under lawful process — and (b) the specific QIE Phase 2 feature with threshold-held QTSP recovery material. Reading (a) is what the launch drafts already commit to; under it, V5.2 already exhibits identity escrow as a property of the Diia QES anchor. The fix is not to rename the project — that loses the differentiator versus Worldcoin / World ID / Self / Anon Aadhaar, all of whom market as anonymity — but to make copy explicit: V1 ships QKB; future iterations *may* extend toward fuller escrow constructions per the QIE design line; nothing is promised on a timeline. The launch drafts already carry this posture; a one-paragraph clarifier on the landing page closes the gap with no rename.

## Recommendation 3 — Domain + repo: no change

`identityescrow.org` is live, `identityescroworg` is the GitHub repo, both align. Under Recommendations 1 and 2 nothing about either name needs to change. A 301 + repo rename would cost a real engineering day, break inbound links to the spec corpus, and risk the live `/ceremony` page during recruitment. Not worth it for a non-decision.

---

## Cost matrix (per rename, if founder picks against the recommendations)

| Action | Engineering cost | Risk during ceremony |
|---|---|---|
| Rename `QKB` → `zk-QES` across code | 1.5 days. New `@zkqes/*` npm scope claim, package republish, `QKBRegistry*` → `ZKQESRegistry*` contract sweep, deploy-fixtures regen, ABI re-pump to web/sdk/circuits worktrees, 16-spec sweep, 8-CLAUDE.md sweep, `/ceremony` copy + i18n keys, ceremony-coord scripts (R2 bucket layout, status.json schema, `.r1cs` filename in published commands), CLI-server + cookbooks + Fly launcher form. | High. Ceremony commands at `/ceremony/contribute` would fail until contributors re-pull; pre-baked `qkb-v5.r1cs` filename is in PSE/etc. inboxes already if recruitment has begun. |
| Rename `Identity Escrow` → something property-neutral (e.g., "QKB Project") | 0.5 days. Domain change ($0 if redirect-only), GitHub repo rename + 301, README rewrite, marketing-draft sweep across all 9 files. Loses the "accountable pseudonymity" differentiator versus anonymity-positioned competitors. | Low engineering, high brand. Rebuilds the institutional positioning from zero. |
| Rename domain only (keep project name) | 0.5 days. DNS, GH Pages CNAME, `/ceremony` deeplinks, README references, ceremony-coord script base URLs (`prove.identityescrow.org/ceremony/...`). | Medium. Inbound links to spec + ceremony break until 301 propagates. |
| Sweep marketing drafts only (zk-QES → QKB-as-noun + zk-QES-as-descriptor) | 1 hour. Nine files in `docs/marketing/`. No code touches. | Zero. |

---

## Open calls reserved for founder

1. **Defensive `@zk-qes/*` npm scope squat.** Zero-cost defensive registration in case a future rebrand is wanted. Decide: claim now or leave open? Recommend: **claim now**, costs nothing, prevents squatters during launch arc.
2. **QIE Phase 2 status in README.** The README currently says "Phase 2 (Qualified Identity Escrow — threshold-held QTSP recovery material with formally-specified disclosure conditions) is a future iteration in the project line." This is the language that creates the lead's escrow-overpromising concern. Founder decides: leave as-is, soften to "may be a future iteration if the design clears review and resourcing", or strike entirely until QIE actually ships or is formally killed. Recommend: **soften** — minimal language change, removes the implicit timeline.
3. **Marketing draft sweep.** If Recommendation 1 stands, the existing 9 marketing drafts at `docs/marketing/2026-04-29-launch-drafts/` and `2026-04-30-ceremony-drafts/` need a one-hour sweep (s/zk-QES/QKB/ as noun; insert "zk-QES" as descriptor in opening paragraphs). Founder confirms: marketer does this as a follow-up, or waits for separate dispatch?
4. **`BRAND.md` at repo root.** Optional one-page document defining the noun/descriptor split so future contributors don't reopen the question. Recommend: **yes**, write after sweep, ~30 min.

---

## What this document does not do

- Does not rename any code, contracts, package names, npm artifacts, or domains.
- Does not edit `/ceremony` copy.
- Does not edit `README.md`.
- Does not write any new spec docs.
- Does not lock the decision — founder picks final.

If founder greenlights Recommendation 1 + 2 + 3 (i.e., no renames anywhere), the only follow-up work is the one-hour marketing-draft sweep flagged in Open Call 3, plus the optional BRAND.md.

If founder picks against any recommendation, the cost matrix above is the budget conversation.
