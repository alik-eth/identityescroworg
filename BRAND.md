# Brand

**Date locked:** 2026-05-03
**Decision reference:** `docs/marketing/2026-05-03-branding-decision.md`

A one-page reference for anyone writing public-facing copy, talks, slides, or third-party documentation about this project. Read once; carry forward.

## Names

| Layer | Name | Use it as |
|---|---|---|
| Protocol noun | **QKB** (Qualified Key Binding) | The noun. The thing that ships at V1. The name in code, contracts, packages, specs, CLI, ceremony commands. |
| Public-facing descriptor | **zk-QES** | The descriptor. What QKB *is* in two seconds for an outside reader. Use in opening lines, taglines, HN titles, conference abstracts. |
| Project umbrella | **Identity Escrow** | The org-level name. The research line. The thing the .org domain points at. |
| Phase 2 design line (parked) | **QIE** (Qualified Identity Escrow) | Internal codename only. Not for public copy until QIE either ships or is formally killed. |

## The split, explained once

`QKB` is the codename. It is structurally locked into shipped artifacts (`@qkb/*` packages, `QKBRegistry*` contracts, `QKBPresentationV5.circom`, `qkb` CLI, `qkb-v5.r1cs`). Renaming any of that surface mid-ceremony would be high-cost for zero functional gain. So we keep `QKB` as the working name.

`zk-QES` is the descriptor — "zero-knowledge proof of a qualified electronic signature, in the eIDAS sense." It parses instantly for the audience this project is aimed at (PSE, 0xPARC, Mopro, Anon Aadhaar, ZK research). We use it as the descriptor any time we need outside legibility.

`Identity Escrow` is the project umbrella. It does not refer to a specific contract feature; it refers to a property that any state-issued credential exhibits: the issuing authority retains the ability to identify a holder under lawful process. V1 (QKB) already exhibits this property by virtue of the Diia QES anchor. Future iterations may extend toward fuller escrow constructions, but nothing is promised on a timeline.

## How to write about the project

**Do:**
- Lead with the descriptor: "QKB is a zero-knowledge protocol over qualified electronic signatures (zk-QES)."
- Use `QKB` in install commands, code references, contract addresses, ceremony command paths.
- Use `Identity Escrow` only when referring to the project as a whole, not to V1's feature set.

**Don't:**
- Don't market `QIE` as a near-term feature; it is parked.
- Don't claim escrow as a V1 feature; V1 ships pure binding registration.
- Don't introduce a fourth name. Three is enough.

## Defensive registrations

| Asset | Status | Action |
|---|---|---|
| `identityescrow.org` | Live, canonical | Keep |
| `identityescroworg` (GitHub) | Live, canonical | Keep |
| `zkqes.org` | Registered 2026-05-03 | 301 → `identityescrow.org` |
| `zkqes.com` | Open call | Recommended buy + 301 |
| `@qkb` (npm) | Live, in use | Keep |
| `@zkqes` (npm) | Open call | Recommended defensive squat (no publishes) |

## When this document changes

This brand split is intentionally cheap to reverse. If founder later decides to flip the public noun from `QKB` to `zk-QES`, `zkqes.org` and `@zkqes` are already in hand and the flip is a marketing sweep rather than a code rename. Do not edit this document without founder sign-off; the cost of churn here is paid in audience confusion.
