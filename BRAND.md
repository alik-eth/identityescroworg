# Brand

**Date locked:** 2026-05-03 (rename baseline)
**Decision reference:** `docs/superpowers/specs/2026-05-03-zkqes-rename-design.md` + `docs/superpowers/research/2026-05-03-zkqes-rename-analysis.md`

A one-page reference for anyone writing public-facing copy, talks, slides, or third-party documentation about this project. Read once; carry forward.

## Name

**`zkqes`** — lowercase noun, no expansion needed in casual use. Matches the domain (`zkqes.org`) and the descriptor.

When introducing the project to an outside reader who's seeing it for the first time, the two-second descriptor is **"a zero-knowledge proof of a qualified electronic signature"** (the literal expansion of zk-QES, eIDAS-aware audiences will recognize it). After the first use, just `zkqes`.

There is no protocol-vs-project-vs-descriptor split. The repo, the protocol, the website, the package scope, the CLI binary, the contract namespace — all named `zkqes`. One name, one thing.

## What this brand REVERSED

The 2026-05-03 morning lock briefly used a three-tier hierarchy: `QKB` (protocol noun, structurally locked), `zk-QES` (descriptor), `Identity Escrow` (project umbrella). That decision was reversed the same day, on the explicit reasoning that:

- Nothing was actually shipped under the QKB name yet (zero npm publishes, zero contracts deployed, zero ceremony rounds run).
- The three-name split was confusing for a single-thing project.
- The cost of renaming was strictly minimal at this point in the lifecycle.

So the structural rename to a single noun happened before any of those names left the repo. Future readers seeing this section can ignore the prior brand split entirely; it never reached production.

## How to write about the project

**Do:**
- Lead with the single name: "zkqes is a zero-knowledge protocol over qualified electronic signatures."
- Use `zkqes` in install commands, code references, contract addresses, ceremony command paths.
- When invoking an outside reader, expand to "a zero-knowledge proof of a qualified electronic signature (zk-QES)" once at first introduction, then drop the expansion.

**Don't:**
- Don't introduce additional names, sub-brands, or umbrella terms.
- Don't reintroduce "QKB", "Qualified Key Binding", "Identity Escrow", "QIE", or "Qualified Identity Escrow" anywhere in public-facing copy. (The 9 frozen consensus byte strings inside the protocol — see invariant below — are not branding; they're protocol-internal hash inputs that predate the rename.)
- Don't expand `zkqes` in headlines or branding except as one-shot context.

## Frozen consensus bytes (NOT branding)

A small set of string literals inside the codebase begin with `qkb-` and look like brand artifacts but are NOT branding. They are protocol-internal byte strings hashed (keccak256 / SHA-256 / Poseidon) into circuit publics, contract storage, or off-chain deterministically-derived values. Renaming them invalidates the V5 circuit + Phase B ceremony + every existing fixture.

The frozen tags are documented in **`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md` §3** — keep them; never touch. Each occurrence in code carries a freeze comment pointing back at that spec section. If you're writing a new amendment that needs a new domain-separation tag, name it with a `zkqes-` prefix; existing tags stay frozen.

## Domains

The public-facing surface uses three subdomains under `zkqes.org`. Locked 2026-05-03.

| Subdomain | Purpose | Lifecycle |
|---|---|---|
| `zkqes.org` (root) | Pre-ceremony hero + ceremony recruitment CTA + three contribution paths (snarkjs local / VPS / Fly launcher) | Live pre-recruitment; persists post-launch as the project landing |
| `app.zkqes.org` | The actual register flow — `/ua/registerV5` + `/account/rotate`. Hosts the SPA. End users come here only after Phase B ceremony completes + Sepolia E2E §9.4 green | Live post-ceremony |
| `docs.zkqes.org` | VitePress-rendered docs from the `docs/` tree — install instructions, specs, ceremony attestations, SDK reference, this BRAND.md | Live pre-recruitment |
| `prove.zkqes.org` | Ceremony coordinator (R2-backed status feed + manifest hosting) | Live post-DNS migration; bucket name `prove-zkqes-org` |

Old `prove.identityescrow.org` host + `prove-identityescrow-org` R2 bucket remain frozen as a read-only mirror for V3/V4 historical artifacts; new ceremony rounds publish at `prove.zkqes.org`.

The split exists because the three audiences are distinct: ceremony contributors (zkqes.org root), end users registering with their QES (app.zkqes.org, post-launch), and developers / integrators / researchers (docs.zkqes.org). Surfacing all three on one page would mute the call-to-action that matters at the current lifecycle stage.

## Defensive registrations

| Asset | Status | Action |
|---|---|---|
| `zkqes.org` | Live, canonical | Keep — primary public domain |
| `identityescrow.org` | Held (never published a working public surface) | No 301 needed at present; can be added later if any traffic appears |
| `alik-eth/zkqes` (GitHub) | Live | Repo (renamed 2026-05-03 from `identityescroworg`); GitHub auto-redirects the old URL |
| `zkqes.com` | Open call | Recommended defensive buy + 301 → `zkqes.org` |
| `@zkqes` (npm) | Open call — **claim before first publish** | Defensive squat + protocol scope |
| `@qkb` (npm) | Open call (no publishes ever) | No action — names are not used after the rename |

## When this document changes

This brand collapse is intentionally robust to future edits — the ship surface is single-name, the protocol is single-name, the domain is single-name. If founder later decides to introduce a sub-brand (e.g., a separate name for an EVM-native variant or a fork), it should land as a new noun under the same project, not a re-litigation of the three-tier split.

Do not edit this document without founder sign-off.
