# V5.3 Orchestration Plan — OID-anchor + range-check + doc

> **For agentic workers**: REQUIRED SUB-SKILL: `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans`. Steps use checkbox `- [ ]` syntax for tracking.

**Goal**: Ship V5.3 amendment closing the F1 OID-anchor Sybil vector, F2 rotationNewWallet range-check, F3 walletSecret↔msgSender doc — all in-place on the V5.2 main circuit with the public-signal layout UNCHANGED.

**Architecture**: Three independent worker tracks merging into a single `feat/v5_3-circuits` integration branch. circuits-eng owns the main circuit + ceremony; contracts-eng adds a one-line revert; web-eng pumps the new fixtures. Pot22 reused; no new ceremony pot.

**Spec**: `docs/superpowers/specs/2026-05-03-v5_3-oid-anchor-amendment.md` (v0.1, pending user-review gate).

**Tech stack**: circom 2.1.9, snarkjs 0.7.6, pot22, Foundry, React/wagmi (existing).

---

## §1 — Interface contracts (FROZEN once founder reviews v0.1)

### §1.1 — Public-signal layout: UNCHANGED from V5.2

22 signals in the same order. No calldata change. Contracts-eng `verifyProof(uint[22])` keeps its signature; web-eng's SDK fixture filename changes from `verification_key.json` (v5.2) to a new file under `ceremony/v5_3/verification_key.json` but same shape.

### §1.2 — Witness-builder API: +1 (or +3) private input

```ts
// V5.3 minimal (recommended by spec):
interface BuildWitnessV5Input {
  // ... existing V5.2 inputs ...
  subjectSerialOidOffsetInTbs: number;  // NEW: byte offset of `06 03 55 04 05` in leafTbs
}
```

If founder picks F1.4 (stronger):

```ts
  // V5.3 stronger (defense-in-depth):
  subjectDnOffsetInTbs: number;
  subjectDnLength: number;
```

F2 + F3 add no witness-builder API changes.

### §1.3 — Contract surface: +1 line per flow

```solidity
// Inside register() and rotateWallet(), pre-verifier:
if (sig.rotationNewWallet != uint256(uint160(sig.rotationNewWallet))) revert InvalidNewWallet();
```

`error InvalidNewWallet();` declared once. ~50 gas per call.

### §1.4 — Constraint envelope (FROZEN target)

| Component | V5.3 minimal | V5.3 stronger |
|---|---|---|
| Base (V5.2 measured) | 3,876,304 | 3,876,304 |
| F1 OID-anchor | +~10,500 | +~10,500 |
| F1.4 DN-bounds | — | +~5,500 |
| F2 Num2Bits(160) | +~160 | +~160 |
| **Total projected** | **~3,887,000** | **~3,892,000** |
| Pot22 cap | 4,194,304 | 4,194,304 |
| Headroom | 7.3% | 7.2% |

If T1 cold-compile measurement is more than 5K above projected, surface to lead immediately; do NOT plow.

---

## §2 — Dispatch order

```
DAY 1                      DAY 2-3                    DAY 4
─────                      ───────                    ─────
[c-eng]  T1 (main circuit) [c-eng]   T2 (witness)   [c-eng]  T3 (ceremony stub)
[c-eng]  cold-compile check          + tests                  + pump verifier+vkey
                                                              + integration green

                           [contracts-eng] T4 (one-line revert + tests)

                                                      [web-eng] T5 (SDK fixture pump
                                                                + happy-path replay)

DAY 5+: founder review gate; Phase B ceremony coordinator dispatch (lead-side)
        for the real V5.3 ceremony (5-10 contributors, ~1-2 weeks wall).
```

T1+T2+T3 are sequential (one worker, circuits-eng owns the main-circuit + witness + ceremony pipeline). T4 (contracts-eng) parallel from day 2 since it doesn't need T2/T3 output until pumping the verifier .sol. T5 (web-eng) gates on T3's stub artifacts.

**Critical-path discipline**: T1's cold-compile constraint count is the gate. If it lands above 4.05M (above 4% safety floor), spec needs a tweak before T2 plows.

---

## §3 — Branches & worktrees

| Worker | Branch | Worktree |
|---|---|---|
| circuits-eng | `feat/v5_3-circuits` | `/data/Develop/qkb-wt-v5/v5_3-circuits/` (new; lead creates post-V5.4-merge) |
| contracts-eng | `feat/v5_3-contracts` | `/data/Develop/qkb-wt-v5/v5_3-contracts/` (new) |
| web-eng | `feat/v5_3-web` | `/data/Develop/qkb-wt-v5/v5_3-web/` (new) |

Branches cut from `main` HEAD post-V5.4-merge. Spec + this plan stay in `feat/qkb-cli-server-circuits @ 8eaf022` for now (no separate branch needed for docs); lead pumps them across at dispatch time.

Lead does all merges from the main checkout. Order:
1. `feat/v5_3-circuits` (provides verifier .sol + vkey for downstream pumps).
2. `feat/v5_3-contracts` (uses the verifier).
3. `feat/v5_3-web` (uses the SDK fixture).

Tag `v0.5.3-pre-ceremony` after E2E green; full Phase B ceremony lands as a separate tag `v0.5.3` once the multi-contributor zkey ships.

---

## §4 — Pump table (cross-package outputs lead moves)

| Artifact | From | To | When |
|---|---|---|---|
| `Groth16VerifierV5_3Stub.sol` | `v5_3-circuits/packages/circuits/ceremony/v5_3/` | `v5_3-contracts/packages/contracts/src/` | end of T3 |
| `verification_key.json` + sample triple + `witness-input-sample.json` | `v5_3-circuits/.../ceremony/v5_3/` | `v5_3-web/packages/sdk/fixtures/v5_3/` | end of T3 |
| (Phase B output, much later) `qkb-v5_3.zkey` (~2.0 GB) | post-ceremony | R2 + manifest | Phase B close |

---

## §5 — Risks + escalation triggers

| Risk | Trigger | Action |
|---|---|---|
| T1 constraint count >4.05M (above 4% safety floor) | T1 cold-compile reports high | circuits-eng surfaces to lead before T2; spec amendment |
| Real Diia cert uses non-standard subject-serialNumber encoding | T1 real-fixture test fails on OID anchor | T1 surfaces to lead; spec adjusts (e.g., add WrapperOID handling) |
| Founder picks F1.4 stronger after spec review | Founder review gate response | spec v0.2 with the 3-input variant + +5K constraint update |
| Phase B ceremony contributor recruitment slips | lead day-N standup | re-sequence: ship V5.3 with the stub zkey to Sepolia first; mainnet gates on full ceremony |
| Contracts-eng deploy plan: dual-verifier grace window vs hard cutover | Lead's deploy strategy decision | spec §"Backwards compat / migration" lays out both; founder picks |

---

## §6 — Per-worker plans (LEAD-WRITTEN, deferred)

Per the established pattern (founder directive 2026-05-03 from V5.4 brief), per-worker bite-sized TDD plans are **lead-written after this orchestration brief is reviewed**, NOT auto-generated by circuits-eng. This brief carries enough scope for lead to dispatch.

If lead wants circuits-eng to draft per-worker plans before dispatch, that's a separate ask.

---

## §7 — Acceptance gates (V5.3 RC)

Before tagging `v0.5.3-pre-ceremony`:

- [ ] `pnpm -F @qkb/circuits test` green (mocha + vitest)
- [ ] `pnpm -F @qkb/circuits compile:v5` reports constraint count in projected range
- [ ] `cd packages/contracts && forge test -vv` green (with new `InvalidNewWallet` cases)
- [ ] `pnpm -F @qkb/web test` + `pnpm -F @qkb/web exec playwright test` green
- [ ] V5.3 stub ceremony reproducible: `pnpm -F @qkb/circuits ceremony:v5_3:stub`
- [ ] Sample proof bytewise-stable across re-runs (manifest sha256s match)
- [ ] CLAUDE.md V5.31-V5.33 invariants documented in circuits package
