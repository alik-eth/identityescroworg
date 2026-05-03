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

### §1.4 — Constraint envelope (UPDATED — v0.2 empirical)

> **v0.2 amendment — empirical numbers from T1+T2+T3 cold-compile.** v0.1's projection of ~10.5K for F1 was off by 2× (root cause: circomlib `Multiplexer(1, 1408)` is ~2,800 constraints/mux, not ~1,408 — see spec §F1.3 v0.2 amendment). Pot22 envelope holds; headroom remains comfortably above the 4% safety floor.

| Component | V5.3 minimal projected (v0.1) | V5.3 minimal **measured (v0.2)** |
|---|---|---|
| Base (V5.2 measured) | 3,876,304 | 3,876,304 |
| F1 OID-anchor | +~10,500 | **+19,892** |
| F2 Num2Bits(160) parent-aliveness | +~160 | **+161** |
| F3 doc | 0 | 0 |
| **Total** | **~3,887,000** | **3,896,356** |
| Pot22 cap | 4,194,304 | 4,194,304 |
| Headroom | 7.3% | **7.10%** |

The +20,052 delta (V5.2 → V5.3) is bounded; pot22 stays the right tier (no jump to pot23 needed). The 7.10% headroom is well above the 4% safety floor.

If a future amendment grows constraints another ~120K (lands above 4.05M), spec amendment + ceremony pot22 → pot23 step-up is required.

---

## §2 — Dispatch order

> **v0.2 amendment — T5 reframe.** v0.1's diagram conflated two web-eng deliverables under "T5 (SDK fixture pump + happy-path replay)". The reframe: T5 is **witness-builder consumer integration** in web-eng's browser path (the SDK already pumps fixtures via the lead's pump table §4). Specifically T5 is web-eng updating their browser-side `buildWitnessV5` consumer (in `packages/web/src/lib/witness/build-v5.ts` or equivalent) to thread the new `subjectSerialOidOffsetInTbs` private input, then re-running the V5 happy-path Playwright e2e to verify the in-browser `fullProve` round-trip succeeds. The "fixture pump" leg of T5 is purely a lead-side mechanical step in §4 (cp + commit) — not a worker task.

```
DAY 1                      DAY 2-3                    DAY 4
─────                      ───────                    ─────
[c-eng]  T1 (main circuit) [c-eng]   T2 (witness)   [c-eng]  T3 (ceremony stub)
[c-eng]  cold-compile check          + tests                  + pump verifier+vkey
                                                              + integration green

                           [contracts-eng] T4 (one-line revert + tests
                                              on rotateWallet only — v0.2)

                                                      [web-eng] T5 (witness-builder
                                                                consumer + happy-path
                                                                e2e replay; lead pumps
                                                                fixtures separately)

DAY 5+: founder review gate; Phase B ceremony coordinator dispatch (lead-side)
        for the real V5.3 ceremony (5-10 contributors, ~1-2 weeks wall).
```

T1+T2+T3 are sequential (one worker, circuits-eng owns the main-circuit + witness + ceremony pipeline). T4 (contracts-eng) parallel from day 2 since it doesn't need T2/T3 output until pumping the verifier .sol. T5 (web-eng) gates on T3's stub artifacts AND on the lead-side pump from §4.

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

- [x] **circuits-eng T1 — F1 OID-anchor + F2 range-check + F3 doc** committed (`25bf103` + `b56c936`) on `feat/v5_3-circuits`. Constraint count measured 3,896,356 (+20,052 over V5.2; 7.10% pot22 headroom).
- [x] **circuits-eng T2 — witness builder + tests** in flight. `src/build-witness-v5.ts` emits `subjectSerialOidOffsetInTbs`. Heavy integration test suite (`pnpm test:v5`) green:
  - V5.3 F1 OID-anchor happy-path (real Diia leaf): PASS
  - V5.3 F1 wrong OID offset → reject: PASS
  - V5.3 F1 value-offset / OID-offset +7 invariant violated → reject: PASS
  - V5.3 F2 rotationNewWallet ≥ 2^160 → reject: PASS
  - All V5.2 tamper tests still green (no regression).
- [x] **circuits-eng T3 — V5.3 stub ceremony script** at `ceremony/scripts/stub-v5_3.sh`. Cold ceremony run pending (Phase B coordination by lead).
- [x] **CLAUDE.md V5.31-V5.34 invariants** documented in circuits package.
- [ ] `pnpm -F @qkb/circuits test` full suite (vitest + remaining mocha) — gated on T2 commit.
- [ ] `cd packages/contracts && forge test -vv` green (with new `InvalidNewWallet` cases on `rotateWallet`) — contracts-eng T4.
- [ ] `pnpm -F @qkb/web test` + `pnpm -F @qkb/web exec playwright test` green — web-eng T5.
- [ ] V5.3 stub ceremony reproducible: `pnpm -F @qkb/circuits ceremony:v5_3:stub`
- [ ] Sample proof bytewise-stable across re-runs (manifest sha256s match)
- [x] **Spec v0.2** amendments committed (cost projection corrected, optimizer footgun documented, F2 contract scope narrowed, ETSI string-tag scope, F1.5 SDK derivation, founder F1.2 minimal decision recorded).
