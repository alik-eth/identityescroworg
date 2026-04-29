# circuits-eng — V5 §6.0a checkpoint handoff

**Date:** 2026-04-29
**Branch:** `feat/v5arch-circuits` @ `4b38667`
**Worktree:** `/data/Develop/qkb-wt-v5/arch-circuits`
**Status:** clean checkpoint mid-§6.0a, all decisions through Phase 1 frozen
**Successor pickup:** §6.0a Phase 2 (V2Core-isolated witness harness from `fixture-qkb2.json`)

---

## §1. Final state at checkpoint

Branch tip `4b38667`. 15 commits since dispatch on `feat/v5arch-circuits`, cut from `a3b040a` (lead's `feat/v5-frontend` HEAD at dispatch time). Working tree clean, no uncommitted state. Lockfile clean (3-line vitest-only delta from commit `42681e1` is the only `pnpm-lock.yaml` change).

**What's locked (no further design discussion needed):**
- §2 TS SpkiCommit reference impl + parity-fixture infrastructure (parity gate §9.1 closed circuits-side).
- §3 `Bytes32ToHiLo` circom primitive + tests.
- §4 `SignedAttrsParser` circom + 6/6 tests on real Diia signedAttrs (the V5 soundness payload — CAdES messageDigest gate).
- §5 `SpkiCommit` circom template + circom-vs-TS-vs-Solidity parity (4-way).
- §6.1 `QKBPresentationV5.circom` skeleton — public-signal layout matches contracts-eng's `PublicSignals` struct exactly.
- §6.0a Phase 1 (deterministic QKB/2.0 fixture).

**What's in-flight (the next agent picks up here):**
- §6.0a Phase 2-4 (witness harness + V2Core refactor + parity test). See §5 of this doc.

**What remains after §6.0a:**
- §6.2-§6.10 main-circuit wiring (BindingParseV2Core, 3× Sha256Var, SignedAttrsParser, X509SubjectSerial, NullifierDerive, 4× Bytes32ToHiLo, 2× SpkiCommit, Secp256k1PkMatch, leafTBS bind, E2E).
- §7 witness builder.
- §8 stub ceremony for contracts-eng integration.
- §11 Phase 2 real ceremony.

The §6.1 skeleton at commit `ea9cfd5` is intact and ready for §6.2 wiring after V2Core refactor lands.

---

## §2. Commit roll (since dispatch)

```
4b38667 feat(circuits): deterministic QKB/2.0 binding fixture for V5 tests   ← §6.0a Phase 1 (HEAD)
ea9cfd5 feat(circuits): QKBPresentationV5 skeleton (§6.1)
124e4bd feat(circuits): SpkiCommit circom template                          ← §5
32bcd9c feat(circuits): SignedAttrsParser — fixed-shape CAdES messageDigest ← §4 (soundness payload)
d9badd5 docs(circuits): MAX_SA 256→1536 in per-worker plan (mirrors spec v5) ← cherry-picked
dfcbabf docs: V5 spec v5 — MAX_SA 256→1536 ground-truth amendment             ← cherry-picked
4692c5e feat(circuits): Bytes32ToHiLo primitive + circom-tester suite        ← §3
f3c2428 chore(circuits): silence circomlibjs TS7016 + non-null limb access
f1d7a79 feat(circuits): SpkiCommit parity-fixture generator + v5-parity.json ← §2.5 (parity gate trigger)
57ef9dd feat(circuits): SpkiCommit TS reference implementation               ← §2.4
17e7fe5 feat(circuits): 6×43-bit LE limb decomposition for SpkiCommit         ← §2.3
ec21226 feat(circuits): parseP256Spki DER walker + canonical prefix gate     ← §2.2
42681e1 build(circuits): add vitest@^2.1.0 (surgical lockfile edit)
7556ff9 fix(circuits): satisfy TS strict on extract-spkis Buffer→ArrayBuffer
98193bd feat(circuits): extract leaf + intermediate SPKIs from DER certs     ← §2.0
```

---

## §3. Architectural decisions made ad-hoc this session

These decisions don't naturally live in commit messages alone — capturing the *why* here so a successor doesn't have to re-derive.

### §4 fixed-shape walker (commit `32bcd9c`)

**Decision:** `SignedAttrsParser` verifies a 17-byte canonical messageDigest Attribute prefix at a *witnessed* `mdAttrOffset` rather than scanning the SET OF for the OID. Range-bound `mdAttrOffset < 256`.

**Why:** The plan §4 sketched a position-agnostic SET OF walker (~180K constraints) for "find the messageDigest attribute by OID". But the parent circuit elsewhere asserts `sha256(bytes[0..length)) == signedAttrsHash`, and `signedAttrsHash` is bound (off-circuit) to the leaf-cert ECDSA gate via EIP-7212. Those upstream constraints fix `bytes[]` to the EXACT bytes Diia signed; the prover cannot manipulate content at any offset. So a fixed-shape check at a witnessed offset is sound for the same reason a content-addressed pointer is — forging a "signedAttrs that ECDSA-verifies AND happens to contain a fake 49-byte messageDigest-shaped substring at offset N" is computationally equivalent to forging a P-256 signature.

The 17-byte messageDigest Attribute prefix is `30 2F 06 09 2A 86 48 86 F7 0D 01 09 04 31 22 04 20`. The 9-byte id-messageDigest OID alone is high-entropy ASN.1 — distinct enough that no other Diia CAdES attribute embeds it within the first 256 bytes. The audit-bound `mdAttrOffset < 256` is defense-in-depth against future emit-format drift.

**SHA-256-locked:** `04 20` (OCTET STRING with 32-byte payload) and `31 22` (SET length 34) hard-code SHA-256 as the digest. Migrating to SHA-512 would change those constants and require a new template + new ceremony.

**Constraint count:** measured 150,584 constraints (vs my pre-coding estimate of ~75K — circomlib `Multiplexer(1, 1536)` is ~3K constraints/output not ~1.5K/output). 17% under plan-budget 180K.

### §5 SpkiCommit four-way parity

**Decision:** Same `Poseidon₂(Poseidon₆(xLimbs), Poseidon₆(yLimbs))` construction across four implementations:
1. **circuits-eng TS reference** (`scripts/spki-commit-ref.ts`) — source of truth.
2. **flattener-eng TS port** (parity-fixture-gated).
3. **contracts-eng Solidity P256Verify.spkiCommit** (Path B' bytecode emission, parity-fixture-gated).
4. **circuits-eng circom template** (`circuits/primitives/SpkiCommit.circom`).

All four produce identical decimals on the lead-pumped parity fixture:
- `admin-leaf-ecdsa` (real Diia leaf SPKI): `21571940304476356854922994092266075334973586284547564138969104758217451997906`
- `admin-intermediate-ecdsa` (synthetic): `3062275996413807393972187453260313408742194132301219197208947046150619781839`

Cross-checked V4's existing `computeLeafSpkiCommit(X, Y)` (test/integration/witness-builder.ts:303) — produces the SAME value as V5's `spkiCommit(spki)` for the leaf SPKI. Five-way parity (V4 leaf-circuit math also agrees) confirms the construction is correct across the full migration boundary.

**Constraint count:** 948 per SpkiCommit instance. Two instances in §6 main = ~1.9K total. Negligible.

### §6.0a Path K decision (commit `4b38667` is Phase 1 of K)

**Decision:** Refactor V2Core to a single-pass walker AND build a deterministic QKB/2.0 fixture, before §6.2 wiring. Lead-greenlit as path K with 2.5-day budget.

**The math correction story (load-bearing for understanding the trade-off):**

I initially claimed the single-pass refactor would yield ~10× constraint savings (parser cost 1.97M → ~250-400K). After reading circomlib's `Multiplexer(wIn, nIn)` source, the actual savings are ~1.8× asymptotic, capping at 2×.

Cost of `Multiplexer(wIn, nIn)`: `(wIn+1) × nIn + 1` constraints (1× `Decoder(nIn)` ≈ nIn constraints + wIn × `EscalarProduct(nIn)` at nIn each).

Comparing strategies for K bytes at one offset:
- Current V2Core: K separate `Multiplexer(1, MAX_B)` ≈ 2K × MAX_B
- Single-pass walker: 1 `Multiplexer(K, MAX_B)` ≈ (K+1) × MAX_B

Savings ratio = 2K / (K+1) ≈ 1.8× at K=10. The amortization works **within a single offset only**, not across offsets — V2Core's 12 BindingKeyAt scanners each operate over different offsets and can't share a Decoder.

**Realistic refactor outcome:** V2CoreFast lands at ~1.4M constraints (was 1.97M at MAX_BCANON=768; scales to ~2.6M at 1024 without refactor; ~1.4M at 1024 WITH refactor). Total V5 projects ~2.7M. zkey ~1.5GB. In-browser proving ~6-8s. Worth doing.

**Without refactor (alternative considered + rejected):** ~3.95M total, ~2.2GB zkey, ~10-15s proving. Rejected because zkey exceeds lead's 1GB practical browser-proving threshold; UX impact was the deciding factor.

### MAX_BCANON 768 → 1024 (pending lead-side spec amendment)

**Decision:** MAX_BCANON bumps from 768 to 1024 in V5 spec §0.5 (and `packages/circuits/CLAUDE.md` invariant 6).

**Why:** Diagnostic measurement during §6.0a triage found:
- Real Diia binding (`fixture.json.binding.bytesLength`): **849 B**
- MAX_BCANON spec bound: **768 B** ← undersized
- 1024 gives 21% headroom over 849B

This is the **second** measurement-driven amendment this session (MAX_SA 256→1536 was the first, commit `dfcbabf` cherry-picked from main). Pattern: spec bounds were authored before measuring real fixtures; both real-Diia data points (1388B signedAttrs, 849B binding) overflow the original spec bounds. Reasonable to expect MAX_LEAF_TBS and MAX_CERT may also need adjustment when measured — flagged as "Path J" in my message but lead deferred.

**Pending:** lead writes the spec amendment commit (1c14f0f-style) once V2CoreFast measurement confirms the parser at MAX_BCANON=1024 is workable.

### V5 envelope 1.85M → ~3M (pending)

**Decision:** Total V5 constraint envelope revises from 1.85M (spec v5) to ~3M (target post-refactor measurement).

**Why:** Even with V2Core refactor, total V5 projects ~2.7M (V2CoreFast ~1.4M + Sha256Var ×4 ~1.05M + SignedAttrsParser 150K + SpkiCommit ×2 ~2K + nullifier/hiLo/pkMatch ~150K). Doesn't fit 1.85M envelope. ~3M target with margin lands at ~1.5GB zkey, acceptable browser-proving UX (~6-8s).

**Pending:** lead writes the envelope amendment commit alongside MAX_BCANON, post-Phase-3 measurement. The number depends on whether V2CoreFast lands at the projected ~1.4M or below. Phase 4's measurement is the trigger.

### Option A ctxHash (commit `ea9cfd5` skeleton documents this inline)

**Decision:** V5 main circuit computes TWO hashes of the same `ctxBytes`:
1. `Sha256Var(ctxBytes)` → 32 bytes → `Bytes32ToHiLo` → public signals `ctxHashHi` / `ctxHashLo` (transparent on-chain audit).
2. `PoseidonChunkHashVar(ctxBytes)` → field element → consumed by `NullifierDerive` (V4-domain-stable nullifier).

No cross-binding constraint between the two — both are deterministic functions of the witnessed `ctxBytes`, so they auto-agree given the same input.

**Why:** V4's `NullifierDerive` consumes a field-domain ctxHash (Poseidon-chunk). V5 spec §0.1 exposes ctxHashHi/Lo as SHA-256-domain (public auditability). Three options were considered:
- **A.** Compute both, no cross-binding. Cost: ~5K extra constraints (PoseidonChunkHashVar over MAX_CTX=256). V4 nullifier-domain stable — same user/ctx/wallet produces same nullifier across V4/V5.
- **B.** Use SHA-256-domain ctxHash for NullifierDerive too. Saves 5K constraints. Nullifier-domain shifts; V4 user re-registering on V5 looks like a fresh namespace.
- **C.** Same as A, different framing.

Lead-greenlit A. The 5K constraints is 0.27% of the 1.85M (or 0.17% of revised 3M) envelope — negligible. The V4-domain stability is incidental but useful; the implementation simplicity (no mod-p reduction edge cases, no hi/lo packing alignment) is the load-bearing reason.

Per-worker plan §0.4 wording was sloppy ("field-encoded ctx hash" — didn't disambiguate). Lead's plan-cleanup pass will fix it. Documented inline at the top of `circuits/QKBPresentationV5.circom`.

### circomlibjs TS noise (commit `f3c2428`)

**Decision:** Added local `packages/circuits/types/circomlibjs.d.ts` with `declare module 'circomlibjs';`. tsconfig `include` extended to pick up `types/**/*.d.ts`.

**Why:** circomlibjs 0.1.7 ships no `.d.ts`. V4's existing usage at `test/integration/witness-builder.ts` defined a per-file local `PoseidonF` interface to capture the surface it touches. New V5 callers (e.g., `scripts/spki-commit-ref.ts`) would each re-trigger TS7016 unless silenced globally. The 1-line ambient declaration is a forever-fix that doesn't pollute call sites.

`@types/circomlibjs` doesn't exist on npm. Adding a typed shim package would have polluted the dep tree; inline `// @ts-expect-error` would have been opaque. Lead's option-B preference here was the right call.

### MODULE_TYPELESS_PACKAGE_JSON warning (cosmetic, not addressed)

ts-node emits a one-line warning when running `*.test.ts` under mocha because the package.json doesn't have `"type": "module"`. Cosmetic, doesn't affect test outcomes. Adding `"type": "module"` would require porting all CJS-style requires to ESM imports across the package — out of scope for V5 refactor work.

---

## §4. §6 progression plan (post-§6.0a)

After Phase 2-4 of §6.0a lands, the §6.2-§6.10 sequence picks up. Time estimates I locked in pre-§6.0a; some shift based on whether the next agent inherits a clean V2CoreFast or has to debug.

| Step | Component | Estimate | Notes |
|---|---|---|---|
| §6.2 | BindingParseV2CoreFast wiring | 1-2h | After refactor lands; just plumbing offsets through |
| §6.3 | 3× Sha256Var (binding 1024 + signedAttrs 1536 + leafTBS 1024) + 3× Bytes32ToHiLo | 1-2h | Heaviest compile (~1.05M constraints); first cache miss is slow |
| §6.4 | SignedAttrsParser wiring + messageDigest === bindingHash equality | 1h | Parser already at 32bcd9c; just wiring |
| §6.5 | 2× SpkiCommit (leaf + intermediate) | 30 min | Templates already at 124e4bd |
| §6.6 | X509SubjectSerial + NullifierDerive (Poseidon-domain ctxHash) | 1-2h | V4 reuse |
| §6.7 | Sha256Var(ctxBytes) + Bytes32ToHiLo for ctxHashHi/Lo | 30 min | Just hi/lo pipeline |
| §6.8 | Secp256k1PkMatch (msgSender ← pkX/pkY) | 1-2h | V4 reuse, but msgSender semantics need verification |
| §6.9 | leafTBS bound to leaf-cert DER consistency | 1h | Pin leafTBS as a substring of leafCertBytes |
| §6.10 | E2E test on real Diia fixture | 2-4h | Where everything lands together; pinch point |

Total: ~10-15h of focused work post-§6.0a. Lead's 5-7-day budget for §6 is generous.

---

## §5. Path forward for §6.0a Phase 2-4 (next agent's pickup point)

### Phase 2: V2Core-isolated witness harness (~1-2h)

**Files to create:**
- `packages/circuits/circuits/binding/BindingParseV2CoreLegacyTest.circom` — wraps V2Core in `component main` with all 17 inputs declared. Mirrors the V4 test-wrapper pattern (e.g., `MerkleProofPoseidonTest.circom`).
- `packages/circuits/test/binding/BindingParseV2Core.test.ts` — mocha + chai + circom_tester. Reads `fixture-qkb2.json`, builds the witness vector (binding bytes padded to MAX_BCANON=1024 + 12 offsets + 4 lengths + nonceBytesIn[32] + policyIdBytesIn[128] + policyVersionIn), calls `circuit.calculateWitness(input, true)`, asserts:
  - 4 deterministic spot-checks: `tsValue == 1777478400`, `policyVersion == 1`, `policyLeafHash == 0x2d00…f812 mod p`, `nonceBytes` matches fixture's `expected.nonceHex`.
  - 8 outputs structurally well-formed (lengths, ranges).

**Witness-builder code pattern** (TS):

```typescript
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { compile, type CompiledCircuit } from '../helpers/compile';
import { expect } from 'chai';

const FIXTURE_DIR = resolve(__dirname, '..', '..', 'fixtures', 'integration', 'admin-ecdsa');
const binding = readFileSync(resolve(FIXTURE_DIR, 'binding.qkb2.json'));
const fix = JSON.parse(readFileSync(resolve(FIXTURE_DIR, 'fixture-qkb2.json'), 'utf8'));

const MAX_BCANON = 1024;
const MAX_CTX = 256;
const MAX_TS_DIGITS = 20;
const MAX_POLICY_ID = 128;

function padTo(buf: Buffer, max: number): number[] {
    const out = new Array<number>(max).fill(0);
    for (let i = 0; i < buf.length; i++) out[i] = buf[i] as number;
    return out;
}

const witnessInput = {
    bytes: padTo(binding, MAX_BCANON),
    bcanonLen: binding.length,
    pkValueOffset: fix.offsets.pkValue,
    schemeValueOffset: fix.offsets.schemeValue,
    assertionsValueOffset: fix.offsets.assertionsValue,
    statementSchemaValueOffset: fix.offsets.statementSchemaValue,
    nonceValueOffset: fix.offsets.nonceValue,
    ctxValueOffset: fix.offsets.ctxValue,
    ctxHexLen: fix.lengths.ctxHex,
    policyIdValueOffset: fix.offsets.policyIdValue,
    policyIdLen: fix.lengths.policyId,
    policyLeafHashValueOffset: fix.offsets.policyLeafHashValue,
    policyBindingSchemaValueOffset: fix.offsets.policyBindingSchemaValue,
    policyVersionValueOffset: fix.offsets.policyVersionValue,
    policyVersionDigitCount: fix.lengths.policyVersionDigit,
    tsValueOffset: fix.offsets.tsValue,
    tsDigitCount: fix.lengths.tsDigit,
    versionValueOffset: fix.offsets.versionValue,
    nonceBytesIn: padTo(Buffer.from(fix.expected.nonceHex, 'hex'), 32),
    policyIdBytesIn: padTo(Buffer.from('qkb-default-ua', 'utf8'), MAX_POLICY_ID),
    policyVersionIn: fix.expected.policyVersion,
};

const circuit = await compile('binding/BindingParseV2CoreLegacyTest.circom');
const witness = await circuit.calculateWitness(witnessInput, true);
await circuit.checkConstraints(witness);
```

### Phase 3: V2CoreFast refactor (~1 day)

**Files:**
- Rename `circuits/binding/BindingParseV2Core.circom` → `circuits/binding/BindingParseV2CoreLegacy.circom`. **Keep template name** as `BindingParseV2Core` so existing V4 imports don't break.
- Create new `circuits/binding/BindingParseV2CoreFast.circom` with template name `BindingParseV2CoreFast`. Same input/output signature as Legacy.

**Refactor strategy** — for each (offset, K) pair, replace `K × Multiplexer(1, MAX_B)` with `1 × Multiplexer(K, MAX_B)`:

```circom
// LEGACY pattern (cost: 2K × MAX_B):
component pick[KEY_LEN];
for (var i = 0; i < KEY_LEN; i++) {
    pick[i] = Multiplexer(1, MAX_B);
    for (var j = 0; j < MAX_B; j++) pick[i].inp[j][0] <== bytes[j];
    pick[i].sel <== offset - KEY_LEN + i;
    pick[i].out[0] === key[i];
}

// FAST pattern (cost: (K+1) × MAX_B, ~1.8× savings):
component picker = Multiplexer(KEY_LEN, MAX_B);
for (var j = 0; j < MAX_B; j++) {
    for (var i = 0; i < KEY_LEN; i++) picker.inp[j][i] <== bytes[j];
}
picker.sel <== offset - KEY_LEN;  // start offset; output[i] = bytes[sel + i]?
```

**Caveat:** circomlib's `Multiplexer(wIn, nIn)` selects `nIn` inputs and outputs `wIn` of them ALL at the SAME selected index — that's not what we want. We want bytes at `[sel, sel+1, ..., sel+wIn-1]`. The Decoder produces a one-hot vector for `sel`; to get byte `bytes[sel+i]` we'd need a SHIFTED Decoder per `i`.

So the actual refactor pattern is: build ONE Decoder for `sel` and EscalarProduct it against wIn shifted views of `bytes`. The shifted-view trick keeps the Decoder cost amortized while the EscalarProducts give us K different outputs.

```circom
// REAL FAST pattern using one Decoder + K EscalarProducts:
component dec = Decoder(MAX_B - KEY_LEN + 1);
dec.inp <== offset - KEY_LEN;
component prod[KEY_LEN];
for (var i = 0; i < KEY_LEN; i++) {
    prod[i] = EscalarProduct(MAX_B - KEY_LEN + 1);
    for (var j = 0; j < MAX_B - KEY_LEN + 1; j++) {
        prod[i].in1[j] <== bytes[j + i];        // shifted by i
        prod[i].in2[j] <== dec.out[j];
    }
    prod[i].out === key[i];
}
```

Cost: `(MAX_B - KEY_LEN + 1) + KEY_LEN × (MAX_B - KEY_LEN + 1)` ≈ `(KEY_LEN + 1) × MAX_B`. Same as `Multiplexer(K, MAX_B)`.

The same shifted-view pattern applies to BPFSlice (fixed K bytes at offset).

### Phase 4: parity test + commit (~half day)

**Strategy:**
- Build `BindingParseV2CoreFastTest.circom` (mirrors Legacy test wrapper, swaps template).
- Add a parity test that:
  1. Constructs identical witness inputs from `fixture-qkb2.json`.
  2. Runs Legacy through `circuit.calculateWitness`, captures all 8 outputs.
  3. Runs Fast through same input, captures all 8 outputs.
  4. Asserts byte-identity for each output (pkBytes[65], nonceBytes[32], ctxBytes[256], ctxLen, policyIdBytes[128], policyLeafHash, policyVersion, tsValue).

- Add deterministic spot-checks against `fixture.expected.*`:
  1. `tsValue == 1777478400`
  2. `policyVersion == 1`
  3. `policyLeafHash` field-equivalent to `0x2d00e73da8…f812` (BN254 mod-p reduction)
  4. `nonceBytes[i] == 0xAB` for all i ∈ [0..31]

- Measure constraint count via `snarkjs r1cs info build/test-cache/<hash>/BindingParseV2CoreFastTest.r1cs`.

- Surface to lead with the empirical V2CoreFast number. Lead's spec-amendment commit (MAX_BCANON 768→1024 + envelope 1.85M→3M) is queued pending this measurement.

**Acceptance criteria:**
- Parity test green (byte-identical outputs).
- 4 deterministic spot-checks green.
- V2CoreFast constraint count <800K (target <500K, threshold for envelope amendment).
- Constraint reduction vs Legacy: ≥1.5×.

If parity test fails on ANY output, **STOP and surface immediately** — soundness regression (per lead's standing flag).

### Time budget

- Phase 2: 1-2h
- Phase 3: ~1 day
- Phase 4: ~0.5 day
- **Total: ~2 days remaining** in the 2.5-day budget. Hard cap 3 days; surface for re-decision if exceeded.

### Files to be created/modified summary

```
packages/circuits/circuits/binding/
├── BindingParseV2CoreLegacy.circom       # was BindingParseV2Core.circom
├── BindingParseV2CoreLegacyTest.circom   # NEW (Phase 2)
├── BindingParseV2CoreFast.circom         # NEW (Phase 3)
└── BindingParseV2CoreFastTest.circom     # NEW (Phase 4)

packages/circuits/test/binding/
├── BindingParseV2Core.test.ts            # NEW (Phase 2: deterministic-value spot-checks)
└── BindingParseV2CoreParity.test.ts      # NEW (Phase 4: Legacy↔Fast parity)
```

After parity passes, swap V5 main circuit's import to use Fast:
```circom
// circuits/QKBPresentationV5.circom
include "./binding/BindingParseV2CoreFast.circom";
// component parser = BindingParseV2CoreFast(MAX_BCANON, MAX_CTX, MAX_TS_DIGITS);
```

Legacy stays in tree for one V5 release as the parity reference; lead's instruction was "drop the legacy in a follow-up commit" once Fast is integrated and stable.

---

## §6. Soundness-critical items the next agent must NOT regress

1. **Bit-equivalence parity test is non-negotiable.** V2Core parses an attacker-influenced byte sequence (the canonical binding); any extraction-bug = soundness bug. If parity test fails, STOP and surface.

2. **V4 BindingParseV2Core stays in tree as `BindingParseV2CoreLegacy.circom` for parity reference.** Only delete in a follow-up commit AFTER Fast is integrated into V5 main + green for ≥1 week.

3. **Deterministic spot-checks against hand-computed expected values catches witness-builder drift, not just refactor-vs-original drift.** `tsValue`, `policyVersion`, `policyLeafHash`, `nonceBytes` all hand-checkable from `fixture-qkb2.json.expected.*`.

4. **V4 fixture `binding.qkb.json` (QKB/1.0) stays untouched** — V4 regression tests on `main` depend on it. New fixture `binding.qkb2.json` (QKB/2.0) is purely additive; do not modify or remove the V4 file.

5. **Don't touch the §4 fixed-shape walker design.** SignedAttrsParser's soundness rests on the upstream `sha256(bytes) == signedAttrsHash` binding (from §6 main + leaf-cert ECDSA). If that upstream binding is ever weakened in §6.x wiring, the §4 walker becomes insufficient and must be replaced by a position-agnostic SET OF walker. Surface to lead immediately if you find any path that doesn't satisfy that.

6. **Public-signal layout in `QKBPresentationV5.circom` is FROZEN per V5 spec §0.1 / orchestration §2.1 / arch-contracts QKBRegistryV5.PublicSignals struct.** All 14 are `signal input`s declared in canonical order in `component main { public [...] }` per CLAUDE.md invariant 8. Don't make any of them `signal output` or change order — would silently break contracts-eng's `verifyProof(uint[14] input, ...)` ABI.

7. **Constraint budget at 1.85M is invalidated** — successor should reference the post-Phase-3-measurement envelope (TBD, target ~3M). Lead's spec/plan amendment commit is queued.

---

## §7. Pending lead-side actions

1. **Spec amendment commit** (MAX_BCANON 768→1024 + envelope 1.85M→~3M). Lead writes this on `feat/v5-frontend` once V2CoreFast measurement confirms the workable parser cost. Will need cherry-picking onto `feat/v5arch-circuits` post-merge.

2. **Plan §0.4 cleanup** (Option A ctxHash wording). Lead has a backlog of plan-doc nits to fold:
   - §3 vitest-style harness → mocha+chai+circom_tester
   - §4 walker shape (fixed-shape vs scan-walker)
   - §6.1 MAX_SA value (now 1536) — already cherry-picked but plan still has `MAX_SA = 256` in step 1
   - §6.5 step 6 (synthetic-key parity OK for circuit testing — needs expansion)

3. **Real Diia QES over QKB/2.0 binding** (post-A1 task #49). Required for §6.10 E2E and §11 ceremony. Operational task: someone runs `gen-qkb-v2-core-binding.mjs`, signs the output with a Diia QES key, drops the `.p7s` next to it. Not blocking V5 circuit work.

---

## §8. Open questions / things a successor should think about

1. **Phase 1 fixture is 617B, real Diia binding is 849B.** The 232B gap means V2CoreFast's parity test exercises a DIFFERENT input length than the eventual production binding. Two options for the successor:
   - **Live with it.** V2Core parses up to MAX_BCANON=1024 regardless of input length. The 617B fixture exercises all 12 keys + 4 variable-length cases; smaller-than-real is fine for unit testing.
   - **Pad the synthetic fixture closer to 849B.** Could add filler attributes, longer policyId, longer assertions block — but this drifts further from the canonical schema. Not recommended unless something specific requires it.
   
   Recommended: live with the 617B fixture. The real-Diia-replacement (post-A1) will cover the 849B case automatically once it lands.

2. **Witness-builder API design.** Phase 2 hand-builds the 17-input witness. Once §7 (`build-witness-v5.ts`) lands, that becomes the canonical witness builder for V5. Phase 2 should write its harness in a way that's easy to refactor into the §7 builder later — i.e., as a function `buildV2CoreWitnessFromFixture(fixturePath: string): V2CoreWitnessInput`, not inline inside the test.

3. **circomlibjs `EscalarProduct` direct usage in V2CoreFast.** The Fast template will import `EscalarProduct` directly from `circomlib/circuits/multiplexer.circom` rather than going through `Multiplexer`. Slightly unusual style for this codebase — flag as "intentional, refactor-driven" in the file's docstring so a future reader doesn't try to "simplify" it back to Multiplexer.

4. **Constraint-budget calibration data point** (for §6.6+ planning):
   - Multiplexer(1, MAX_B): cost = 2 × MAX_B + 1 ≈ 2 × MAX_B
   - Multiplexer(K, MAX_B) or (Decoder + K × EscalarProduct): cost ≈ (K+1) × MAX_B
   - For K=10: ~11 × MAX_B per (offset, slice) pair instead of ~20 × MAX_B
   
   Useful for §6.x sub-budget estimation.

5. **Mocha test-isolation pattern.** Always use `mocha --no-config <file>` (not `pnpm -F @qkb/circuits exec mocha <file>`) per CLAUDE.md tip #2. The package's default mocharc glob will silently fall back to running ALL V4 tests if the path is appended after default args; this OOMed at 4GB during my §3 work. `NODE_OPTIONS='--max-old-space-size=8192'` is the right cap for V2CoreFast's larger compile.

---

## §9. Wakeup-trigger inventory

When fresh circuits-eng is spawned later, the natural pickup points are:

1. **§6.0a Phase 2-4 resumption** (immediate next step). Read this doc + `fixture-qkb2.json` + `BindingParseV2Core.circom`. Build witness harness, refactor, parity test, commit. ~2 days of focused TDD execution.

2. **§6.2-§6.10 main-circuit wiring** (post-§6.0a). Read this doc's §4 + §6.1 skeleton at commit `ea9cfd5` + `arch-contracts/src/QKBRegistryV5.sol:155` PublicSignals struct. Wire one component per commit per the §4 progression table. ~10-15h.

3. **§7 witness builder** (post-§6.10). Build `scripts/build-witness-v5.ts` that emits the V5 witness from a `binding.qkb2.json` + `fixture-qkb2.json` + leaf cert + signedAttrs DER + intermediate cert. Reuses V4 patterns at `test/integration/witness-builder.ts`.

4. **§8 stub ceremony** (post-§7). Lift V4's `stub-ceremony.sh` pattern, retarget to V5 main circuit. Produces a stub Groth16VerifierV5.sol for contracts-eng integration. Phase-1-style ceremony.

5. **§11 Phase 2 real ceremony** (post-§8 + lead-driven coordination). 20-30 contributor MPC; coordinated by lead. Worker hand-off probably preferred.

---

## §10. Quick-reference summary for the successor

- **Read first:** this doc, then `docs/superpowers/specs/2026-04-29-v5-architecture-design.md` (spec v5), then `docs/superpowers/plans/2026-04-29-v5-architecture-circuits.md` (per-worker plan; ignore stale `MAX_SA = 256` in §6.1 step 1 — use 1536).
- **Workspace:** `/data/Develop/qkb-wt-v5/arch-circuits` (worktree on `feat/v5arch-circuits`).
- **Branch tip:** `4b38667`. 15 commits since dispatch from `a3b040a`.
- **Next code change:** Phase 2 — `BindingParseV2CoreLegacyTest.circom` + `test/binding/BindingParseV2Core.test.ts`.
- **Memory cap:** `NODE_OPTIONS='--max-old-space-size=8192'` for circuit compiles.
- **Test invocation:** `pnpm exec mocha --no-config --reporter spec --timeout 600000 -r ts-node/register test/binding/BindingParseV2Core.test.ts` (CWD = `packages/circuits/`).
- **Commit message style:** Look at `4b38667` or `32bcd9c` for the multi-paragraph "what + why + verification" pattern lead expects.
- **Standing greenlight:** lead approves component-by-component commits; surface only on >50% sub-budget overrun, frozen-interface drift, parity test failure, or scope question.

End of handoff.
