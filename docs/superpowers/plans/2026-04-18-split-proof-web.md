# Split-Proof Pivot — `web-eng` Plan

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans.

**Goal:** Rewrite witness-building + registry-submission paths so the SPA generates two Groth16 proofs (leaf + chain) per QES presentation and submits them together to `QKBRegistryV3`. Update unit tests + Playwright E2E.

**Spec:** `docs/superpowers/specs/2026-04-18-split-proof-pivot.md`
**Orchestration:** `docs/superpowers/plans/2026-04-18-split-proof-orchestration.md` (READ §2 before touching anything — interface contracts are frozen)

**Worktree:** `/data/Develop/qie-wt/web` — branch `feat/qie-web`

**Tech stack:** TanStack Router, Vite, pkijs, snarkjs (browser), ethers

---

## Task W0: Orient

- [ ] **Step 1:** `cd /data/Develop/qie-wt/web && git log --oneline -10` — current head should be `8602e6d docs(web): CLAUDE.md notes for demo mode + transport + storage schema (D7)`.
- [ ] **Step 2:** Read `packages/web/CLAUDE.md` (covers witness.ts invariants, transport, storage schemas).
- [ ] **Step 3:** Read `packages/web/src/lib/witness.ts` and `packages/web/src/lib/registry.ts` end-to-end. These are the two files getting the biggest changes.

---

## Task W1: Split witness builder

**Files:**
- Modify: `packages/web/src/lib/witness.ts`
- Modify: `packages/web/tests/unit/witness.phase2.test.ts`

- [ ] **Step 1: Refactor `buildPhase2Witness`**

Current shape returns one unified witness object. New shape:

```typescript
export interface Phase2Witness {
  leaf: LeafWitness;   // feeds QKBPresentationEcdsaLeaf.wasm
  chain: ChainWitness; // feeds QKBPresentationEcdsaChain.wasm
  shared: {
    // Re-exported for convenience; both leaf + chain already carry these.
    pkX: bigint[];
    pkY: bigint[];
    ctxHash: bigint;
    declHash: bigint;
    timestamp: bigint;
    nullifier: bigint;
    leafSpkiCommit: bigint;  // same on both sides
    rTL: bigint;
    algorithmTag: number;
  };
}
```

`LeafWitness` keys (match leaf circuit's `signal input` names):
- `pkX[4]`, `pkY[4]`, `ctxHash`, `declHash`, `timestamp`, `nullifier`  (public)
- `Bcanon[MAX_BCANON]`, `BcanonLen`, `BcanonPaddedIn[MAX_BCANON]`, `BcanonPaddedLen`
- `pkValueOffset`, `schemeValueOffset`, `ctxValueOffset`, `ctxHexLen`, `declValueOffset`, `declValueLen`, `tsValueOffset`, `tsDigitCount`
- `declPaddedIn[MAX_DECL + 64]`, `declPaddedLen`
- `signedAttrs[MAX_SA]`, `signedAttrsLen`, `signedAttrsPaddedIn[MAX_SA]`, `signedAttrsPaddedLen`, `mdOffsetInSA`
- `leafDER[MAX_CERT]`, `leafSpkiXOffset`, `leafSpkiYOffset`
- `leafSigR[6]`, `leafSigS[6]`
- `subjectSerialValueOffset`, `subjectSerialValueLength`

`ChainWitness` keys (match chain circuit's `signal input` names):
- `rTL`, `algorithmTag` (public)
- `leafDER[MAX_CERT]`, `leafSpkiXOffset`, `leafSpkiYOffset`   (same values as leaf — re-supplied)
- `leafTbsPaddedIn[MAX_CERT]`, `leafTbsPaddedLen`
- `intDER[MAX_CERT]`, `intDerLen`, `intSpkiXOffset`, `intSpkiYOffset`
- `intSigR[6]`, `intSigS[6]`
- `merklePath[MERKLE_DEPTH]`, `merkleIndices[MERKLE_DEPTH]`

Shared parsing (Bcanon parse, RDN walk for subject serialNumber, leaf TBS offset discovery, SPKI coordinate extraction, intermediate cert location) is computed once and threaded into both witness objects.

- [ ] **Step 2: Rewrite the witness test**

`packages/web/tests/unit/witness.phase2.test.ts` asserts both shapes:

```typescript
it('emits leaf + chain witnesses with matching leafSpkiCommit', async () => {
  const w = await buildPhase2Witness(/* synthetic CAdES fixture */);
  expect(w.leaf).toBeDefined();
  expect(w.chain).toBeDefined();
  expect(w.shared.leafSpkiCommit).toEqual(w.leaf.leafSpkiCommit); // output from leaf
  // leaf.leafDER and chain.leafDER must be identical
  expect(w.leaf.leafDER).toEqual(w.chain.leafDER);
});
```

Plus existing assertions on nullifier correctness (with the synthetic `PNODE-12345678` fixture).

- [ ] **Step 3: Run**

```bash
pnpm -F @qkb/web test -- witness.phase2
pnpm -F @qkb/web typecheck
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add packages/web/src/lib/witness.ts packages/web/tests/unit/witness.phase2.test.ts
git commit -m "feat(web): split witness builder into leaf + chain (split-proof pivot)"
```

---

## Task W2: Split prover + registry call

**Files:**
- Modify: `packages/web/src/lib/prover.ts` (or equivalent — the snarkjs wrapper)
- Modify: `packages/web/src/lib/registry.ts`
- Modify: `packages/web/src/lib/prover.config.ts` (or wherever R2 URLs live)

- [ ] **Step 1: Update `prover.config.ts`**

```typescript
export const PROVER_CONFIG = {
  ecdsa: {
    leaf: {
      zkeyUrl: 'https://prove.identityescrow.org/ecdsa-leaf/qkb-leaf.zkey',
      zkeySha256: '<pumped from circuits>',
      wasmUrl:  'https://prove.identityescrow.org/ecdsa-leaf/QKBPresentationEcdsaLeaf.wasm',
    },
    chain: {
      zkeyUrl: 'https://prove.identityescrow.org/ecdsa-chain/qkb-chain.zkey',
      zkeySha256: '<pumped from circuits>',
      wasmUrl:  'https://prove.identityescrow.org/ecdsa-chain/QKBPresentationEcdsaChain.wasm',
    },
  },
  // rsa: {} — deferred
} as const;
```

Lead pumps the real sha256s + URLs after circuits ceremony.

- [ ] **Step 2: Rewrite prover to do two proofs**

```typescript
export async function proveQkb(witness: Phase2Witness) {
  const cfg = PROVER_CONFIG.ecdsa;  // dispatch on algorithmTag when RSA lands

  // Both proofs can run in parallel — no data dependency.
  const [leaf, chain] = await Promise.all([
    groth16FullProve(witness.leaf, cfg.leaf.wasmUrl, cfg.leaf.zkeyUrl),
    groth16FullProve(witness.chain, cfg.chain.wasmUrl, cfg.chain.zkeyUrl),
  ]);

  return {
    proofLeaf: leaf.proof,
    publicLeaf: leaf.publicSignals,  // uint256[13]
    proofChain: chain.proof,
    publicChain: chain.publicSignals, // uint256[5]
  };
}
```

- [ ] **Step 3: Rewrite `registry.register(...)` call**

Current (V2): one proof + `Inputs` struct. New (V3):

```typescript
const tx = await registryContract.register(
  {
    a: proofLeaf.pi_a.slice(0, 2),
    b: [proofLeaf.pi_b[0].slice(0, 2), proofLeaf.pi_b[1].slice(0, 2)],
    c: proofLeaf.pi_c.slice(0, 2),
  },
  {
    pkX: publicLeaf.slice(0, 4),
    pkY: publicLeaf.slice(4, 8),
    ctxHash: publicLeaf[8],
    declHash: publicLeaf[9],
    timestamp: publicLeaf[10],
    nullifier: publicLeaf[11],
    leafSpkiCommit: publicLeaf[12],
  },
  {
    a: proofChain.pi_a.slice(0, 2),
    b: [proofChain.pi_b[0].slice(0, 2), proofChain.pi_b[1].slice(0, 2)],
    c: proofChain.pi_c.slice(0, 2),
  },
  {
    rTL: publicChain[0],
    algorithmTag: publicChain[1],
    leafSpkiCommit: publicChain[2],
  },
);
```

Also update `registerEscrow` and `revokeEscrow` call sites the same way.

- [ ] **Step 4: Run unit tests**

```bash
pnpm -F @qkb/web test
pnpm -F @qkb/web typecheck
pnpm -F @qkb/web build
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/lib/prover.ts \
        packages/web/src/lib/prover.config.ts \
        packages/web/src/lib/registry.ts
git commit -m "feat(web): two-proof prove + split-proof registry.register wiring"
```

---

## Task W3: Update Playwright E2E

**Files:**
- Modify: `packages/web/tests/e2e/register.spec.ts` (or equivalent)

- [ ] **Step 1: Update E2E to handle two-proof UI state**

The UX should show dual-proof progress (leaf + chain) and a combined "generating proof…" spinner. E2E waits for both to complete, then confirms the `/register` call shape matches V3's split-proof signature.

- [ ] **Step 2: Run**

```bash
pnpm -F @qkb/web test:e2e
```

Expected: PASS (this uses the real Diia fixture from `fixtures/integration/admin-ecdsa/`).

- [ ] **Step 3: Commit**

```bash
git add packages/web/tests/e2e/register.spec.ts
git commit -m "test(web): Playwright E2E — split-proof register flow"
```

---

## Report to lead after each task

SendMessage to lead at the end of W1–W3 with:
- Task ID + short summary
- Test count (passing / total)
- Commit hash
- Any surprises

Wait for greenlight before moving on.

---

## Risks

| Risk | Trigger | Mitigation |
|---|---|---|
| Prover OOM in browser tab | Two zkeys loaded simultaneously | Run them serially rather than in parallel (slower but 1 zkey in RAM at a time) |
| Playwright flakes on long proof time | Two proofs > 60 s combined | Bump Playwright default timeout to 120 s for the register spec |
| ABI mismatch | V3 ABI pumped to web disagrees with the function signature above | Message contracts-eng; adapt to the real ABI once pumped |
