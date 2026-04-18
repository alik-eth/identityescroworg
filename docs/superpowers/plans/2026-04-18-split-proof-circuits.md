# Split-Proof Pivot — `circuits-eng` Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox syntax.

**Goal:** Revert the unified `QKBPresentationEcdsa.circom` (10.85 M constraints, impossible to setup) back to Phase-1 §5.4 split: leaf + chain circuits, glued by `leafSpkiCommit` equality on-chain. Add the person-nullifier to the leaf. Run both ceremonies on a small Fly VM. Upload to R2.

**Spec:** `docs/superpowers/specs/2026-04-18-split-proof-pivot.md`
**Orchestration:** `docs/superpowers/plans/2026-04-18-split-proof-orchestration.md` (READ §2 before touching anything — interface contracts are frozen)

**Worktree:** `/data/Develop/qie-wt/circuits` — branch `feat/qie-circuits`

**Tech stack:** circom 2.1.9, circomlib Poseidon, snarkjs 0.7.4, mocha, ts-node

---

## Task C0: Orient

- [ ] **Step 1:** `cd /data/Develop/qie-wt/circuits && git log --oneline -10` — current head should be `6c4bbe8 circuits: bump Node heap to 80 GiB for snarkjs setup`.
- [ ] **Step 2:** Read existing files into context:
  - `packages/circuits/circuits/QKBPresentationEcdsaLeaf.circom` — Phase-1 leaf; we amend this to add nullifier.
  - `packages/circuits/circuits/QKBPresentationEcdsa.circom` — unified; we DELETE this after Chain is landed.
  - `packages/circuits/circuits/primitives/NullifierDerive.circom` + `primitives/X509SubjectSerial.circom` — already built, reusable.
- [ ] **Step 3:** Note the unified circuit's `§4. sha256(leafTBS) + EcdsaP256Verify for intermediate` + `§5. Merkle canonicalize` blocks. These become the core of Chain.

---

## Task C1: Amend Leaf circuit — add nullifier

**Files:**
- Modify: `circuits/QKBPresentationEcdsaLeaf.circom`
- Modify: `test/primitives/leaf.test.ts` (if exists) or add `test/QKBPresentationEcdsaLeaf.test.ts`

- [ ] **Step 1: Add nullifier primitive to Leaf**

Edit `QKBPresentationEcdsaLeaf.circom`. Add new includes at top:

```circom
include "./primitives/NullifierDerive.circom";
include "./primitives/X509SubjectSerial.circom";
```

Inside `template QKBPresentationEcdsaLeaf()`, add after the existing inputs:

```circom
    // === NEW public signal (§14.4 person-level nullifier) ===
    signal input nullifier;

    // === NEW private inputs (nullifier extraction) ===
    signal input subjectSerialValueOffset;
    signal input subjectSerialValueLength;
```

At the bottom of the template body, before the `leafSpkiCommit` section, add:

```circom
    // =========================================================================
    // 7. Person-level nullifier (§14.4).
    // =========================================================================
    component subjectSerial = X509SubjectSerial(MAX_CERT);
    for (var i = 0; i < MAX_CERT; i++) subjectSerial.leafDER[i] <== leafDER[i];
    subjectSerial.subjectSerialValueOffset <== subjectSerialValueOffset;
    subjectSerial.subjectSerialValueLength <== subjectSerialValueLength;

    component nullifierDerive = NullifierDerive();
    for (var i = 0; i < 4; i++) {
        nullifierDerive.subjectSerialLimbs[i] <== subjectSerial.subjectSerialLimbs[i];
    }
    nullifierDerive.subjectSerialLen <== subjectSerialValueLength;
    nullifierDerive.ctxHash <== ctxHash;

    nullifierDerive.nullifier === nullifier;
```

Change the `component main` declaration at the bottom:

```circom
component main {public [pkX, pkY, ctxHash, declHash, timestamp, nullifier]}
    = QKBPresentationEcdsaLeaf();
```

This gives the 13-signal public layout per orchestration §2.1: 12 inputs + `leafSpkiCommit` output = 13 total.

- [ ] **Step 2: Local compile — SKIPPED (offloaded to Fly)**

Local workstation is RAM-constrained (31 GB total, Desktop apps + multiple claude CLIs already eating baseline). A 7.68 M-constraint circom compile peaks ~6 GB and has OOM'd local dev before. The Fly ceremony VM (C5) runs the compile anyway, with gate enforcement there. Skip local compile.

If you want a sanity check without compiling, run `grep -nE 'signal input|signal output|component' circuits/QKBPresentationEcdsaLeaf.circom` to eyeball the wire shape. The Fly ceremony script will fail-loud if constraints > 8 M.

- [ ] **Step 3: Commit**

```bash
git add circuits/QKBPresentationEcdsaLeaf.circom
git commit -m "feat(circuits): add person-nullifier to Leaf circuit (§14.4)"
```

---

## Task C2: Write Chain circuit

**Files:**
- Create: `circuits/QKBPresentationEcdsaChain.circom`

- [ ] **Step 1: Write the Chain circuit**

The Chain circuit takes the intermediate-signs-leaf + LOTL-membership constraints (§3 and §5 of the unified circuit) and emits `leafSpkiCommit` as output (computed from the same `leafDER` that the leaf circuit uses — the equality check lives on-chain between the two proofs' public signals). **Chain also reads `leafDER`** because it needs:
(a) the leaf TBS range for `sha256(leafTBS)`, and
(b) the leaf SPKI x/y bytes to compute `leafSpkiCommit`.

Create `circuits/QKBPresentationEcdsaChain.circom`:

```circom
pragma circom 2.1.9;

// QKBPresentationEcdsaChain — chain-side ECDSA proof (Phase-2 split-proof).
//
// Wires R_QKB constraints 3, 4 per spec §5.3: intermediate signs leaf,
// intermediate ∈ trusted list. Exposes `leafSpkiCommit` as a public output
// so the on-chain verifier can assert equality with the leaf proof's
// `leafSpkiCommit`, gluing the two Groth16 proofs into one R_QKB attestation.
//
// Public signals (5):
//   [0]    rTL               trusted-list Merkle root
//   [1]    algorithmTag      1 == ECDSA-P256 (literal constraint)
//   [2]    leafSpkiCommit    Poseidon2(Poseidon6(leafXLimbs), Poseidon6(leafYLimbs))
//                            — MUST match leaf proof's output signal

include "./primitives/Sha256Var.circom";
include "./primitives/EcdsaP256Verify.circom";
include "./primitives/MerkleProofPoseidon.circom";
include "./primitives/PoseidonChunkHashVar.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";

template Bytes32ToLimbs643() {
    signal input bytes[32];
    signal output limbs[6];

    component bits[32];
    signal bitStream[256];
    for (var i = 0; i < 32; i++) {
        bits[i] = Num2Bits(8);
        bits[i].in <== bytes[i];
        for (var b = 0; b < 8; b++) {
            bitStream[i * 8 + (7 - b)] <== bits[i].out[b];
        }
    }

    for (var l = 0; l < 6; l++) {
        var start = 256 - (l + 1) * 43;
        var len = 43;
        if (start < 0) { len = 43 + start; start = 0; }
        var acc = 0;
        for (var b = 0; b < len; b++) acc = acc * 2 + bitStream[start + b];
        limbs[l] <== acc;
    }
}

template QKBPresentationEcdsaChain() {
    var MAX_CERT = 1536;
    var MERKLE_DEPTH = 16;

    // === Public signals ===
    signal input rTL;
    signal input algorithmTag;
    signal output leafSpkiCommit;

    algorithmTag === 1;

    // === Private inputs ===
    signal input leafDER[MAX_CERT];
    signal input leafSpkiXOffset;
    signal input leafSpkiYOffset;

    // Leaf TBS (witness-supplied padded form; same Phase-1 trust model as
    // the unified circuit had — binding of leafTbsPaddedIn to leafDER at
    // leafTbsOffset is witness-side, not in-circuit; closed in a follow-up).
    signal input leafTbsPaddedIn[MAX_CERT];
    signal input leafTbsPaddedLen;

    // Intermediate cert + its SPKI + signature over leaf TBS
    signal input intDER[MAX_CERT];
    signal input intDerLen;
    signal input intSpkiXOffset;
    signal input intSpkiYOffset;
    signal input intSigR[6];
    signal input intSigS[6];

    // Merkle inclusion for intermediate under rTL
    signal input merklePath[MERKLE_DEPTH];
    signal input merkleIndices[MERKLE_DEPTH];

    // =========================================================================
    // 1. Extract leaf SPKI x, y from leafDER → 6×43-bit limbs → leafSpkiCommit
    // =========================================================================
    component leafX[32];
    component leafY[32];
    signal leafXBytes[32];
    signal leafYBytes[32];
    for (var i = 0; i < 32; i++) {
        leafX[i] = Multiplexer(1, MAX_CERT);
        leafY[i] = Multiplexer(1, MAX_CERT);
        for (var j = 0; j < MAX_CERT; j++) {
            leafX[i].inp[j][0] <== leafDER[j];
            leafY[i].inp[j][0] <== leafDER[j];
        }
        leafX[i].sel <== leafSpkiXOffset + i;
        leafY[i].sel <== leafSpkiYOffset + i;
        leafXBytes[i] <== leafX[i].out[0];
        leafYBytes[i] <== leafY[i].out[0];
    }
    component leafXLimbs = Bytes32ToLimbs643();
    component leafYLimbs = Bytes32ToLimbs643();
    for (var i = 0; i < 32; i++) {
        leafXLimbs.bytes[i] <== leafXBytes[i];
        leafYLimbs.bytes[i] <== leafYBytes[i];
    }

    component packX = Poseidon(6);
    component packY = Poseidon(6);
    for (var i = 0; i < 6; i++) {
        packX.inputs[i] <== leafXLimbs.limbs[i];
        packY.inputs[i] <== leafYLimbs.limbs[i];
    }
    component packXY = Poseidon(2);
    packXY.inputs[0] <== packX.out;
    packXY.inputs[1] <== packY.out;
    leafSpkiCommit <== packXY.out;

    // =========================================================================
    // 2. sha256(leafTBS) + EcdsaP256Verify with intermediate SPKI.
    // =========================================================================
    component hashTBS = Sha256Var(MAX_CERT);
    for (var i = 0; i < MAX_CERT; i++) hashTBS.paddedIn[i] <== leafTbsPaddedIn[i];
    hashTBS.paddedLen <== leafTbsPaddedLen;

    signal tbsDigestBytes[32];
    for (var i = 0; i < 32; i++) {
        var acc = 0;
        for (var b = 0; b < 8; b++) acc = acc * 2 + hashTBS.out[i * 8 + b];
        tbsDigestBytes[i] <== acc;
    }
    component tbsDigestLimbs = Bytes32ToLimbs643();
    for (var i = 0; i < 32; i++) tbsDigestLimbs.bytes[i] <== tbsDigestBytes[i];

    component intX[32];
    component intY[32];
    signal intXBytes[32];
    signal intYBytes[32];
    for (var i = 0; i < 32; i++) {
        intX[i] = Multiplexer(1, MAX_CERT);
        intY[i] = Multiplexer(1, MAX_CERT);
        for (var j = 0; j < MAX_CERT; j++) {
            intX[i].inp[j][0] <== intDER[j];
            intY[i].inp[j][0] <== intDER[j];
        }
        intX[i].sel <== intSpkiXOffset + i;
        intY[i].sel <== intSpkiYOffset + i;
        intXBytes[i] <== intX[i].out[0];
        intYBytes[i] <== intY[i].out[0];
    }
    component intXLimbs = Bytes32ToLimbs643();
    component intYLimbs = Bytes32ToLimbs643();
    for (var i = 0; i < 32; i++) {
        intXLimbs.bytes[i] <== intXBytes[i];
        intYLimbs.bytes[i] <== intYBytes[i];
    }

    component intVerify = EcdsaP256Verify();
    for (var i = 0; i < 6; i++) {
        intVerify.msghash[i] <== tbsDigestLimbs.limbs[i];
        intVerify.r[i] <== intSigR[i];
        intVerify.s[i] <== intSigS[i];
        intVerify.pubkey[0][i] <== intXLimbs.limbs[i];
        intVerify.pubkey[1][i] <== intYLimbs.limbs[i];
    }

    // =========================================================================
    // 3. Canonicalize intDER → Poseidon leaf; Merkle-verify under rTL.
    // =========================================================================
    component intHash = PoseidonChunkHashVar(MAX_CERT);
    for (var i = 0; i < MAX_CERT; i++) intHash.bytes[i] <== intDER[i];
    intHash.len <== intDerLen;

    component merkle = MerkleProofPoseidon(MERKLE_DEPTH);
    merkle.leaf <== intHash.out;
    for (var i = 0; i < MERKLE_DEPTH; i++) {
        merkle.path[i] <== merklePath[i];
        merkle.indices[i] <== merkleIndices[i];
    }
    merkle.root <== rTL;
}

component main {public [rTL, algorithmTag]}
    = QKBPresentationEcdsaChain();
```

- [ ] **Step 2: Local compile — SKIPPED (offloaded to Fly)**

Same rationale as C1 Step 2 — local workstation is RAM-constrained. Chain is smaller (~3.2 M) so it would probably fit locally, but keeping the pattern uniform: all compiles happen on the Fly ceremony VM, where the gate (hard cap 4.0 M for pow-22) fires during setup.

Eyeball the wire shape via grep if desired.

- [ ] **Step 3: Commit**

```bash
git add circuits/QKBPresentationEcdsaChain.circom
git commit -m "feat(circuits): QKBPresentationEcdsaChain — chain-side of split proof"
```

---

## Task C3: Delete unified circuit + unified test

**Files:**
- Delete: `circuits/QKBPresentationEcdsa.circom`
- Delete: any test file that references it (e.g. `test/QKBPresentationEcdsa.e2e.test.ts` if it targets the unified one). Keep leaf + chain tests.

- [ ] **Step 1: Identify dependents**

```bash
grep -rln 'QKBPresentationEcdsa\.circom\|QKBPresentationEcdsa()' circuits test scripts || true
```

If any test or helper imports the unified circuit by name, either (a) redirect to leaf/chain variants, or (b) delete. If unsure, message lead.

- [ ] **Step 2: Delete**

```bash
git rm circuits/QKBPresentationEcdsa.circom
# Delete or rewrite tests that import the unified circuit. Keep Leaf/Chain tests.
git commit -m "chore(circuits): remove unified QKBPresentationEcdsa (split-proof pivot)"
```

---

## Task C4: Update witness helpers

**Files:**
- Modify: existing witness-builder scripts (likely in `scripts/` or `test/helpers/`)

- [ ] **Step 1: Locate existing ECDSA witness builder**

```bash
grep -rln 'buildEcdsaWitness\|QKBPresentationEcdsa' scripts test src 2>/dev/null || true
```

There are likely helpers that built the unified witness. Split them into:
- `buildLeafWitness(cadesInputs, ctx, declaration, timestamp)` → emits leaf-circuit witness keys
- `buildChainWitness(cadesInputs)` → emits chain-circuit witness keys

Shared derivations (`leafSpkiCommit`, Bcanon offsets, RDN parse) live in a common helper called from both.

- [ ] **Step 2: Emit stub proof fixtures for contracts worktree**

Generate stub-verifier-compatible proof + public input JSONs for both circuits. These will be pumped by lead into the contracts worktree.

```bash
pnpm --filter @qkb/circuits tsx scripts/emit-stub-fixtures.ts  # write this script if not present
```

Expected outputs:
- `fixtures/integration/ecdsa-leaf/proof.json`
- `fixtures/integration/ecdsa-leaf/public.json`  — 13-element array
- `fixtures/integration/ecdsa-chain/proof.json`
- `fixtures/integration/ecdsa-chain/public.json` — 5-element array

The leaf `public.json[12]` and chain `public.json[2]` MUST be identical (`leafSpkiCommit`), or the on-chain equality check will fail at integration test time.

- [ ] **Step 3: Commit**

```bash
git add scripts/emit-stub-fixtures.ts \
        fixtures/integration/ecdsa-leaf/*.json \
        fixtures/integration/ecdsa-chain/*.json
git commit -m "chore(circuits): split witness builders + stub proof fixtures (leaf + chain)"
```

---

## Task C5: Run leaf ceremony on Fly

**Files:**
- Modify: `ceremony/scripts/fly-ceremony-ecdsa.sh` — split into `fly-ceremony-leaf.sh` and `fly-ceremony-chain.sh`, or parameterize.

- [ ] **Step 1: Parameterize or rewrite the ceremony script**

Key changes vs the existing unified script:
- `PTAU_POWER=24` for leaf, `PTAU_POWER=22` for chain
- `CIRCUIT_NAME=QKBPresentationEcdsaLeaf` or `QKBPresentationEcdsaChain` (env-parameterized)
- VM `--vm-memory 16384` (down from 98304)
- Gate constraint cap: 8 M leaf, 4 M chain
- R2 upload path: `ecdsa-leaf/` vs `ecdsa-chain/`

- [ ] **Step 2: Fly machine run — leaf**

```bash
fly machine run ubuntu:22.04 \
  --app qkb-ceremony \
  --region ams \
  --vm-size performance-4x \
  --vm-memory 16384 \
  --volume qkb_ceremony:/data \
  --volume-size 60 \
  --env CIRCUIT_NAME=QKBPresentationEcdsaLeaf \
  --env PTAU_POWER=24 \
  --env CEREMONY_BRANCH=feat/qie-circuits \
  --env R2_ACCOUNT_ID=$R2_ACCOUNT_ID \
  --env R2_ACCESS_KEY_ID=$R2_ACCESS_KEY_ID \
  --env R2_SECRET_ACCESS_KEY=$R2_SECRET_ACCESS_KEY \
  --env R2_BUCKET=$R2_BUCKET \
  -- bash -c "curl -fsSL https://raw.githubusercontent.com/alik-eth/identityescroworg/feat/qie-circuits/packages/circuits/ceremony/scripts/fly-ceremony-split.sh | bash"
```

Monitor via `fly logs -a qkb-ceremony`. Expected setup time: ~25 min.

- [ ] **Step 3: Pull artifacts + commit metadata**

After ceremony completes, SFTP-pull `QKBGroth16Verifier.sol` → rename to `QKBGroth16VerifierEcdsaLeaf.sol`. Pull `verification_key.json` + `zkey.sha256`. Commit under `ceremony/ecdsa-leaf/`.

```bash
git add ceremony/ecdsa-leaf/QKBGroth16VerifierEcdsaLeaf.sol \
        ceremony/ecdsa-leaf/verification_key.json \
        ceremony/ecdsa-leaf/zkey.sha256 \
        ceremony/urls.json   # update with leaf zkey URL + sha256
git commit -m "ceremony(circuits): leaf ECDSA groth16 — v1"
```

- [ ] **Step 4: Destroy the machine**

```bash
MACHINE_ID=$(fly machines list -a qkb-ceremony --json | jq -r '.[0].id')
fly machine destroy $MACHINE_ID -a qkb-ceremony --force
```

---

## Task C6: Run chain ceremony on Fly

Same pattern as C5 with `CIRCUIT_NAME=QKBPresentationEcdsaChain`, `PTAU_POWER=22`. Smaller ptau, smaller zkey, ~10 min compute. Upload to `ecdsa-chain/`.

- [ ] **Step 1:** Execute ceremony.
- [ ] **Step 2:** Pull + commit `ceremony/ecdsa-chain/QKBGroth16VerifierEcdsaChain.sol` + VK + hash.
- [ ] **Step 3:** Update `ceremony/urls.json` with chain entries.
- [ ] **Step 4:** Destroy the machine.
- [ ] **Step 5: Commit**

```bash
git add ceremony/ecdsa-chain/* ceremony/urls.json
git commit -m "ceremony(circuits): chain ECDSA groth16 — v1"
```

---

## Task C7: Integration test

**Files:**
- Create: `test/integration/split-proof-roundtrip.test.ts`

- [ ] **Step 1: Write a mocha integration test**

Loads Diia admin fixture, builds both witnesses, runs both Groth16 provers against the ceremony outputs from C5/C6, asserts both proofs verify locally via `snarkjs.groth16.verify`, asserts `leafPublic[12] === chainPublic[2]`, asserts leaf public `nullifier` matches `fixtures/nullifier-kat.json#admin-ecdsa.nullifier`.

- [ ] **Step 2: Run**

```bash
pnpm --filter @qkb/circuits test -- --match split-proof-roundtrip
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add test/integration/split-proof-roundtrip.test.ts
git commit -m "test(circuits): split-proof round-trip integration — leaf+chain+equality"
```

---

## Report to lead after each task

SendMessage to lead at the end of each task (C1–C7) with:
- Task ID + short summary (1 line)
- Constraint count (if compilation happened)
- Commit hash
- Any surprises or deviations

Do NOT proceed to the next task without lead greenlight — except C1→C2 which can run back-to-back since both just touch circuits.

---

## Risks

| Risk | Trigger | Mitigation |
|---|---|---|
| Leaf constraint blow-up | C1 Step 2 > 7.95 M | Message lead — possible `X509SubjectSerial` optimization or MAX_CERT trim |
| Chain constraint blow-up | C2 Step 2 > 4.0 M | Message lead — possible MAX_CERT trim or Merkle depth cut |
| Fly machine OOM | C5/C6 setup crashes | `fly machine destroy`, re-run with `performance-8x:32768MB` |
| R2 upload fails | C5/C6 Step 3 | Re-run just the upload; zkey is preserved on `/data` volume |
