# Wallet-Bound Nullifier — circuits-eng Implementation Plan

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **For circuits-eng:** Implement the spec at `docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md`. Follow superpowers:test-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `QKBPresentationV5.circom` to emit the V5.1 19-field public-signal layout, fold `rotation_mode` into the main circuit, ship updated witness builder + stub ceremony zkey for cross-package integration.

**Architecture:** Public-signal layout grows from 14 → 19. New private input `walletSecret`. Three new Poseidon₂ outputs (`identityFingerprint`, `identityCommitment`, `nullifier` re-derived). Rotation logic gated on `rotation_mode` flag using `ForceEqualIfEnabled` (existing primitive in circomlib). New witness builder input/output schema.

**Tech Stack:** Circom 2.1.9, snarkjs ≥0.7.4, BN254, Poseidon₂/T3 primitive (already in use).

**Branch:** `feat/v5arch-circuits` (worktree at `/data/Develop/qkb-wt-v5/arch-circuits/`).

**Wall estimate:** 3 days.

---

## Task 1: Update `QKBPresentationV5.circom` with V5.1 signals

**Files:**
- Modify: `packages/circuits/circuits/QKBPresentationV5.circom`
- Reference: spec §"Construction" + §"Public-signal layout (V5 → V5.1)"

- [ ] **Step 1: Add new private input** `walletSecret` — a single BN254 field element. Off-circuit derivation produces 32 bytes (HKDF or Argon2id), then truncates the top 2 bits via `& ((1<<254)-1)` mask before packing into the field element. This avoids overflow against the BN254 scalar field (~254 bits) without limb-splitting. The mask is documented in spec §"Wallet-secret derivation" — entropy loss is 2 bits, security stays at 254-bit. The signal type is `signal input walletSecret;` (NOT a 2-element array).

- [ ] **Step 2: Add three new public outputs**: `identityFingerprint`, `identityCommitment`, plus three rotation-mode outputs `rotationMode`, `rotationOldCommitment`, `rotationNewWallet`.

- [ ] **Step 3: Re-derive `nullifier`** from `(walletSecret, ctxHash)` instead of subjectSerial-derived secret. Replace existing `NullifierDerive` invocation.

- [ ] **Step 4: Compute `identityFingerprint`** as `Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)`. `subjectSerialPacked` is the existing `Poseidon₅(subjectSerialLimbs, subjectSerialLen)` — share the wire from existing primitive.

- [ ] **Step 5: Compute `identityCommitment`** as `Poseidon₂(subjectSerialPacked, walletSecret)`.

- [ ] **Step 6: Implement rotation_mode gates** using `ForceEqualIfEnabled`:
  - When `rotationMode == 0` (register): `rotationOldCommitment === identityCommitment` AND `rotationNewWallet === msgSender`.
  - When `rotationMode == 1` (rotate): no constraint on `rotationOldCommitment` (consumer supplies the prior commitment from on-chain) AND `rotationNewWallet === msgSender`.
  - The circuit cannot enforce "rotationOldCommitment matches the on-chain stored commitment" — that's a contract-side gate.

- [ ] **Step 7: Verify constraint count** stays under 4.5M (per spec envelope). Run `circom --r1cs --inspect` and check the report. Expected delta: +800 to +3K constraints. Document the actual count.

- [ ] **Step 8: Run circuit unit tests** (existing `tests/QKBPresentationV5.test.ts` etc.) — they will fail because of signal layout change; that's the next task.

- [ ] **Step 9: Commit**

```bash
git add packages/circuits/circuits/QKBPresentationV5.circom
git commit -m "circuits(v51): add walletSecret + 5 new public signals + rotation_mode gates"
```

---

## Task 2: Update witness builder `build-witness-v5.ts` → V5.1

**Files:**
- Modify: `packages/circuits/src/build-witness-v5.ts`
- Test: `packages/circuits/tests/build-witness-v5.test.ts`
- Reference: spec §"Witness-builder API impact"

- [ ] **Step 1: Update interface** `WitnessV5Inputs` → `WitnessV51Inputs`. Add `walletSecret: Buffer` (32 bytes) field. Document derivation responsibility (caller derives via HKDF or Argon2id; circuit doesn't care).

- [ ] **Step 2: Update output type** `WitnessV5Output` → `WitnessV51Output`. Add 5 new public-signal fields.

- [ ] **Step 3: Implement `deriveWalletSecret(privateKey, subjectSerialPacked)`** helper function for tests. EOA-only path (HKDF over personal_sign). Web-eng has the production path; this is just for circuit-level test fixtures.

- [ ] **Step 4: Update `buildWitnessV5()` → `buildWitnessV51()`** to populate the 19-field public-signal array in the frozen index order from §1.1 of orchestration plan.

- [ ] **Step 5: Add `rotation_mode` parameter** with default 0 (register). When 1 (rotate), takes `rotationOldCommitment` and `rotationNewWallet` as additional inputs.

- [ ] **Step 6: Update existing tests** for new signal layout. All 14 existing register tests should pass with new shape. Add 3 new tests for rotateWallet path.

- [ ] **Step 7: Run tests**

```bash
pnpm -F @zkqes/circuits test
```
Expected: green.

- [ ] **Step 8: Commit**

```bash
git add packages/circuits/src/build-witness-v5.ts packages/circuits/tests/build-witness-v5.test.ts
git commit -m "circuits(v51): witness builder for 19-field publicSignals + rotateWallet path"
```

---

## Task 3: Real-Diia .p7s round-trip with V5.1

**Files:**
- Modify: `packages/circuits/tests/real-diia-e2e.test.ts`
- Reference: spec §"Soundness invariants"

- [ ] **Step 1: Update real-Diia E2E test** to derive `walletSecret` via the new helper, build V5.1 witness, run snarkjs prove + verify against stub zkey.

- [ ] **Step 2: Add register-repeat-claim test**: same identity, same wallet, fresh ctx → produces a different nullifier, same fingerprint, same commitment.

- [ ] **Step 3: Add rotate-wallet test**: build a witness with `rotation_mode=1` + valid old-wallet sig + new wallet → proof verifies.

- [ ] **Step 4: Run full circuit test suite**

```bash
pnpm -F @zkqes/circuits test:real-diia
```
Expected: 4/4 (existing) + 2/2 (new) green.

- [ ] **Step 5: Commit**

```bash
git add packages/circuits/tests/real-diia-e2e.test.ts
git commit -m "circuits(v51): real-Diia E2E for register-repeat + rotateWallet paths"
```

---

## Task 4: Generate stub V5.1 zkey + verifier

**Files:**
- Modify: `packages/circuits/scripts/build-ceremony-stub-v5.ts`
- Output: `packages/circuits/ceremony/v5_1/qkb-v5_1-stub.zkey`, `packages/circuits/ceremony/v5_1/Groth16VerifierV5_1Stub.sol`, `packages/circuits/ceremony/v5_1/verification_key.json`

- [ ] **Step 1: Update ceremony script** to invoke the V5.1 main circuit. Single-contributor "stub ceremony" — admin's contribution only, NOT the production pot23 multi-contributor flow.

- [ ] **Step 2: Generate stub zkey** via `snarkjs groth16 setup` + `snarkjs zkey contribute` with admin entropy.

- [ ] **Step 3: Auto-generate Groth16VerifierV5_1Stub.sol** via `snarkjs zkey export solidityverifier`. Class name should be `Groth16VerifierV5_1Stub` (with the `Stub` suffix to match existing V5 pattern).

- [ ] **Step 4: Auto-generate verification_key.json**.

- [ ] **Step 5: Run verify-against-sample test**: build a sample V5.1 proof from real Diia .p7s + dummy walletSecret → verify against this stub zkey via `groth16.verify`. Must succeed.

- [ ] **Step 6: Commit**

```bash
git add packages/circuits/scripts/build-ceremony-stub-v5.ts \
        packages/circuits/ceremony/v5_1/qkb-v5_1-stub.zkey \
        packages/circuits/ceremony/v5_1/Groth16VerifierV5_1Stub.sol \
        packages/circuits/ceremony/v5_1/verification_key.json
git commit -m "circuits(v51): stub ceremony zkey + auto-generated verifier for integration"
```

---

## Task 5: Update CLAUDE.md package invariants

**Files:**
- Modify: `packages/circuits/CLAUDE.md`

- [ ] **Step 1: Add V5.1 invariants section**. List the 19-field public-signal layout, the 5 new soundness invariants (per spec §"Soundness invariants"), the wallet-uniqueness rule, and the rotation_mode gate semantics.

- [ ] **Step 2: Document witness-builder API change** — `walletSecret` is the new private input; callers derive via HKDF (EOA) or Argon2id (SCW); circuit treats it as opaque 32-byte field element.

- [ ] **Step 3: Commit**

```bash
git add packages/circuits/CLAUDE.md
git commit -m "circuits(v51): document new invariants + witness API in CLAUDE.md"
```

---

## Verification (lead runs after each commit)

```bash
pnpm -F @zkqes/circuits test           # 70+ tests, all green
pnpm -F @zkqes/circuits typecheck      # clean
pnpm -F @zkqes/circuits build          # circuit recompiles + R1CS regenerates
```

Lead inspects diff for:
- No out-of-scope file changes (circuit primitives folder, top-level circuit only)
- Constraint count delta documented
- Stub artifacts committed

## Artifact pump (lead, after Task 4 lands)

```bash
cp /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/ceremony/v5_1/Groth16VerifierV5_1Stub.sol \
   /data/Develop/qkb-wt-v5/arch-contracts/packages/contracts/src/

cp /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/ceremony/v5_1/verification_key.json \
   /data/Develop/qkb-wt-v5/arch-web/packages/sdk/fixtures/v5_1/

git -C /data/Develop/qkb-wt-v5/arch-contracts add packages/contracts/src/Groth16VerifierV5_1Stub.sol
git -C /data/Develop/qkb-wt-v5/arch-contracts commit -m "chore(contracts): pump Groth16VerifierV5_1Stub.sol from circuits"

git -C /data/Develop/qkb-wt-v5/arch-web add packages/sdk/fixtures/v5_1/verification_key.json
git -C /data/Develop/qkb-wt-v5/arch-web commit -m "chore(sdk): pump v5_1 verification_key from circuits"
```
