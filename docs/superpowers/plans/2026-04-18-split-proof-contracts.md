# Split-Proof Pivot — `contracts-eng` Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox syntax.

**Goal:** Rewrite `QKBVerifier.sol` and deploy `QKBRegistryV3` to accept a split leaf+chain proof pair instead of one unified 14-signal proof. Keep the rest of the Phase-2 surface (arbitrators, escrow, nullifier maps, declHash whitelist) intact.

**Spec:** `docs/superpowers/specs/2026-04-18-split-proof-pivot.md`
**Orchestration:** `docs/superpowers/plans/2026-04-18-split-proof-orchestration.md` (READ §2 before touching anything — interface contracts are frozen)

**Worktree:** `/data/Develop/qie-wt/contracts` — branch `feat/qie-contracts`

**Tech stack:** Solidity 0.8.24, Foundry (forge-std v1.9.4, OpenZeppelin v5.1.0)

---

## Task K0: Orient

- [ ] **Step 1:** `cd /data/Develop/qie-wt/contracts && git log --oneline -10` — current head should be `bd78b14 chore(contracts): pump Sepolia v2 deploy addresses`.
- [ ] **Step 2:** Read `packages/contracts/CLAUDE.md` §13 end-to-end. You will be rewriting §13.1 + §13.2 + adding §13.11 for the split-proof change.
- [ ] **Step 3:** Read existing `src/QKBVerifier.sol` and `src/QKBRegistry.sol`. You're producing `src/QKBVerifier.sol` (rewrite) + `src/QKBRegistryV3.sol` (new). V2 stays in place (no deletes).

---

## Task K1: Split `QKBVerifier` library

**Files:**
- Modify: `src/QKBVerifier.sol`
- Modify: `test/QKBVerifier.t.sol`

- [ ] **Step 1: Redefine `Inputs` as `LeafInputs` + `ChainInputs`**

```solidity
interface IGroth16LeafVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[13] calldata input
    ) external view returns (bool);
}

interface IGroth16ChainVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[5] calldata input
    ) external view returns (bool);
}

library QKBVerifier {
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    /// Leaf public signals (13) — §14.3 split-proof pivot:
    ///   [0..3]   pkX limbs
    ///   [4..7]   pkY limbs
    ///   [8]      ctxHash
    ///   [9]      declHash
    ///   [10]     timestamp
    ///   [11]     nullifier
    ///   [12]     leafSpkiCommit  (output)
    struct LeafInputs {
        uint256[4] pkX;
        uint256[4] pkY;
        bytes32    ctxHash;
        bytes32    declHash;
        uint64     timestamp;
        bytes32    nullifier;
        bytes32    leafSpkiCommit;
    }

    /// Chain public signals (5):
    ///   [0]      rTL
    ///   [1]      algorithmTag (0=RSA, 1=ECDSA)
    ///   [2]      leafSpkiCommit (output)
    struct ChainInputs {
        bytes32 rTL;
        uint8   algorithmTag;
        bytes32 leafSpkiCommit;
    }

    function verify(
        IGroth16LeafVerifier  lv,
        IGroth16ChainVerifier cv,
        Proof memory proofLeaf,
        LeafInputs memory inputsLeaf,
        Proof memory proofChain,
        ChainInputs memory inputsChain
    ) internal view returns (bool) {
        if (!DeclarationHashes.isAllowed(inputsLeaf.declHash)) return false;
        if (inputsLeaf.leafSpkiCommit != inputsChain.leafSpkiCommit) return false;

        uint256[13] memory leafArr;
        leafArr[0] = inputsLeaf.pkX[0];
        leafArr[1] = inputsLeaf.pkX[1];
        leafArr[2] = inputsLeaf.pkX[2];
        leafArr[3] = inputsLeaf.pkX[3];
        leafArr[4] = inputsLeaf.pkY[0];
        leafArr[5] = inputsLeaf.pkY[1];
        leafArr[6] = inputsLeaf.pkY[2];
        leafArr[7] = inputsLeaf.pkY[3];
        leafArr[8] = uint256(inputsLeaf.ctxHash);
        leafArr[9] = uint256(inputsLeaf.declHash);
        leafArr[10] = uint256(inputsLeaf.timestamp);
        leafArr[11] = uint256(inputsLeaf.nullifier);
        leafArr[12] = uint256(inputsLeaf.leafSpkiCommit);

        uint256[5] memory chainArr;
        chainArr[0] = uint256(inputsChain.rTL);
        chainArr[1] = uint256(inputsChain.algorithmTag);
        chainArr[2] = uint256(inputsChain.leafSpkiCommit);

        if (!lv.verifyProof(proofLeaf.a, proofLeaf.b, proofLeaf.c, leafArr)) return false;
        if (!cv.verifyProof(proofChain.a, proofChain.b, proofChain.c, chainArr)) return false;

        return true;
    }

    function toPkAddress(uint256[4] memory pkX, uint256[4] memory pkY)
        internal pure returns (address)
    {
        uint256 x = _packLimbsLE(pkX);
        uint256 y = _packLimbsLE(pkY);
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes32(x), bytes32(y))))));
    }

    function _packLimbsLE(uint256[4] memory limbs) private pure returns (uint256) {
        return limbs[0] | (limbs[1] << 64) | (limbs[2] << 128) | (limbs[3] << 192);
    }
}
```

- [ ] **Step 2: Rewrite `test/QKBVerifier.t.sol`**

Update every test that constructed `Inputs` to construct the new `LeafInputs` + `ChainInputs` instead. Add:
- `test_verify_rejectsCommitMismatch()` — different `leafSpkiCommit` in leaf vs chain returns false.
- `test_verify_rejectsBadDeclHash()` — unchanged semantics, now checks leaf's declHash.

- [ ] **Step 3: Run**

```bash
forge test --match-path 'packages/contracts/test/QKBVerifier.t.sol' -vv
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/QKBVerifier.sol test/QKBVerifier.t.sol
git commit -m "feat(contracts): split QKBVerifier into leaf+chain (split-proof pivot)"
```

---

## Task K2: Rename V2 integration test path + pump leaf/chain stub verifiers

**Files:**
- Rename: `test/fixtures/integration/ecdsa/` → `test/fixtures/integration/ecdsa-legacy-unified/` (quarantine)
- Create: `test/fixtures/integration/ecdsa-leaf/` + `ecdsa-chain/` directories
- Create: `src/verifiers/QKBGroth16VerifierStubEcdsaLeaf.sol` + `QKBGroth16VerifierStubEcdsaChain.sol` (lead will pump)

- [ ] **Step 1:** Wait for lead pump. Lead will message when leaf+chain stub verifier .sol files land in `src/verifiers/` (from circuits worktree).
- [ ] **Step 2: Rewrite `test/QKBGroth16VerifierStub.integration.t.sol`**

```solidity
// Assert:
// - Accept-pumped-leaf: real leaf stub proof verifies
// - Accept-pumped-chain: real chain stub proof verifies
// - Reject-cross: leaf proof submitted as chain proof fails (different public-input width)
// - Reject-tampered-leaf-proof
// - Reject-tampered-chain-proof
// - End-to-end: QKBVerifier.verify(...) returns true with matching leafSpkiCommit
// - End-to-end: returns false with mismatched leafSpkiCommit
```

- [ ] **Step 3: Run**

```bash
forge test --match-path 'packages/contracts/test/QKBGroth16VerifierStub.integration.t.sol' -vvv
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/verifiers/QKBGroth16VerifierStubEcdsaLeaf.sol \
        src/verifiers/QKBGroth16VerifierStubEcdsaChain.sol \
        test/fixtures/integration/ecdsa-leaf/* \
        test/fixtures/integration/ecdsa-chain/* \
        test/QKBGroth16VerifierStub.integration.t.sol
git commit -m "test(contracts): split-proof stub integration (leaf + chain + commit match)"
```

---

## Task K3: Write `QKBRegistryV3`

**Files:**
- Create: `src/QKBRegistryV3.sol`
- Create: `test/QKBRegistryV3.register.t.sol`
- Create: `test/QKBRegistryV3.escrow.t.sol`
- Create: `test/QKBRegistryV3.nullifier.t.sol`

- [ ] **Step 1: Write V3 from V2**

Copy `src/QKBRegistry.sol` to `src/QKBRegistryV3.sol`. Replace:

- Verifier slots: from (`rsaVerifier`, `ecdsaVerifier`) to (`rsaLeafVerifier`, `rsaChainVerifier`, `ecdsaLeafVerifier`, `ecdsaChainVerifier`). Four settable slots, four setters + events.
- `register`, `registerEscrow`, `revokeEscrow` signatures: take `(proofLeaf, leafInputs, proofChain, chainInputs)` pairs.
- Dispatch: `chainInputs.algorithmTag == 0` → rsa pair; `== 1` → ecdsa pair; else `UnknownAlgorithm()`.
- `_authorizeBinding(leafInputs, chainInputs, proofLeaf, proofChain)` — internal gate. Calls `QKBVerifier.verify(leafVerifier, chainVerifier, ...)`. On success returns `pkAddr = QKBVerifier.toPkAddress(leafInputs.pkX, leafInputs.pkY)`.
- Store `nullifier` from `leafInputs.nullifier`; store `rTL` equality check against registry's `trustedListRoot` from `chainInputs.rTL`.

New error:
```solidity
error LeafSpkiCommitMismatch();
```

Revert taxonomy from V2 otherwise unchanged (AlreadyBound, NullifierUsed, RootMismatch, BindingTooOld, BindingFromFuture, InvalidProof, UnknownAlgorithm, NotAdmin, ZeroAddress, NotBound, BadExpireSig, EscrowExists, NoEscrow, EscrowAlreadyRevoked, EscrowExpiryInPast, NullifierAlreadyRevoked, UnknownNullifier).

`isActiveAt`, `expire`, `usedNullifiers`, `nullifierToPk`, `revokedNullifiers`, `revokeNullifier`, `escrows` — same semantics as V2.

- [ ] **Step 2: Port `test/QKBRegistry.*.t.sol` suites to V3**

Four test files: `test/QKBRegistryV3.register.t.sol`, `QKBRegistryV3.expire.t.sol`, `QKBRegistryV3.isActiveAt.t.sol`, `QKBRegistryV3.escrow.t.sol`, `QKBRegistryV3.nullifier.t.sol`, `QKBRegistryV3.admin.t.sol`.

For each V2 test, duplicate and adapt:
- Construct `LeafInputs` + `ChainInputs` instead of `Inputs`.
- `register(proofLeaf, leafInputs, proofChain, chainInputs)`.
- Add a new revert case: `test_register_revertsLeafSpkiCommitMismatch()`.

Use stub verifiers that accept any 13-signal/5-signal input (the Phase-1 `StubGroth16Verifier` pattern).

- [ ] **Step 3: Run full test suite**

```bash
forge test -vv
```

Expected: PASS.

- [ ] **Step 4: Refresh gas snapshot**

```bash
forge snapshot --snap packages/contracts/snapshots/gas-snapshot.txt
```

Expected register gas: ~180 k–220 k (higher than V2's 120 k — two Groth16 verify calls instead of one).

- [ ] **Step 5: Commit**

Split into reviewable chunks:

```bash
git add src/QKBRegistryV3.sol
git commit -m "feat(contracts): QKBRegistryV3 — split-proof register surface"

git add test/QKBRegistryV3.*.t.sol
git commit -m "test(contracts): QKBRegistryV3 full suite (register, expire, escrow, nullifier, admin)"

git add packages/contracts/snapshots/gas-snapshot.txt
git commit -m "chore(contracts): refresh gas snapshot for V3 split-proof register"
```

---

## Task K4: Deploy script for V3

**Files:**
- Create: `script/DeployRegistryV3.s.sol`

- [ ] **Step 1: Write the script**

Reads from env:
- `ROOT_TL`
- `ADMIN_PRIVATE_KEY`, `ADMIN_ADDRESS`
- `RSA_LEAF_VERIFIER_ADDR`, `RSA_CHAIN_VERIFIER_ADDR` (optional → stub fallbacks)
- `ECDSA_LEAF_VERIFIER_ADDR`, `ECDSA_CHAIN_VERIFIER_ADDR` (optional → stub fallbacks)

Deploys any missing verifiers as `StubGroth16Verifier` bindings matching each slot's public-signal width. Then deploys `QKBRegistryV3(admin, rootTL, rsaLeaf, rsaChain, ecdsaLeaf, ecdsaChain)`. Logs the address.

- [ ] **Step 2: Anvil dry-run**

```bash
anvil --port 8545 &
forge script packages/contracts/script/DeployRegistryV3.s.sol --fork-url http://localhost:8545 -vv
```

Expected: deploys clean.

- [ ] **Step 3: Commit**

```bash
git add script/DeployRegistryV3.s.sol
git commit -m "script(contracts): DeployRegistryV3 — fresh split-proof registry"
```

---

## Task K5: MIGRATION.md update

**Files:**
- Modify: `packages/contracts/MIGRATION.md`

- [ ] **Step 1:** Add a §V2 → V3 section documenting:
- V3 is a fresh deploy at a new address (not upgrade; storage layout changes).
- Holders who registered against V2 must re-register against V3 with a split-proof pair.
- Relying-party dual-lookup pattern: query V2 first (Phase-1 legacy holders), fall back to V3 (split-proof holders).
- Sepolia V2 at `0xcac30ff7B0566b6E991061cAA5C169c82A4319a4` is abandoned (had no real registrations).

- [ ] **Step 2: Commit**

```bash
git add MIGRATION.md
git commit -m "docs(contracts): MIGRATION.md — V2 → V3 split-proof pivot"
```

---

## Report to lead after each task

SendMessage to lead at the end of K1–K5 with:
- Task ID + short summary
- `forge test` line counts (passing / total)
- Commit hash(es)
- Any surprises

Wait for greenlight before moving on. K1→K2 can run back-to-back if K1 is trivially green.

---

## Risks

| Risk | Trigger | Mitigation |
|---|---|---|
| Gas regression > 250 k for V3 register | K3 Step 4 | Message lead; acceptable up to 300 k given dual Groth16 verify. Beyond that, profile. |
| Stub verifier width mismatch | Pumped stub .sol has wrong `uint256[N]` signature | Lead re-pumps with correct width from circuits; block K2. |
| Storage layout surgery for V3 | Accidentally extending V2 instead of fresh V3 | V3 MUST NOT inherit V2. Fresh contract. |
