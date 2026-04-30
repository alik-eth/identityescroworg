# Wallet-Bound Nullifier — contracts-eng Implementation Plan

> **For contracts-eng:** Implement the spec at `docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md` and your own contract review at `docs/superpowers/specs/2026-04-30-issuer-blind-nullifier-contract-review.md` (filename retained from earlier draft). Follow superpowers:test-driven-development.

**Goal:** Extend `QKBRegistryV5.sol` to V5.1: new mappings, new register flow with first-claim/repeat-claim/wallet-uniqueness gates, new `rotateWallet()` function, drop `registrantOf`, preserve `nullifierOf` write-once. NFT contract is NOT modified.

**Architecture:** 3 new mappings + drop 1 + rotateWallet entry point + `Groth16VerifierV5_1Stub` integration + ABI bump propagation to `@qkb/contracts-sdk`. NFT cross-coupling is OUT (per user directive 2026-04-30 NFT-decoupling).

**Tech Stack:** Solidity ^0.8.20, foundry, EIP-7212 P-256 precompile (Base mainnet/Sepolia native).

**Branch:** `feat/v5arch-contracts` (worktree at `/data/Develop/qkb-wt-v5/arch-contracts/`).

**Wall estimate:** 2 days.

---

## Task 1: Add new mappings + drop `registrantOf`

**Files:**
- Modify: `packages/contracts/src/QKBRegistryV5.sol` (rename references but keep file name to minimize churn — the contract version bump is logical, not a fresh file)
- Test: `packages/contracts/test/QKBRegistryV5.t.sol`
- Reference: orchestration §1.4

- [ ] **Step 1: Add new state mappings** at top of contract:
```solidity
mapping(bytes32 => bytes32) public identityCommitments;
mapping(bytes32 => address) public identityWallets;
mapping(bytes32 => mapping(bytes32 => bool)) public usedCtx;
```

- [ ] **Step 2: Drop `registrantOf` mapping**. Anti-Sybil migrates to `usedCtx`. No callers post-amendment (verified via grep across `packages/contracts/`, `packages/contracts-sdk/`, `packages/sdk/`).

- [ ] **Step 3: Test that drop is safe** — add a test that grep's the codebase for `registrantOf` and asserts no live references outside this contract file. (Belt-and-suspenders check.)

- [ ] **Step 4: Commit**

```bash
forge build && forge test
git add packages/contracts/src/QKBRegistryV5.sol packages/contracts/test/QKBRegistryV5.t.sol
git commit -m "contracts(v51): add identityCommitments/identityWallets/usedCtx + drop registrantOf"
```

---

## Task 2: Update `register()` for V5.1 19-field publicSignals + first-claim path

**Files:**
- Modify: `packages/contracts/src/QKBRegistryV5.sol`
- Test: `packages/contracts/test/QKBRegistryV5_1.t.sol` (NEW)
- Reference: spec §"register() flow" + §"Soundness invariants 1-5"

- [ ] **Step 1: Update register signature** to take `uint256[19] calldata publicSignals` (was 14).

- [ ] **Step 2: Unpack new fields**:
```solidity
bytes32 fingerprint           = bytes32(publicSignals[14]);
bytes32 commitment            = bytes32(publicSignals[15]);
uint256 mode                  = publicSignals[16];
bytes32 oldCommitment         = bytes32(publicSignals[17]);
address newWallet             = address(uint160(publicSignals[18]));
```

- [ ] **Step 3: Enforce register-mode gate**: `require(mode == 0, "wrong mode for register")`.

- [ ] **Step 4: Compute `ctxKey`** via the simplified Hi/Lo concat:
```solidity
bytes32 ctxKey = bytes32((uint256(publicSignals[3]) << 128) | uint256(publicSignals[4]));
```

- [ ] **Step 5: Implement first-claim branch** (`identityCommitments[fp] == 0`):
  - `require(nullifierOf[msg.sender] == 0, "wallet already has identity")` — wallet uniqueness.
  - `identityCommitments[fp] = commitment`
  - `identityWallets[fp] = msg.sender`
  - `usedCtx[fp][ctxKey] = true`
  - `nullifierOf[msg.sender] = nul` (write-once)

- [ ] **Step 6: Implement repeat-claim branch** (`identityCommitments[fp] != 0`):
  - **Stale-bind check FIRST** (invariant 2): `require(identityWallets[fp] == msg.sender, "wallet not bound to this identity")`.
  - `require(identityCommitments[fp] == commitment, "commitment mismatch")` — same wallet must produce same commitment.
  - `require(!usedCtx[fp][ctxKey], "ctx already used for this identity")`.
  - `usedCtx[fp][ctxKey] = true`.
  - DO NOT touch `nullifierOf[msg.sender]` (write-once on first-claim only).

- [ ] **Step 7: Replace verifier integration** to use `Groth16VerifierV5_1Stub.verifyProof()` (after Task 1 above pump from circuits-eng).

- [ ] **Step 8: Add tests** for both branches:
  - First-claim: gas snapshot ≤ 2.5M, all 4 mappings + nullifierOf written correctly.
  - Repeat-claim same wallet: succeeds, no nullifierOf overwrite.
  - Repeat-claim wrong wallet: reverts on stale-bind.
  - Repeat-claim mismatched commitment: reverts on commitment-mismatch.
  - Repeat-claim same ctx: reverts on usedCtx.
  - Wallet uniqueness violation: same wallet, second identity → reverts.

- [ ] **Step 9: Run tests**

```bash
cd packages/contracts && forge test -vv
```

- [ ] **Step 10: Commit**

```bash
git add packages/contracts/src/QKBRegistryV5.sol packages/contracts/test/QKBRegistryV5_1.t.sol
git commit -m "contracts(v51): register() with first/repeat/wallet-uniqueness gates"
```

---

## Task 3: Add `rotateWallet()` entry point

**Files:**
- Modify: `packages/contracts/src/QKBRegistryV5.sol`
- Test: `packages/contracts/test/QKBRegistryV5_1.t.sol`
- Reference: spec §"rotateWallet() flow"

- [ ] **Step 1: Define function signature**:
```solidity
function rotateWallet(
  uint256[19] calldata publicSignals,
  uint256[2] calldata proofA,
  uint256[2][2] calldata proofB,
  uint256[2] calldata proofC,
  bytes calldata oldWalletAuthSig
) external;
```

- [ ] **Step 2: Verify groth16 proof** against `Groth16VerifierV5_1Stub` with `mode == 1`.

- [ ] **Step 3: Unpack rotation fields**:
  - `fingerprint = bytes32(publicSignals[14])`
  - `newCommitment = bytes32(publicSignals[15])`
  - `mode = publicSignals[16]` — `require(mode == 1, "wrong mode for rotate")`
  - `oldCommitment = bytes32(publicSignals[17])`
  - `newWallet = address(uint160(publicSignals[18]))`

- [ ] **Step 4: Validate rotation invariants**:
  - `require(identityCommitments[fingerprint] == oldCommitment, "old commitment mismatch")`
  - `require(newWallet == msg.sender, "tx must be from new wallet")`
  - `require(nullifierOf[newWallet] == 0, "new wallet already has identity")` — wallet uniqueness.

- [ ] **Step 5: Verify old-wallet authorization signature** via ECDSA recover:
  - Reconstruct hash: `keccak256(abi.encodePacked("qkb-rotate-auth-v1", fingerprint, newWallet))`
  - Recover signer from `oldWalletAuthSig` against the EIP-191 personal-message hash.
  - `require(recovered == identityWallets[fingerprint], "invalid old wallet auth")`.

- [ ] **Step 6: Update state atomically**:
  - `identityCommitments[fingerprint] = newCommitment`
  - `address oldWallet = identityWallets[fingerprint]; identityWallets[fingerprint] = newWallet;`
  - `nullifierOf[newWallet] = nullifierOf[oldWallet]; delete nullifierOf[oldWallet];`
  - DO NOT touch `usedCtx[fingerprint][*]` — invariant 3 (monotonic).

- [ ] **Step 7: Emit `WalletRotated`** event:
```solidity
event WalletRotated(bytes32 indexed fingerprint, address indexed oldWallet, address indexed newWallet, bytes32 newCommitment);
```

- [ ] **Step 8: Add tests**:
  - Happy path: A registers → A rotates to B with valid sig → identityWallets[fp]==B, commitment updated, nullifierOf migrated.
  - Wrong-mode rejection: rotateWallet with mode=0 reverts.
  - Bad oldWalletAuthSig: reverts.
  - Commitment mismatch: reverts.
  - newWallet already has identity: reverts on wallet uniqueness.
  - Re-register against pre-rotation usedCtx: reverts (invariant 3 holds).

- [ ] **Step 9: Gas snapshot** — assert ≤ 600K per spec.

- [ ] **Step 10: Commit**

```bash
git add packages/contracts/src/QKBRegistryV5.sol packages/contracts/test/QKBRegistryV5_1.t.sol
git commit -m "contracts(v51): rotateWallet() with old-wallet sig + commitment + wallet-uniqueness gates"
```

---

## Task 4: Update IQKBRegistry interface + ABI bump

**Files:**
- Modify: `packages/contracts/src/IQKBRegistry.sol`
- Modify: `packages/contracts-sdk/src/abis/QKBRegistryV5.json` (regenerate)
- Modify: `packages/contracts-sdk/src/types.ts` (regenerate from ABI)
- Modify: `packages/contracts-sdk/package.json` (bump 0.5.0 → 0.5.1-pre)

- [ ] **Step 1: Update IQKBRegistry**: register signature changes to 19-field publicSignals, add rotateWallet.

- [ ] **Step 2: Regenerate ABI** via `forge inspect QKBRegistryV5 abi > packages/contracts-sdk/src/abis/QKBRegistryV5.json`.

- [ ] **Step 3: Re-run TypeScript codegen** for `@qkb/contracts-sdk` types. (Use existing pipeline; if none, manually update.)

- [ ] **Step 4: Bump version** in package.json and CHANGELOG.

- [ ] **Step 5: Run sdk tests**:
```bash
pnpm -F @qkb/contracts-sdk test
pnpm -F @qkb/contracts-sdk build
```

- [ ] **Step 6: Commit**

```bash
git add packages/contracts/src/IQKBRegistry.sol \
        packages/contracts-sdk/src/abis/QKBRegistryV5.json \
        packages/contracts-sdk/src/types.ts \
        packages/contracts-sdk/package.json
git commit -m "contracts(v51): IQKBRegistry + sdk ABI bump for 19-field register + rotateWallet"
```

---

## Task 5: Refactor existing tests for new public-signal shape

**Files:**
- Modify: `packages/contracts/test/QKBRegistryV5.t.sol` (existing 28 register tests)

- [ ] **Step 1: Update test fixture builders** to populate the 19-field publicSignals shape (was 14).

- [ ] **Step 2: For each existing test**, verify it still asserts correctly. Some tests will need new assertions for the V5.1 mappings (identityCommitments, identityWallets, usedCtx).

- [ ] **Step 3: Drop `registrantOf` assertions** — mapping no longer exists.

- [ ] **Step 4: Run full forge suite**:
```bash
forge test -vv
```
Expected: 28 (refactored) + 6 (new V5.1) = 34/34 green.

- [ ] **Step 5: Final gas snapshot**:
```bash
forge snapshot --diff .gas-snapshot
```
Document new ceiling vs old in commit message.

- [ ] **Step 6: Commit**

```bash
git add packages/contracts/test/QKBRegistryV5.t.sol .gas-snapshot
git commit -m "contracts(v51): refactor 28 register tests for 19-field publicSignals + drop registrantOf"
```

---

## Verification (lead runs after each commit)

```bash
cd packages/contracts && forge test -vv
pnpm -F @qkb/contracts-sdk test
pnpm -F @qkb/contracts-sdk typecheck
```

Lead inspects diff for:
- No changes to `IdentityEscrowNFT.sol` (NFT decoupling per user directive)
- Gas snapshot delta documented
- ABI bump propagated cleanly to @qkb/contracts-sdk

## Artifact pump (lead, after Task 4 lands)

The contracts-sdk regen + ABI bump propagates to web-eng:

```bash
cp /data/Develop/qkb-wt-v5/arch-contracts/packages/contracts-sdk/src/abis/QKBRegistryV5.json \
   /data/Develop/qkb-wt-v5/arch-web/packages/contracts-sdk/src/abis/

cp /data/Develop/qkb-wt-v5/arch-contracts/packages/contracts-sdk/src/types.ts \
   /data/Develop/qkb-wt-v5/arch-web/packages/contracts-sdk/src/

git -C /data/Develop/qkb-wt-v5/arch-web add packages/contracts-sdk/
git -C /data/Develop/qkb-wt-v5/arch-web commit -m "chore(sdk): pump V5.1 ABI from contracts-eng"
```
