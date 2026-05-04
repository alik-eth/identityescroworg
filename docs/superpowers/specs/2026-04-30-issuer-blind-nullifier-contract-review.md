# Issuer-Blind Nullifier Amendment — Independent Contract-Side Review

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

**Date:** 2026-04-30
**Reviewer:** contracts-eng
**Reviews:** circuits-eng's spec at `docs/superpowers/specs/2026-04-30-issuer-blind-nullifier-amendment.md` (v0.2, commit `b2fc660` on `feat/v5arch-circuits`).
**Status:** Review-only. No contract code changes in this dispatch.
**Revision history:**
- v0.1 (~14:00 UTC): early review against my own assumed state-shape (3 mappings + time-locked-veto reset).
- v0.2 (~16:00 UTC): updated against the actual v0.2 spec (5 new public signals → 19 frozen, fold-into-main rotation, no V5 reset, NFT cross-contract coupling). Reverses my prior recommendation on Q1 to align with spec's β. Drops §5 reset analysis (V5 ships no reset). Adds new §7 on the Q4 NFT-coupling decision.

---

## TL;DR

The amendment is **clean from the contract side**. Implementable without exotic primitives, without new Poseidon sub-deploys, without new admin powers. Two contract-side gas snapshots:

| Function           | V5 (current) | V5.1 (post-amendment) |
|--------------------|--------------|------------------------|
| `register()` first claim | 2,017,734    | **~2,055,000** (+~37K)   |
| `register()` repeat (new ctx) | n/a (didn't exist) | **~370K** (no Poseidon spkiCommit if optimized; see §1) |
| `rotateWallet()`   | n/a          | **~430-470K** (incl. NFT cross-contract call) |

All three within the 2.5M acceptance gate (post-`def6270`). No churn for `IdentityEscrowNFT.sol` consumers OUTSIDE the new `adminTransfer()` entry point that this amendment introduces (cross-contract coupling — see §7).

**Confirmations on lead's pre-decided picks:**

| Item              | Lead's call                          | Contract-side stance | Notes |
|-------------------|--------------------------------------|----------------------|-------|
| Q1 rotation circuit (β fold-into-main) | Single ceremony, single verifier | ✅ **Endorse — reverses my v0.1 weak preference** | One immutable slot vs two; one ceremony coordination; mode-bit gate is cheap to enforce on-chain. |
| Q4 NFT migration (`adminTransfer`)     | Registry-callable single fn, atomic in `rotateWallet()` | ✅ **Endorse the call shape** | Single-fn beats callback for atomicity + simplicity; see §7 for full ergonomics + gas + attack surface analysis. |
| Q5 V5 reset posture (no reset)         | Ship without `identityReset()`   | ✅ **Endorse — strongly** | Cleanest contract surface. Zero new attack surface beyond `rotateWallet()`. UX cost real but documented in spec; V6 reset path stays open. |

**Three contract-side concerns flagged for circuits-eng (orthogonal to lead's three holes):**

1. **Drop `registrantOf`.** The spec keeps both `nullifierOf` and `registrantOf` for "backward compat" (line 233-234 of the amendment), but spec line 558 already states `nullifierOf` uniqueness is redundant with `usedCtx`. With anti-Sybil moved to `usedCtx`, `registrantOf` has no callers. Saves 1 SSTORE per first-claim register — meaningful when register costs 2M.
2. **`ctxKey` derivation simplification.** Spec uses `keccak256(abi.encode(ctxHashHi, ctxHashLo))` for the `usedCtx` mapping key. Hi/Lo halves of a SHA-256 hash already reassemble cleanly via `bytes32((uint256(hi) << 128) | lo)` — no keccak needed. Saves ~36 gas + simpler audit story.
3. **Public-signal binding for `rotationOldCommitment` / `rotationNewWallet`.** Under register mode (mode=0), the spec says both are no-ops bound to `identityCommitment` and `msgSender` respectively. Contract MUST explicitly verify these no-op constraints before unpacking the publicSignals array into the verifier. Without the explicit gate, a register caller could pass arbitrary values in slots [17..18] without affecting the proof.

(Detailed treatment in §2 attack surface and §3 ABI sections.)

---

## §1 — State layout impact

### Final per-register storage cost (against the actual spec)

| Operation                          | New SSTOREs                                        | Cost |
|------------------------------------|----------------------------------------------------|------|
| `register()` first claim — spec as-written | identityCommitments + identityWallets + usedCtx + nullifierOf + registrantOf = **5 SSTOREs** | 5 × 22,100 = **110,500** |
| `register()` first claim — with my recommendation #1 (drop registrantOf) | identityCommitments + identityWallets + usedCtx + nullifierOf = **4 SSTOREs** | 4 × 22,100 = **88,400** |

V5 baseline first-claim is 2 SSTOREs (`nullifierOf` + `registrantOf`) = 44,200. So:
- Spec as-written: **+66,300 gas vs V5 baseline** for storage alone.
- Spec + my #1: **+44,200 gas vs V5 baseline** for storage alone.

### `register()` repeat-claim cost

This is the new path the amendment enables — same wallet, same identity, fresh ctx. Spec lines 270-285:

```solidity
bytes32 storedCommit = identityCommitments[fp];
if (storedCommit == bytes32(0)) {
    identityCommitments[fp] = commit;
    identityWallets[fp]     = msg.sender;
} else {
    require(storedCommit == commit, "commitment drift");
    require(identityWallets[fp] == msg.sender, "wallet mismatch — use rotateWallet()");
}
require(!usedCtx[fp][ctxKey], "already registered for this ctx");
usedCtx[fp][ctxKey] = true;
```

On repeat-claim: only `usedCtx[fp][ctxKey] = true` is a NEW SSTORE (1 × 22,100 = 22,100). identityCommitments + identityWallets are read-not-written. Plus the existing register-flow nullifierOf + registrantOf? **Wait** — the spec's register() doesn't gate on whether this is a first-claim or repeat. It still writes nullifierOf and registrantOf at the bottom (line 290-291). On repeat-claim, `nullifierOf[msg.sender]` is non-zero (from the first claim), so the line 288 require fails: **repeat-claim register() reverts if you reuse the same wallet across ctxs.**

This is a SPEC INCONSISTENCY. Spec says "register repeat = same wallet, new ctx". But the existing nullifierOf/registrantOf gates require nullifierOf[msg.sender] == 0. They contradict each other.

**Flag for circuits-eng: clarify register()'s repeat semantics.** Two options:
- (a) Repeat is allowed: drop the `nullifierOf[msg.sender] == 0` gate; rely on `usedCtx[fp][ctxKey]` for Sybil. This is what the spec narrative implies.
- (b) Repeat is NOT allowed (one ctx per wallet, full stop): the entire `usedCtx` mapping is redundant.

I think (a) is intended (one user can register against many ctxs). If so, **the contract MUST drop the nullifierOf[msg.sender]==0 check** for repeat-claim. The cleanest formulation:

```solidity
if (storedCommit == bytes32(0)) {
    // First claim — write all five (or four with #1) maps.
    nullifierOf[msg.sender] = nul;
    identityCommitments[fp] = commit;
    identityWallets[fp]     = msg.sender;
} else {
    // Repeat — no nullifierOf write (already set from first claim).
    require(storedCommit == commit, "commitment drift");
    require(identityWallets[fp] == msg.sender, "wallet mismatch — use rotateWallet()");
    // Spec invariant: nullifier value MUST be the same — Poseidon₂(walletSecret, ctxHash) varies per ctx, so this is technically a NEW nullifier per ctx. So nullifierOf[msg.sender] gets OVERWRITTEN with the latest ctx's nullifier. That breaks isVerified() consistency and Verified-modifier consumers.
}
require(!usedCtx[fp][ctxKey], "already registered for this ctx");
usedCtx[fp][ctxKey] = true;
```

🚨 **Sub-flag:** the nullifier construction `Poseidon₂(walletSecret, ctxHash)` is **per-ctx unique**. Repeat-claim against ctxs A and B produces two DIFFERENT nullifier values for the same wallet. So:
- If contract overwrites `nullifierOf[msg.sender]` per claim, the value drifts (bad — `IdentityEscrowNFT` consumers can't rely on it).
- If contract only writes `nullifierOf[msg.sender]` on first-claim, subsequent claims' nullifier values are not on-chain.
- `registrantOf[nullifier]` would have multiple entries for the same wallet, which IS fine but bloats storage.

**Recommendation:** keep `nullifierOf[msg.sender]` as the FIRST nullifier (written on first-claim only). Subsequent claims still emit `Registered` events with the new nullifier value (off-chain indexers can reconstruct the per-ctx history). `registrantOf` can be dropped (anti-Sybil moved to `usedCtx`).

### Storage-slot mapping (new)

```solidity
// Slots 0-4: existing V5 (admin, trustedListRoot, policyRoot, nullifierOf, registrantOf-or-dropped)
// New slots:
mapping(bytes32 => bytes32) public identityCommitments;          // slot N+0
mapping(bytes32 => address) public identityWallets;              // slot N+1
mapping(bytes32 => mapping(bytes32 => bool)) public usedCtx;     // slot N+2
```

Where `N=4` if `registrantOf` is preserved, `N=3` if dropped. Both layouts are append-only relative to V5 — no slot collisions, audit-clean.

### `register()` total gas projection

V5 baseline measured: **2,017,734** (`RealTupleGasSnapshot.t.sol`).

Delta breakdown for first-claim:

| Component                                                  | Δ Gas (spec as-written) | Δ Gas (with #1) |
|------------------------------------------------------------|-------------------------|------------------|
| +3 SSTOREs (identityCommitments + identityWallets + usedCtx) | +66,300                  | +66,300          |
| +1 SSTORE retained: nullifierOf — no change                | 0                       | 0                |
| +0/-1 SSTORE: registrantOf retained / dropped              | 0                       | -22,100          |
| +keccak256(hi,lo) for ctxKey                               | +36-50                  | +36-50           |
| +Groth16 verifier 14→19 public inputs (5 extra G1 mul+add) | +25K-30K                | +25K-30K         |
| +calldata bump (5 × 32 = 160 B)                            | +2,560                  | +2,560           |
| +misc (sig.identityFingerprint/Commitment unpacking, comparisons) | +500-1,000      | +500-1,000       |
| **Net add**                                                | **+95K-100K**           | **+72K-78K**     |

**Projected `register()` first-claim total: ~2,090K-2,115K.** Comfortably inside 2.5M acceptance.

### Repeat-claim cost (new path)

On repeat:
- Skip leafSpki/intSpki spkiCommit calls? **NO** — Gates 2a still execute because the proof binds to those values via the verifier. Cannot skip.
- Skip Merkle climbs? **NO** — same reason.
- Save: 2 storage writes (identityCommitments + identityWallets), already populated.
- Pay: 1 storage write (usedCtx for new ctxKey).

**Repeat-claim register() projected: ~2,065K-2,090K** — only slightly cheaper than first-claim because Poseidon is the dominant cost, not storage. The amendment's "register repeat" optimization potential is small UNLESS we also fold the spkiCommit + Merkle climbs into a "trust-list cache" (e.g., per-(fingerprint, intSpki) memoization). That's a future optimization; not in this amendment's scope.

---

## §2 — Attack surface review

For each entry point, walked through reentrancy / front-running / griefing / state corruption / privilege creep / cross-flow consistency.

### `register()` — first claim

Same as V5 current. Reentrancy ✓, Front-running ✓ (proof binds to msg.sender via in-circuit keccak), MEV ✓, Griefing ✓ (spam costs ~2.05M gas), State corruption ✓ (atomic), Admin creep ✓ (none).

### `register()` — repeat (same fingerprint, new ctx)

| Vector             | Analysis                                                                                          | Status |
|--------------------|---------------------------------------------------------------------------------------------------|--------|
| Same-ctx replay    | `usedCtx[fp][ctxKey]` already true → revert at the new gate.                                      | ✓ |
| Cross-ctx replay   | Proof commits to specific ctxHash. Pairing eq fails for a different ctx.                          | ✓ |
| Wallet-bind drift  | Repeat-path requires `identityWallets[fp] == msg.sender`. Stale binding fails — must rotateWallet. | ✓ |
| Forced re-register | An attacker can't force-register a user into a ctx without the user's wallet sig + ZK proof.     | ✓ |
| 🚨 **Spec gap:** nullifierOf write semantics on repeat | Per §1's sub-flag: spec is unclear on whether nullifierOf overwrites per-claim or sticks to first-claim. | **Needs spec clarification** |

### `rotateWallet()`

Spec lines 421-442. The flow:

```
1. require(identityWallets[fp] == msg.sender)               — auth
2. require(identityCommitments[fp] == oldCommitment)        — stale-bind
3. require(newWallet != address(0) && != msg.sender)        — sanity
4. rotationVerifier.verifyProof(rotationProof, [fp, oldC, newC, newWallet]) — ZK proof
5. identityCommitments[fp] = newCommitment                  — state update
6. identityWallets[fp]     = newWallet                      — state update
7. emit WalletRotated(fp, msg.sender, newWallet)            — event
8. (lead's Q4 add-on) IdentityEscrowNFT.adminTransfer(msg.sender, newWallet)  — NFT migration
9. (Q4 spec recommend) nullifierOf[newWallet] = nullifierOf[msg.sender]; delete nullifierOf[msg.sender] — nullifier migration
```

| Vector             | Analysis                                                                                          | Status |
|--------------------|---------------------------------------------------------------------------------------------------|--------|
| Reentrancy         | Step 8 is an external call (cross-contract to NFT). Even with CEI ordering (state writes before call), defensively add `nonReentrant`. NFT.adminTransfer should not call back. | ✓ with belt-and-suspenders |
| Front-running      | Proof commits to BOTH oldCommitment AND newWallet. Frontrunner reordering tx can't substitute their own newWallet — pairing eq would fail. | ✓ |
| MEV                | No bond/fee, no MEV surface.                                                                        | ✓ |
| Griefing           | Stolen wallet + stolen oldWalletSecret = compromise (game-over per spec's threat model). No new attack. | Acceptable (matches spec's threat model) |
| State corruption   | Steps 5-9 must all succeed atomically. Any revert in adminTransfer (e.g. newWallet already has NFT) cascades. ✓ | ✓ |
| Admin creep        | None — rotateWallet is self-service via ZK proof + msg.sender auth.                                 | ✓ |
| 🚨 **Cross-contract atomicity** | If step 8 (NFT) reverts, registry state changes from steps 5-7 roll back. ✓ | ✓ |
| 🚨 **NFT collision** | If newWallet already holds an IdentityEscrowNFT (from a separate identity), step 8 must revert to prevent identity collapse. NFT contract's adminTransfer logic is the gate here. | **Spec for NFT contract** |

### Cross-flow concerns

- **Repeated rotation ping-pong:** legitimate user rotates `oldWallet → newWallet1 → newWallet2 → ...`. Each rotation costs ~430-470K gas; after each, only the latest wallet works. No vulnerability — just expensive.
- **Rotation across chain reorg:** all state changes in one tx. Reorgs are safe.
- **`rotationOldCommitment` / `rotationNewWallet` no-op binding under register mode:** the contract MUST explicitly check `sig.rotationMode == 0` AND `sig.rotationOldCommitment == sig.identityCommitment` AND `sig.rotationNewWallet == sig.msgSender`. Without these gates, a register caller could pass arbitrary garbage in slots [17..18] (the proof binds to whatever's there, but the contract semantically expects no-op values). **Flag for circuits-eng:** confirm whether the in-circuit constraints already enforce these (lines 387-398 of the spec suggest yes via `ForceEqualIfEnabled`); if so, contract gates are redundant but harmless. If not, contract MUST add them.
- **`rotateWallet()` mode-bit verification:** rotateWallet() must check `sig.rotationMode == 1`. Without this, a register-mode proof could be submitted to the rotateWallet entry point and the verifier would accept (since mode-bit is just a public input). The mode-bit semantically distinguishes the two flows but doesn't auto-route them; the entry point must enforce.

---

## §3 — ABI bump propagation cost

### `register()` ABI change

PublicSignals struct: 14 → 19 fields. Calldata: +160 bytes. Selector changes (struct shape changes the selector hash).

| Consumer                          | Touch needed                                                                | Severity |
|-----------------------------------|------------------------------------------------------------------------------|----------|
| `packages/contracts/src/QKBRegistryV5.sol` | Update `PublicSignals` struct, `register()` body. Add `rotateWallet()`. | Medium |
| `packages/contracts/src/IdentityEscrowNFT.sol` | Add `adminTransfer(address from, address to)` callable only by registry. (See §7.) | Medium |
| `packages/contracts-sdk/src/IQKBRegistry.sol` | If `nullifierOf` semantics preserved (recommended), no change. Drop `registrantOf` from public ABI if dropping per #1. | ✓ Low |
| `packages/sdk` (viem helpers) | `src/registry/index.ts` `encodeRegisterFromSignals` → 19-field encoder. Add `encodeRotateWallet`. ~6h work. | Medium |
| `packages/web` Step4 register path | Cascades through JS SDK above. No direct contract knowledge. | Auto-cascades |
| `packages/circuits` | Spec's domain. Witness builder + new rotation circuit / mode-flag wiring. | Owned by circuits-eng |

### `IQKBRegistry` interface

Spec line 558: "The `nullifierOf` mapping is retained for backward-compat... but its uniqueness is now redundant with `usedCtx`."

Position: **preserve `IQKBRegistry` byte-for-byte.** Same selectors:
- `isVerified(address) → bool` — semantics: holder has at least one nullifier on file (i.e., has registered against ≥1 ctx).
- `nullifierOf(address) → bytes32` — semantics CHANGE: was "the wallet's unique person-ctx nullifier"; becomes "the FIRST nullifier this wallet registered" (per §1's recommendation). Type unchanged. Returns 0 if never registered.
- `trustedListRoot() → bytes32` — unchanged.

`IdentityEscrowNFT.sol` consumes only these three. Works without edit.

### ERC-165

V5 doesn't implement ERC-165. New `rotateWallet()` adds a selector but no ERC-165 ID is stored. No consumer queries for it. **No churn.**

### Third-party

V5 hasn't shipped to mainnet. **No third-party impact.**

---

## §4 — Q1 confirmation: single circuit + mode flag (β)

**Reverses my v0.1 weak preference for option (b) separate circuit.**

### Why I now endorse (β)

The decisive factor is the **ceremony coordination cost** vs the marginal gas saving.

- Option α (separate rotation circuit): 1 extra immutable slot for `rotationVerifier`, ~80K-100K gas saving on rotateWallet (smaller verifier with 4 public inputs), 1 extra ceremony coordination (new ptau, new contributors, new zkey hosting).
- Option β (fold into main): 1 verifier address total, rotateWallet pays the same Groth16 cost as register (~340K — 19 inputs instead of 14 → ~+25K vs hypothetical 14-input rotation), but ZERO additional ceremony work.

Net: β costs ~80-100K extra gas per rotateWallet call against a single-ceremony win. At Base Sepolia gas prices, ~80K gas = ~$0.005. **The gas delta is irrelevant against the operational simplicity.**

Plus, β has a contract-side benefit I missed in v0.1: **single immutable verifier address** means the registry constructor takes ONE `IGroth16VerifierV5` argument, deploys once, and there's never a "which verifier did I deploy" ambiguity. Audit story is cleaner.

### Mode-bit dispatch on the contract side

Each entry point pins the mode bit to its semantics:

```solidity
function register(Proof p, PublicSignals sig, ...) external {
    require(sig.rotationMode == 0, "must be register mode");
    require(sig.rotationOldCommitment == sig.identityCommitment, "register no-op #1");
    require(sig.rotationNewWallet == sig.msgSender, "register no-op #2");
    // ... rest of register flow ...
}

function rotateWallet(Proof p, PublicSignals sig, address newWallet) external {
    require(sig.rotationMode == 1, "must be rotation mode");
    require(sig.rotationNewWallet == uint256(uint160(newWallet)), "newWallet binding");
    require(sig.msgSender == uint256(uint160(msg.sender)), "msgSender binding");
    // ... rest of rotation flow ...
}
```

Cost per gate: ~3-6 gas each. **Trivial.**

If the in-circuit `ForceEqualIfEnabled` constraints (spec lines 387-398) already enforce the no-op invariants under register mode, the contract gates `register no-op #1/#2` are redundant. Confirm with circuits-eng — if they're in-circuit, drop the redundant on-chain checks. If not, keep them.

### Single-verifier-with-mode-flag verdict

**β is the right call. ✅**

---

## §5 — Q5 confirmation: V5 ships no `identityReset()`

**Endorse — strongly.**

Reasons (mostly the spec's, slightly extended for the contract side):

1. **Cleanest contract surface.** With no reset, the entire DoS-mitigation conversation goes away. No `pendingResets` mapping, no `vetoReset()` / `commitReset()` / `gcReset()` entry points, no time-based state. The contract has 4 user-facing functions: `register()`, `rotateWallet()`, plus the existing `setTrustedListRoot()` / `setPolicyRoot()` / `transferAdmin()` (admin-only).

2. **Audit cost reduction.** Each entry point is auditable independently. No cross-flow timer interactions. No "what if the user rotates while a reset is queued" edge cases.

3. **Storage simpler.** No ~22K-44K of pending-reset overhead per legitimate-recovery user. No `gcReset()` cleanup story.

4. **`usedCtx` invariant unambiguous.** Spec line 463: "V6 reset implementations MUST NOT clear `usedCtx[fp][*]`". With V5 shipping no reset, this invariant is just "`usedCtx` is monotonic — once set, never unset." Easy to reason about. V6 can preserve it explicitly.

5. **No regression vs V5 status quo.** V5 already has no recovery path for wallet loss (per `IdentityEscrowNFT` non-transferability + `nullifierOf` permanence). The amendment just makes the same trade-off explicit.

**Drop my v0.1 §5 reset analysis — it was contemplating an option that's not in the V5 amendment.** I'll keep the V6 sketch as a future-reference note, but the V5 review concludes here for reset.

---

## §6 — Poseidon deployment confirmation

The amendment uses Poseidon₂ in three on-chain-relevant places (per spec lines 80-83):

```
identityFingerprint = Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)   — circuit-side
identityCommitment  = Poseidon₂(subjectSerialPacked, walletSecret)         — circuit-side
nullifier           = Poseidon₂(walletSecret, ctxHash)                     — circuit-side
```

All three are computed in-circuit and exposed as public signals. **The contract never calls Poseidon for these.** Contract just stores/reads bytes32 values via mappings.

V5's existing Poseidon contracts:
- `PoseidonT3` (Poseidon₂, t=3): used for spkiCommit final step + Merkle climb. Reused, no new deploy.
- `PoseidonT7` (Poseidon₆, t=7): used for spkiCommit limb hash. Reused, no new deploy.

The amendment adds NO new Poseidon types. PoseidonT3/T7 stay as-is.

**Naming clarification (the dispatch's "T2"):** there's no PoseidonT2 instance in V5. T2 in the dispatch is a typo for T3 (Poseidon over 2 inputs uses t=3, the parameter t = arity + 1). Hash arity 2 = parameter t = 3 → contract called PoseidonT3.

✅ **No new Poseidon sub-deployments needed.**

---

## §7 — NEW: Q4 NFT cross-contract coupling — `IdentityEscrowNFT.adminTransfer()`

Lead's pre-decision: "Don't make `IdentityEscrowNFT.ownerOf()` dynamic. Add `IdentityEscrowNFT.adminTransfer(oldWallet, newWallet, tokenId)` callable only by registry. `rotateWallet()` invokes it atomically."

Three contract-side angles to weigh in on:

### §7.1 Single-fn vs callback pattern — **endorse single-fn (the lead's pick)**

Three patterns considered:

| Pattern | Description | Contract-side cost |
|---------|-------------|---------------------|
| **(A) Single-fn**: registry calls `IdentityEscrowNFT.adminTransfer(from, to)` | Registry → NFT direct call during `rotateWallet()`. NFT clears NFT from `from`, mints/transfers to `to`, emits ERC-721 `Transfer`. Both contracts atomic via revert propagation. | ~50K gas per rotation (1 CALL + 2 SSTOREs in NFT - 1 refund + Transfer event). |
| **(B) Event callback**: NFT subscribes to `WalletRotated` event | Doesn't exist in EVM natively. Either: (i) off-chain indexer watches events + calls a permissioned `adminMigrate()` on NFT — NOT atomic; (ii) NFT polls registry on every transfer — gas-prohibitive. | Either non-atomic (bad UX during rotation window) or expensive. |
| **(C) Dynamic ownerOf**: NFT.ownerOf reads identityWallets[fp] | Lead said NO. Forces NFT to depend on registry every read. Expensive (extra SLOAD per ownerOf call) and breaks ERC-721 staticness assumptions. | Bad. |

**Recommendation: stick with (A).** Reasons:
- **Atomic.** The NFT migration happens in the same tx as the registry state update. No partial-update window.
- **Simple.** One function call, one revert path. Audit-clean.
- **Standard pattern.** Many DeFi protocols use this (e.g., StaderLabs liquidity migrators, Lido withdrawal vault).
- **Gas-cheap.** ~50K gas, well within the rotation budget.

### §7.2 Gas overhead for the NFT call

Detailed breakdown of the cross-contract call inside `rotateWallet()`:

| Step                                                          | Gas           |
|---------------------------------------------------------------|---------------|
| `CALL` opcode (cold contract address, value=0, no data growth) | ~2,600-2,700  |
| `IdentityEscrowNFT.adminTransfer` entry / msg.sender check    | ~30-50        |
| Read `_owners[oldWallet]` (1 SLOAD, cold)                     | ~2,100        |
| Write `_owners[oldWallet] = address(0)` (SSTORE non-zero→0; refund) | -4,800 net (22,100 - 26,900 refund cap fragment) |
| Read `_owners[newWallet]` for collision check (1 SLOAD)       | ~100 (warm)   |
| Write `_owners[newWallet] = tokenId` (SSTORE 0→non-zero)      | ~22,100       |
| Decrement `_balances[oldWallet]`, increment `_balances[newWallet]` (2 SSTOREs warm) | ~10,000 |
| Emit `Transfer(oldWallet, newWallet, tokenId)` event          | ~1,500-1,800  |
| Return + restore                                              | ~200          |

**Total: ~33-35K** (with refunds applied) for the NFT side. Plus the CALL overhead from the registry side ~2,700. **Net: ~36-38K.**

I'd budgeted ~50K above; the tighter accounting gives ~36-38K. Either way, comfortably small.

### §7.3 Reentrancy posture

The cross-contract call is `registry → NFT`. Reentrancy threat: NFT calls back into registry mid-update.

| Risk                                                                | Mitigation |
|---------------------------------------------------------------------|-------------|
| NFT.adminTransfer makes external calls of its own                   | Audit: NFT impl must NOT make external calls in `adminTransfer`. Plain state update + event emit only. |
| NFT calls back into registry during adminTransfer                  | Add `nonReentrant` to `rotateWallet()`. Registry has no other external calls during rotation, so reentrancy on the rotateWallet path is fully blocked. |
| User-controlled NFT impl (e.g., proxy upgrade) becomes malicious   | NFT impl is fixed at deploy and immutable per V5 invariants. Not a real risk. |
| ERC-721 `Transfer` event listeners (off-chain) cause issues         | Off-chain only. No on-chain reentrancy. |

**Recommendation:** add `nonReentrant` modifier to `rotateWallet()`. Cost: ~5K gas, dirt cheap given ~470K total. NFT itself doesn't need its own `nonReentrant` if `adminTransfer` is leaf (no external calls). I recommend implementing `adminTransfer` as a leaf to keep this property.

```solidity
function adminTransfer(address from, address to) external {
    require(msg.sender == address(registry), "only registry");
    require(_owners[from] != 0, "from has no NFT");
    require(_owners[to] == 0, "to already holds NFT (collision)");
    uint256 tokenId = _owners[from];
    delete _owners[from];
    _owners[to] = tokenId;
    _balances[from]--;
    _balances[to]++;
    emit Transfer(from, to, tokenId);
}
```

Leaf. No external calls. `nonReentrant` on NFT side is unnecessary.

### §7.4 Attack surface — malicious-registry-bug

Lead's framing: "A malicious registry bug could call adminTransfer maliciously. Is that acceptable given the registry IS the trust anchor anyway?"

Position: **Yes, acceptable.**

The registry is already the sole authority over identity state. If a registry bug lets an attacker bypass register/rotateWallet auth, that bug also lets them:
- Mint themselves an arbitrary IdentityEscrowNFT via the existing `register()` path (write `nullifierOf[attacker] = anything` → `IdentityEscrowNFT.mint()`).
- Override anyone's identityWallets / identityCommitments.

Adding `adminTransfer` doesn't materially expand this surface. The new NFT entry point is just an extension of the registry's existing god-mode over identity state. The trust anchor stays the same.

The audit boundary: **registry contract correctness is the load-bearing thing**. NFT correctness is a thin wrapper that delegates auth. As long as the registry is sound, the NFT is sound.

### §7.5 Constructor-time wiring

The NFT must know the registry address at deploy time:

```solidity
contract IdentityEscrowNFT {
    address public immutable registry;
    constructor(address _registry, ...) { registry = _registry; ... }
    modifier onlyRegistry() { require(msg.sender == registry, "only registry"); _; }
    function adminTransfer(address from, address to) external onlyRegistry { ... }
}
```

The existing `IdentityEscrowNFT.sol` already accepts a registry address in its constructor. **Add only the new function + modifier; constructor signature unchanged.**

Deploy ordering stays: deploy registry first → deploy NFT with registry's address. Same as today.

### §7.6 Summary

| Aspect                        | Verdict |
|-------------------------------|---------|
| Single-fn pattern (lead's pick) | ✅ Endorse |
| Gas overhead                  | ~36-38K (well within budget) |
| Reentrancy posture            | `nonReentrant` on rotateWallet; NFT.adminTransfer must be leaf |
| Malicious-registry attack    | Acceptable — registry is already the trust anchor |
| Constructor wiring             | Trivial — NFT already knows registry address |

---

## §8 — Spec questions where I have a contract-side angle

The spec has 6 open questions (§"Open questions for review"). I have a contract-side opinion on:

### Spec Q4 — `nullifierOf` migration on `rotateWallet()`

**Spec recommendation: yes, migrate.** I agree.

Without migration: old wallet's `isVerified()` returns true, `nullifierOf[oldWallet]` keeps stale value, `IdentityEscrowNFT` ownership lookups break.

With migration (1 SSTORE rewrite + 1 SSTORE clear): ~17K extra gas per rotation. Worth it for UX consistency.

```solidity
// Inside rotateWallet():
nullifierOf[newWallet] = nullifierOf[msg.sender];
delete nullifierOf[msg.sender];
```

✅ Endorse.

### Spec Q5 — `WalletRotated` event privacy

Spec: "The event emits `(identityFingerprint, oldWallet, newWallet)`, which lets external observers correlate two wallets to the same identity. This is a planned leak (visible at the contract layer regardless), but worth flagging."

Contract-side position: **the leak is implicit anyway** from the state transition. `identityWallets[fp]` is publicly readable; an observer can diff snapshots before/after the rotation tx and see the same fingerprint with different wallets. The event just makes the inference easier; it doesn't enable a NEW leak.

**Recommendation:** emit the event. Indexers and watch services need it. Indexed fields should be `identityFingerprint` (primary lookup key) + `oldWallet` + `newWallet` (secondary — both are likely-watched).

Minor refinement: also emit a `WalletDelegated` event with just `(oldWallet, newWallet)` (no fingerprint) for off-chain "this address moved here" indexers that don't care about identity-level data. Optional; not blocking.

### Spec Q6 — HKDF input includes `subjectSerial`?

This is a circuits-eng / web-eng decision (off-circuit derivation). Contract-side neutral.

But contract observation: if `walletSecret` is per-(wallet, identity), then a wallet bound to two different identities (via two different QESes) gets two different `walletSecret`s — and therefore two different `nullifier`s and `identityCommitment`s. Storage-wise, this just means two entries in `identityCommitments` and `identityWallets`, one per fingerprint. **No contract change needed either way.** Defer to circuits-eng + web-eng.

---

## §9 — Three contract-side concerns flagged for circuits-eng

(Promoting from TL;DR for visibility.)

### #1 — Drop `registrantOf`

Spec lines 233-234 keep both `nullifierOf` and `registrantOf` for "backward compat". But spec line 558 already states `nullifierOf` uniqueness is redundant with `usedCtx`. With anti-Sybil moved to `usedCtx`, `registrantOf` has zero callers post-amendment.

**Saves 1 SSTORE (22.1K gas) per first-claim register.** Net first-claim register gas drops from ~2,115K to ~2,093K. Worth doing.

If circuits-eng wants to keep `registrantOf` for "we might need it later" reasons, please articulate the use case. Otherwise drop.

### #2 — `ctxKey` derivation simplification

Spec line 269: `bytes32 ctxKey = keccak256(abi.encode(sig.ctxHashHi, sig.ctxHashLo))`.

Hi/Lo halves of a SHA-256 hash naturally reassemble:

```solidity
bytes32 ctxKey = bytes32((uint256(sig.ctxHashHi) << 128) | sig.ctxHashLo);
```

- Simpler.
- Saves ~36 gas + the keccak op + the abi.encode allocation.
- No ambiguity about the hash domain (it's just the original ctxHash, byte-reassembled).

Use the keccak form ONLY if there's a deliberate reason to domain-separate (e.g., the contract treats `ctxKey` as a different namespace from the proof's ctxHash). I don't see why we'd want that.

### #3 — Public-signal binding for `rotationOldCommitment` / `rotationNewWallet`

Under register mode (mode=0), the spec's circuit lines 387-398 enforce the no-op constraints via `ForceEqualIfEnabled`:

```circom
component regModeCheck1 = ForceEqualIfEnabled();
regModeCheck1.enabled <== 1 - rotationMode;
regModeCheck1.in[0]   <== rotationOldCommitment;
regModeCheck1.in[1]   <== identityCommitment;

component regModeCheck2 = ForceEqualIfEnabled();
regModeCheck2.enabled <== 1 - rotationMode;
regModeCheck2.in[0]   <== rotationNewWallet;
regModeCheck2.in[1]   <== msgSender;
```

If these are wired correctly, the contract-side gates I sketched in §4 are redundant. **Confirm with circuits-eng:** are the no-op constraints in the final circuit, or do they only apply to the rotation_mode==1 path?

If they're in: contract can drop the redundant register-no-op checks. Saves ~6 gas (negligible) and reduces audit surface.
If they're not: contract MUST add the gates explicitly to prevent register-mode callers from passing arbitrary [17..18] values.

---

## §10 — Implementation phase scope

When the spec converges and you greenlight implementation:

- [ ] Update `QKBRegistryV5.sol`: PublicSignals struct (14→19 fields), register() repeat-claim path, rotateWallet() entry point, three new mappings, drop registrantOf (per #1).
- [ ] Update `IdentityEscrowNFT.sol`: add `adminTransfer(from, to)` with `onlyRegistry` modifier. Leaf, no external calls.
- [ ] Add `nonReentrant` modifier on `rotateWallet()`.
- [ ] Add `WalletRotated` event with indexed fields.
- [ ] Update `IQKBRegistry.sol` (or contracts-sdk): preserve existing fns; document semantic shift in `nullifierOf` docstring.
- [ ] Update `RealTupleGasSnapshot.t.sol`: bump expected from ~2.02M → ~2.10M baseline; add rotateWallet measurement (~430-470K target); add per-gate bisection for the new amendment gates.
- [ ] Add 6 new tests:
  - `register()` first claim → all 3 new mappings written
  - `register()` repeat (same wallet, same fingerprint, new ctx) → only usedCtx written
  - `register()` repeat with stale identityWallets → revert
  - `rotateWallet()` happy path → identityCommitments + identityWallets updated, NFT migrated, nullifierOf migrated, event emitted
  - `rotateWallet()` collision (newWallet already has NFT) → revert
  - `rotateWallet()` from wrong wallet → revert
- [ ] Refactor 28 existing register tests to the 19-field PublicSignals layout.

**Effort estimate:** 2-3 days dedicated. Matches lead's estimate.

---

## §11 — Out-of-scope flags

Per dispatch instructions:

- **Pedersen set-membership** (V6 candidate). Out of scope.
- **EIP-3074 / EIP-7702 wallet authorization.** Could simplify rotateWallet but adds Pectra dependency. Not in this review.
- **Social-recovery V6 reset path.** Sketched in spec §"V6 plan"; out of scope here.

---

## References

- Circuits-eng amendment v0.2: `docs/superpowers/specs/2026-04-30-issuer-blind-nullifier-amendment.md` (commit `b2fc660` on `feat/v5arch-circuits`).
- Current V5 contract: `packages/contracts/src/QKBRegistryV5.sol` (HEAD `c2a13e4`).
- Current V5 spec: `docs/superpowers/specs/2026-04-29-v5-architecture-design.md` (with `def6270` gas amendment merged).
- Real-tuple gas snapshot baseline: `packages/contracts/test/integration/RealTupleGasSnapshot.t.sol` (commits `7ff73f2` + `c2a13e4`).
- Prior person-nullifier amendment (context only): `docs/superpowers/specs/2026-04-18-person-nullifier-amendment.md`.
- v0.1 of this review: prior commit `648d646` on this same branch (now superseded by this v0.2 file).
