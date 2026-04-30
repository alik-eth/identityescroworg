# Issuer-Blind Nullifier Amendment — Independent Contract-Side Review

**Date:** 2026-04-30
**Reviewer:** contracts-eng
**Scope:** Independent contract-side analysis of the proposed V5 privacy amendment, parallel to circuits-eng's spec draft at `docs/superpowers/specs/2026-04-30-issuer-blind-nullifier-amendment.md`.
**Status:** Review-only. No contract code changes in this dispatch.

---

## TL;DR

Implementable on the contract side without exotic primitives. **Net gas impact on `register()` is +25-30K (≈1.5%)**, well inside the spec §3 acceptance gate (≤2.5M). Everything the contract needs is already in-tree: PoseidonT3 (= Poseidon₂) covers the new field-domain hashes, no new sub-deploys, no new precompile dependencies, no new admin powers, no new storage slot collisions with V5.

**Three contract-specific recommendations, in priority order:**

1. **Anti-griefing for `identityReset()`: time-locked veto (Option A in §5).** Cleanest contract-side mechanics, lowest gas overhead per reset (~22K), self-service, no admin involvement. Recommend `VETO_PERIOD = 7 days`.
2. **`rotateWallet()` proof system: separate small circuit (Option (b) in §4).** Two verifier addresses costs one extra immutable; benefits include cheaper rotation gas, cleaner audit boundary, independent upgrade path. Defer to circuits-eng on circuit feasibility.
3. **Preserve `nullifierOf` and `isVerified` as the public read surface for IdentityEscrowNFT.** Same byte32 semantics, just redefined: "the wallet's identity commitment, unique under (fingerprint, ctxHash) Sybil bookkeeping." `IQKBRegistry` interface unchanged. Existing IdentityEscrowNFT.sol works with zero edits.

**One concern flagged for circuits-eng's draft (orthogonal to lead's three holes):** the `usedCtx[fingerprint][ctxHash]` mapping persists fingerprint as a contract-readable bytes32. While issuer-blind (issuer can't compute it without the wallet's secret), it IS observable on chain and could be linked across multiple registrations from the same person (every (fingerprint, ctxHash) pair shares a fingerprint). Not a regression vs. V5's current `nullifier` (which has the same linkability across re-registrations) but worth explicit treatment in the privacy guarantees section of the amendment.

---

## §1 — State layout impact

### Current V5 storage (post-§6.7)

```solidity
// QKBRegistryV5.sol
address public admin;                            // slot 0   (160 bits)
bytes32 public override trustedListRoot;         // slot 1
bytes32 public policyRoot;                       // slot 2
mapping(address => bytes32) public nullifierOf;  // slot 3   (mapping base)
mapping(bytes32 => address) public registrantOf; // slot 4   (mapping base)
// poseidonT3, poseidonT7, groth16Verifier, MAX_BINDING_AGE — immutable / constant, no slots.
```

Per-register cold-write cost: 2 × `SSTORE` zero→non-zero = 2 × 22,100 = **44,200 gas**.

### Proposed amendment storage

The amendment adds 3 mappings as a strict superset of current state. **Strict superset** matters: V5 storage layout is preserved by construction (the existing slots 0-4 stay where they are, new slots are appended), so a hypothetical proxy upgrade would be safe — though V5 is non-upgradeable, this property still helps audit reviewers reason about a fresh deploy with shared state semantics.

```solidity
// New mappings (slots 5-8, by declaration order):
mapping(bytes32 => bool)             public identityCommitments;          // slot 5
mapping(address => bytes32)          public identityWallets;              // slot 6
mapping(bytes32 => mapping(bytes32 => bool)) public usedCtx;              // slot 7
//      ↑ fingerprint                ↑ ctxHash             ↑ used?
mapping(bytes32 => PendingReset)     public pendingResets;                // slot 8 (if time-lock veto chosen)

struct PendingReset {                                                     // packs into 1 slot
    bytes32 newCommitment;          // 256 bits
    address newWallet;              // 160 bits → goes into slot+1
    uint64  vetoableUntil;          // 64 bits  → packed with newWallet
}
```

Storage cost analysis:

| Operation                          | New SSTOREs                                    | Cost (cold) |
|------------------------------------|------------------------------------------------|-------------|
| `register()` first claim           | identityCommitments + identityWallets + usedCtx | 3 × 22,100 = **66,300** |
| `register()` repeat (new ctx)      | usedCtx (fresh slot) only                       | 1 × 22,100 = **22,100** |
| `rotateWallet()`                   | identityWallets[old]=0 + identityWallets[new] + identityCommitments[old]=0 + identityCommitments[new] | 4 × ~5,000 (mix cold/warm) ≈ **~20-30K** with refunds |
| `identityReset()` (queue)          | pendingResets struct (1-2 slots packed)         | 1-2 × 22,100 = **22-44K** |
| `commitReset()` (after veto period) | applies pending → identityWallets/Commitments swap + clear pendingResets | ~30K with refunds |
| `vetoReset()`                      | clear pendingResets                             | ~5K (refund) |

### Replacing `nullifierOf` and `registrantOf`?

Two options for the legacy mappings:

**(α) Keep both for backward compat.** `nullifierOf[wallet] = identityCommitments[wallet]_committed_value` (alias). `registrantOf[commitment] = wallet`. Costs: same SSTORE count as current V5 (2 mappings) PLUS the 3 new ones = **5 SSTOREs per first-claim register()**. ~110K storage gas — significant. Not worth it.

**(β) Drop `registrantOf`, redefine `nullifierOf` semantically.** `nullifierOf[wallet]` returns `identityWallets[wallet]` (the commitment). `registrantOf` is functionally replaced by `identityCommitments` (just a `bool`/lookup). Save one SSTORE per register. Net: 3 SSTOREs new, 0 SSTOREs removed (since identityWallets[wallet] is what nullifierOf reads), so **net gas change vs. V5 = +1 SSTORE = +22K** to register() first-claim.

**Recommendation: (β).** Preserves IQKBRegistry interface for IdentityEscrowNFT, drops the redundant `registrantOf` map.

### `register()` gas projection

Current V5 measured: **2,017,734 gas** (per `RealTupleGasSnapshot.t.sol::test_real_tuple_full_register_gas`).

Delta breakdown:

| Component                                              | Δ Gas      |
|--------------------------------------------------------|------------|
| +1 SSTORE (3 new mappings - 1 dropped registrantOf)    | +22,100    |
| +1 cold SLOAD for `usedCtx[fingerprint][ctxHash]` check (cold→cold) | +2,100 |
| +1 cold SLOAD for `identityCommitments[commitment]` freshness check | +2,100 |
| +calldata bump from new public-signal layout (+1 to +2 fields × 32 bytes = ~64 B) | ~+1,000 |
| +Groth16 verifier 14→15 (or 16) public inputs (per extra G1 mul+add) | +5K to +10K |
| **Net add**                                            | **~32-37K** |

**New `register()` ceiling: ~2,055,000.** Well inside 2.5M acceptance.

### Storage refund accounting

Three operations have refund opportunity:

- `rotateWallet()` clears old `identityWallets[oldWallet]` and `identityCommitments[oldCommitment]` → 2× SSTORE_RESET refund (~4,800 gas each post-EIP-3529) = ~9,600 gas refunded.
- `vetoReset()` clears `pendingResets[fingerprint]` → ~4,800 gas refunded.
- `commitReset()` clears `pendingResets[fingerprint]` after applying → ~4,800 gas refunded.

Refund cap is 1/5 of tx gas under EIP-3529. None of these flows hit the cap (they all use ≪ 5× their refund budget).

---

## §2 — Attack surface review

For each entry point, I walked through reentrancy / front-running / griefing / state-corruption / privilege-creep. Findings are flagged where they need amendment-side mitigation.

### `register()` — first claim

| Vector             | Analysis                                                                                           | Status |
|--------------------|----------------------------------------------------------------------------------------------------|--------|
| Reentrancy         | No external calls after state writes (matches V5 current). Event emission is the last action.     | ✓ OK |
| Front-running      | Proof binds to msg.sender via in-circuit keccak gate (per §6.8). A frontrunner with the proof can't reuse it under a different wallet. Same as V5. | ✓ OK |
| MEV / sandwich     | No price-sensitive slot (no AMM hop, no auction). Sandwich is uneconomic.                          | ✓ OK |
| Griefing           | Spam register() with junk proofs → each costs ~2.05M gas at full revert depth → economically unattractive. Dust attack on `usedCtx[fingerprint][ctxHash]` reverts at gate 5 (Sybil check). | ✓ OK |
| State corruption   | All 3 SSTOREs happen atomically inside the same tx. Solidity's revert semantics roll them back together. | ✓ OK |
| Admin creep        | No new admin privileges. setTrustedListRoot / setPolicyRoot still the only mutators.               | ✓ OK |

### `register()` — repeat (same fingerprint, new ctx)

This is the new path the amendment enables — a user re-registers their identity for a fresh ctx (new app/policy/etc.) without burning a fresh QES ceremony.

| Vector             | Analysis                                                                                          | Status |
|--------------------|---------------------------------------------------------------------------------------------------|--------|
| Same-ctx replay    | `usedCtx[fingerprint][ctxHash]` already true → revert at gate 5 (per amendment).                  | ✓ OK |
| Cross-ctx replay   | A stolen proof for ctx=A can't be used for ctx=B because the proof commits to ctxHash. Pairing eq fails. | ✓ OK |
| Wallet-bind drift  | Proof must commit to `walletCommitment` matching `identityWallets[msg.sender]`. Replay from a different wallet fails the keccak gate. | ✓ OK |
| Forced re-register | An attacker can't force a user to "burn" their (fingerprint, ctx) slot — `register()` is auth'd by msg.sender, who must hold the wallet. | ✓ OK |
| 🚨 **Edge case**   | What if `identityWallets[msg.sender]` is set but `identityCommitments[commitment]` was cleared by a `rotateWallet()` sequence? The repeat-register path needs to look up commitment from `identityWallets[msg.sender]` directly, not re-derive it from the proof. | **Flag for circuits-eng** |

**Suggested invariant for the amendment:** `register()` MUST verify `identityWallets[msg.sender] == proof.walletCommitment` before checking `usedCtx`. Without this, a wallet with a stale identityWallets entry could submit a proof for someone else's commitment.

### `rotateWallet()`

The lead's hole #1 (ZK proof of old walletSecret, not just sig auth) is correct and load-bearing. My analysis assumes it's adopted.

| Vector             | Analysis                                                                                          | Status |
|--------------------|---------------------------------------------------------------------------------------------------|--------|
| Reentrancy         | Single tx, no external calls. Can be `nonReentrant` for belt-and-suspenders.                      | ✓ OK |
| Front-running      | Proof commits to BOTH oldWalletSecret AND newWallet via the new circuit's public signals. A frontrunner reordering tx can't substitute their own newWallet. | ✓ OK with hole #1 fix |
| MEV                | No fee/bond mechanism, no MEV opportunity.                                                         | ✓ OK |
| Griefing           | Stolen QES + stolen old wallet (worst case) lets attacker rotate. But this is the SAME compromise V5 register() already accepts — wallet keys are the trust root.                | Acceptable |
| State corruption   | 4 SSTOREs (2 clears + 2 sets). Atomic via revert. Order: write new before clear old, so a chain reorg never leaves "no commitment for fingerprint". | ✓ OK if amendment specifies write-first |
| Admin creep        | None.                                                                                              | ✓ OK |
| 🚨 **Hole #1 verification** | Without ZK proof of old walletSecret, ONLY old-wallet signature auth would let a stolen wallet rotate even after the user revokes the old wallet via off-chain means. The ZK proof closes this. | **Confirms lead's recommendation** |

**Recommended invariant:** the rotateWallet circuit MUST prove knowledge of oldWalletSecret AND that newCommitment = Poseidon(newWalletSecret, fingerprint) AND that fingerprint matches the rotation_circuit's public signal AND that the existing `identityCommitments[oldCommitment]` is in the tree (existence proof, OR contract reads identityWallets[msg.sender] directly). This guarantees wallet rotation is end-to-end binding-side authenticated.

### `identityReset()` — queue

Detailed mechanics depend on the chosen anti-griefing mechanism (§5). Below assumes time-locked veto (my recommendation).

| Vector             | Analysis                                                                                          | Status |
|--------------------|---------------------------------------------------------------------------------------------------|--------|
| Reentrancy         | Single tx, no external calls.                                                                       | ✓ OK |
| Front-running      | An attacker race-submitting a competing reset would win if their tx is mined first. Once `pendingResets[fingerprint]` is set, additional resets revert until veto period elapses or veto fires. | Acceptable |
| MEV                | No bond/fee → no MEV.                                                                              | ✓ OK |
| 🚨 **Griefing — hole #3** | Stolen QES + new wallet → attacker submits identityReset → user submits identityReset back → repeat. **Without anti-griefing, this is a DoS.** Lead's hole #3 is correct. | **Mitigated by veto period** |
| State corruption   | One SSTORE for pendingResets struct. Atomic.                                                       | ✓ OK |
| Admin creep        | None — reset is self-service via QES proof, NOT admin-mediated.                                    | ✓ OK |

### `vetoReset()` (time-lock variant)

| Vector             | Analysis                                                                                          | Status |
|--------------------|---------------------------------------------------------------------------------------------------|--------|
| Reentrancy         | Single tx, no external calls.                                                                       | ✓ OK |
| Auth model         | Must be auth'd by current `identityWallets[someAddress]` matching the existing `identityCommitments[commitment]`. The veto signature can be either (a) a wallet signature from msg.sender that owns the commitment, OR (b) a fresh ZK proof of walletSecret knowledge (so a user who lost the wallet can still veto using their walletSecret). | Choice for amendment |
| Front-running      | Attacker can't veto — they don't have the existing wallet's auth. ✓                                | ✓ OK |
| Griefing           | Spam veto on every queued reset → cost is per-tx + 0 economic benefit → unattractive.              | ✓ OK |
| Admin creep        | None.                                                                                              | ✓ OK |

### `commitReset()` (time-lock variant)

| Vector             | Analysis                                                                                          | Status |
|--------------------|---------------------------------------------------------------------------------------------------|--------|
| Caller             | Public — anyone can finalize after veto window. ✓ standard pattern (relayers).                    | ✓ OK |
| Replay             | Once committed, `pendingResets[fingerprint]` cleared → second commitReset reverts.               | ✓ OK |
| Stale state        | If holder uses old wallet to register fresh ctx during the veto period AFTER attacker queued reset, the holder's state changes — but commitReset still finalizes the queued reset, which OVERWRITES identityWallets[holder]. Means the holder's recent action gets clobbered. | 🚨 **Flag for circuits-eng** |

**Suggested mitigation:** a successful `register()` or `rotateWallet()` during the veto window should auto-`vetoReset()` (or check pendingResets and revert if one is queued). Otherwise the veto-period UX is "you must veto explicitly even if you actively use the wallet."

### Cross-flow concerns

- **Stuck pending resets:** if a queued `pendingResets[fingerprint]` is never `commit`-ed nor `veto`-ed (no one cares), it occupies storage forever. Suggest a TTL (e.g. veto_period × 4 = 28 days) after which anyone can call a `gcReset(fingerprint)` that just clears the struct and refunds the resetter's bond if any. Adds 1 entry point but bounds storage.

- **Blockchain reorgs:** all state transitions are single-tx. Reorgs of any depth are safe — the contract just sees the rolled-back state.

- **Time-source:** uses `block.timestamp`. ±15s skew on Base is fine for a 7-day veto window.

---

## §3 — ABI bump propagation cost

### `register()` selector + signature change

Current ABI:
```solidity
function register(
    Groth16Proof proof,
    PublicSignals(14) sig,
    bytes leafSpki,
    bytes intSpki,
    bytes signedAttrs,
    bytes32[2] leafSig,
    bytes32[2] intSig,
    bytes32[16] trustMerklePath,
    uint256 trustMerklePathBits,
    bytes32[16] policyMerklePath,
    uint256 policyMerklePathBits
) external;
```

New ABI (assumes amendment adds `walletCommitment`, `fingerprint` to public signals, possibly drops nullifier as separate field):
```solidity
function register(
    Groth16Proof proof,
    PublicSignals(15 or 16) sig,   // +1 to +2 fields
    bytes leafSpki,
    bytes intSpki,
    bytes signedAttrs,
    bytes32[2] leafSig,
    bytes32[2] intSig,
    bytes32[16] trustMerklePath,
    uint256 trustMerklePathBits,
    bytes32[16] policyMerklePath,
    uint256 policyMerklePathBits
) external;
```

Selector change: yes (PublicSignals struct shape changes). All existing tooling that pre-encodes register() calldata against the old layout breaks.

### Propagation matrix

| Consumer                     | Touch needed                                                  | Severity |
|------------------------------|---------------------------------------------------------------|----------|
| `packages/contracts-sdk` (Solidity) | `IQKBRegistry.sol` — likely no change if `nullifierOf` semantics preserved (recommendation §1). | ✓ Low |
| `packages/sdk` (viem helpers) | `src/registry/index.ts` `encodeRegisterFromSignals`, `src/facade/index.ts` — must update to new public-signal struct shape. ~4 hours work. | Medium |
| `packages/web` Step4 register | Calldata builder uses the JS SDK above; cascade through it. | Auto-cascades |
| `packages/circuits` witness builder | Already changes anyway (new circuit constraints). Owned by circuits-eng. | Owned |
| Third-party integrations     | None (V5 hasn't shipped to mainnet).                          | ✓ N/A |

### Interface ID (ERC-165)

The amendment ADDS new functions: `rotateWallet()`, `identityReset()`, `identityResetVeto()`, `commitReset()`, possibly `gcReset()`. ERC-165 interface ID is XOR of selectors, so it changes.

But: V5 doesn't currently implement ERC-165. `IQKBRegistry` exposes only view functions consumed by IdentityEscrowNFT. Nobody queries for an interface ID. **No churn from this dimension.**

### `IQKBRegistry` interface preservation

If the amendment redefines `nullifierOf` as "the wallet's identity commitment" (recommendation in §1):
- Same return type (`bytes32`), same uniqueness invariant.
- IdentityEscrowNFT.sol works without edit (it only checks `nullifierOf(holder) != 0`).
- External integrators reading `nullifierOf` still get a "stable wallet→bytes32 mapping that's non-zero iff registered" — the semantic is preserved at the consumer's abstraction level. They shouldn't have been using nullifierOf as a deduplicator anyway (that's the registrantOf path that's going away).

**Recommendation: add a deprecation comment** in `IQKBRegistry` that `nullifierOf`'s pre-image semantics changed (was Poseidon(subjectSerial, ctx); is now Poseidon(walletSecret, fingerprint)) but the type and uniqueness invariant are preserved.

---

## §4 — `rotateWallet()` proof system: (a) extended main circuit vs (b) separate small circuit

### From the contract side

| Aspect                  | (a) Mode-bit in main circuit              | (b) Separate rotateWallet circuit                       |
|-------------------------|-------------------------------------------|----------------------------------------------------------|
| Verifier addresses      | 1 (existing `groth16Verifier`)            | 2 (`groth16Verifier` + `rotateWalletVerifier` immutable) |
| Storage cost            | 0 new slots                               | 1 new immutable slot                                     |
| `register()` gas        | ~2.05M (current + amendment delta)        | ~2.05M (no change)                                       |
| `rotateWallet()` gas    | ~328K Groth16 (same circuit, same sig)    | ~200-280K Groth16 (smaller circuit, smaller pubsig array) |
| Code complexity         | Single dispatch in `register()`, mode bit branches inside | Two functions, cleaner separation                        |
| Audit complexity        | Same auditor must reason about combined main+rotate constraint set | Independent audit per circuit                            |
| Ceremony scope          | One zkey covers both modes (single ceremony) | Two zkeys, two ceremony events (or one larger event)     |
| Future evolution        | Coupled — change rotation logic = redo main ceremony | Decoupled — rotation circuit can evolve independently   |

### Subtle contract-side issue with (a)

If main circuit has a mode bit, the contract must verify the mode bit's intended semantics:
- mode=0 → register() flow → contract checks usedCtx + identityCommitments + identityWallets writes.
- mode=1 → rotateWallet() flow → contract checks identityCommitments rewrite + identityWallets swap.

Either:
- **Single `register()` function dispatches on mode bit** (couples the two flows in one entry point — bad for audit, bad for SDK ergonomics).
- **Two functions both calling the same verifier** but checking the public signal's mode bit and reverting if it doesn't match the expected mode for that entry point.

Option (b) avoids this entirely — each function calls its dedicated verifier; verifier rejects out-of-domain proofs naturally.

### Recommendation

**(b) Separate small circuit, weakly preferred from contract side.** Rationale:
1. Cleaner gas math: rotation is genuinely smaller work than register, gas should reflect it.
2. Audit isolation: rotation logic can be audited in isolation; main circuit doesn't grow.
3. Independent upgrade path: future improvements to rotation don't require a main circuit redeploy.
4. SDK ergonomics: two functions, one verifier per function — matches mental model.

**Caveats / defer to circuits-eng:**
- If the rotation circuit is so small (<100K constraints) that the per-circuit ceremony fixed cost (Phase 2 contributors, distribution, audit) dominates, (a) might be net cheaper at the project level. circuits-eng knows the constraint count better.
- If circuits-eng needs the main circuit to share specific gadgets (Poseidon templates, fingerprint derivation), inline-sharing in (a) might save constraints.

I'm not blocking on (b). Pick what circuits-eng favors based on circuit-side trade-offs; the contract side is happy with either.

---

## §5 — `identityReset()` anti-griefing options trade-off

The four options the lead surfaced. I've tabulated each on contract-side mechanics. Recommendation at the bottom.

### Option A — Time-locked veto (RECOMMENDED)

```solidity
struct PendingReset {
    bytes32 newCommitment;
    address newWallet;
    uint64  vetoableUntil;          // packs with newWallet
}
mapping(bytes32 => PendingReset) public pendingResets;  // fingerprint → pending

uint256 public constant VETO_PERIOD = 7 days;

function identityReset(bytes32 fingerprint, bytes32 newCommitment, address newWallet, Groth16Proof p, PublicSignals sig)
function vetoReset(bytes32 fingerprint, ResetVetoProof) — auth'd by current identityWallets[msg.sender]'s walletSecret
function commitReset(bytes32 fingerprint) — public, callable after vetoableUntil
function gcReset(bytes32 fingerprint) — clears stale pending after T+4×VETO_PERIOD; permissionless cleanup
```

| Dimension              | Cost                                          |
|------------------------|-----------------------------------------------|
| Storage / reset        | 1 SSTORE for pending struct (~22K, refundable) |
| Gas (queue)            | ~2.05M (Groth16 verify + SSTORE)              |
| Gas (commit)           | ~30K (apply struct, clear pending)            |
| Gas (veto)             | ~5K (clear pending) + auth-proof verify ~280K |
| UX                     | 7-day delay for legit recovery                |
| State entropy          | One pending struct per fingerprint; bounded   |
| Centralization         | None                                          |

**Pros:** Self-service. Cheapest gas at the queue site (the most-frequently-called path). Defeats stolen-QES ping-pong if user can detect within 7 days. Bounded storage entropy with `gcReset`.

**Cons:** 7-day delay for legitimate recovery. User must monitor for malicious resets.

### Option B — Bond / fee

```solidity
function identityReset(...) external payable;  // requires msg.value >= RESET_BOND
function challengeReset(...) external payable; // requires msg.value >= RESET_BOND
function resolveReset(bytes32 fingerprint) external; // selects winner by tiebreaker
```

| Dimension              | Cost                                          |
|------------------------|-----------------------------------------------|
| Storage / reset        | 2-3 SSTOREs (pending + bond + challenger?) ~44-66K |
| Gas (queue)            | ~2.05M + bond escrow (~5K)                    |
| Gas (challenge)        | ~2.05M + bond escrow (~5K)                    |
| Gas (resolve)          | ~30-50K                                       |
| UX                     | Must lock 0.01-0.1 ETH for challenge period   |
| Tiebreaker rule        | Complex (oldest commitment? freshest QES?)    |
| Edge cases             | What if both attacker and victim run out of bond? Both addresses marked recovery-locked? Permanent griefing if attacker has more capital. |

**Pros:** Economic disincentive against frivolous resets. Doesn't require monitoring a window.

**Cons:** Capital lockup hurts legitimate-recovery UX. Tiebreaker rule gets complex (every option I write here has at least one adversarial bypass). Doesn't prevent permanent ping-pong if attacker has capital.

### Option C — Disabled

```solidity
// no identityReset entry point
```

**Pros:** Zero new attack surface. Simplest amendment. Smallest audit delta.

**Cons:** Lost wallet + lost walletSecret = permanent identity lockout. UX disaster for non-power-users.

### Option D — Multi-sig

```solidity
mapping(bytes32 => MultisigState) public resetCouncil;
function identityResetVote(...) — only counsil members
function identityResetExecute(bytes32 fingerprint) — after threshold reached
```

**Pros:** Hard to grief at scale (attacker needs to compromise multiple council members).

**Cons:** Centralization. Counsel must operate. Off-chain coordination overhead. Doesn't fit the "trustless eIDAS" narrative.

### Recommendation: **Option A (time-locked veto)**

Cleanest contract-side mechanics:
- One mapping (pendingResets), one struct, four entry points.
- ~22K state cost per reset; ~5K refunded on either commit or veto.
- Self-service — no admin, no council, no off-chain dependency.
- Defeats stolen-QES ping-pong if user is reachable within 7 days.

Two **mandatory amendments** on Option A:

1. **Auto-veto on legitimate use.** A successful `register()` or `rotateWallet()` from `identityWallets[msg.sender]` during the veto window auto-clears `pendingResets[fingerprint]`. UX win — user doesn't need to call `vetoReset` explicitly if they're actively using their wallet.

2. **Reset event with rich indexed fields.** `event ResetQueued(bytes32 indexed fingerprint, bytes32 indexed newCommitment, address indexed newWallet, uint256 vetoableUntil)`. Lets watch services (Etherscan watchlists, Push Protocol, etc.) notify the existing wallet owner that a reset has been queued.

Optional refinement: a `notifierOf(bytes32 fingerprint) → address` mapping where users can register a watcher address to be notified via event filters. Out of scope for this review; punt to lead.

---

## §6 — Poseidon deployment confirmation

### Current V5 deployments

In the registry constructor:
```solidity
poseidonT3 = Poseidon.deploy(PoseidonBytecode.t3Initcode());  // Poseidon₂ (t=3, 2 inputs)
poseidonT7 = Poseidon.deploy(PoseidonBytecode.t7Initcode());  // Poseidon₆ (t=7, 6 inputs)
```

**Naming clarification (clearing up the dispatch's "T2 vs T3 vs T7"):**

| Library label  | Poseidon arity | Inputs | Used for                          |
|----------------|----------------|--------|------------------------------------|
| **T3**         | Poseidon₂      | 2      | Merkle climb, SpkiCommit final step |
| **T7**         | Poseidon₆      | 6      | SpkiCommit limb hash               |

There is **no PoseidonT2 instance**. "T2" in the dispatch was a typo — what's meant is **PoseidonT3 (Poseidon₂)**.

### Amendment's Poseidon usage

The proposed amendment uses Poseidon₂ in three on-chain-relevant places:
1. `commitment = Poseidon₂(walletSecret, fingerprint)` — verified in circuit, contract just stores/reads bytes32.
2. `usedCtx[fingerprint][ctxHash]` lookup — no Poseidon needed (mapping is by raw bytes32 keys).
3. Time-lock veto auth (if Option A): may use Poseidon for a fresh nullifier-style commitment — TBD by amendment.

**Crucial point: every on-chain Poseidon call in the amendment is Poseidon₂. PoseidonT3 (already deployed) covers it.** No new sub-deploys needed.

### What about `fingerprint` derivation?

`fingerprint = Poseidon(subjectSerialLimbs, subjectSerialLen)` — that's Poseidon₅ (5 inputs, t=6). NOT used on-chain. The circuit computes it and exposes it as a public signal; contract just consumes it as bytes32 for the `usedCtx` mapping key. **No PoseidonT6 deploy needed.**

If circuits-eng instead chose `fingerprint = Poseidon₂(Poseidon₂(serialLimbs[0,1]), Poseidon₂(serialLimbs[2,3], len))` (saturated to T3), that would be circuit-side cheaper too — but it's their call.

### Confirmation

✅ **No new Poseidon sub-contract deployments needed.** PoseidonT3 + PoseidonT7 cover everything. Constructor unchanged.

---

## Three holes — my position on each

### Hole #1 — `rotateWallet()` ZK proof of old walletSecret

**Agree, strongly.** Sig-only auth is weaker than the existing `register()`'s ZK + sig combination, and a stolen-wallet rotation that changes the commitment is permanent (vs. spam register attempts that fail anyway). The ZK proof of old walletSecret closes the "wallet stolen but walletSecret unknown to attacker" recovery path: if the user STILL has walletSecret (e.g. derived from a hardware wallet seed they backed up), they can rotate to a fresh wallet without trusting the stolen one. This is exactly the threat model that motivates the amendment.

**Add to the requirement:** the rotation circuit must also prove that newCommitment = Poseidon(newWalletSecret, fingerprint) for the SAME fingerprint as oldCommitment. Without this binding, an attacker with old walletSecret could rotate to a different identity. (This is probably implicit in circuits-eng's design but worth stating.)

### Hole #2 — SCW / ERC-1271 compatibility

**Agree with the V5 exclusion.** ERC-1271 contracts can't expose a private signing key for `personal_sign(walletPriv, …)` — the whole point of SCW is that the "private key" is replaced by access-control logic. So the wallet-derived secret doesn't exist in the SCW model.

V5 trades off SCW support for issuer-blindness. That's a sound trade for the launch population (browser wallets are the dominant V5 prover). Document it explicitly:

> ⚠️ V5 issuer-blind nullifier: SCW (ERC-1271) wallets are NOT supported. The walletSecret derivation requires an EOA's private signing key, which SCWs don't expose. SCW users see a "wallet-type unsupported" error at the prove step.

V6 candidate: a Pedersen-based set membership scheme that doesn't require wallet-side key derivation. Out of scope per the dispatch.

### Hole #3 — `identityReset()` DoS vector

**Agree, mitigation via Option A (time-lock veto) — see §5.** Without the veto, stolen QES = permanent ping-pong. Option A breaks the cycle by giving the legitimate holder a 7-day window to call `vetoReset`. With the auto-veto-on-use refinement, the UX cost is zero for actively-used wallets.

---

## Summary checklist for the eventual implementation phase

When circuits-eng's spec converges and lead dispatches implementation, my contract-side changes will be:

- [ ] Add 3 mappings (`identityCommitments`, `identityWallets`, `usedCtx`) + drop `registrantOf` per recommendation §1(β).
- [ ] If Option A picked: add `pendingResets` mapping + `PendingReset` struct + `VETO_PERIOD` constant.
- [ ] Update `register()` calldata layout (PublicSignals struct +1 to +2 fields).
- [ ] Add gates for `usedCtx` Sybil check, `identityCommitments` freshness check, `identityWallets` wallet-bind check.
- [ ] Add `rotateWallet()` entry point (with separate verifier address per §4 recommendation).
- [ ] Add `identityReset()`, `vetoReset()`, `commitReset()` entry points (Option A) + auto-veto-on-use in register/rotate.
- [ ] Add `gcReset()` for stale-pending cleanup.
- [ ] Add events: `ResetQueued`, `ResetCommitted`, `ResetVetoed`, `WalletRotated`, possibly modified `Registered` semantics.
- [ ] Update `IQKBRegistry.nullifierOf` semantics docstring (preserve the type/invariant, change the pre-image).
- [ ] Update test suite: 28 register tests need new public-signal layout; ~10 new tests for rotate + reset paths; gas snapshot ceiling stays at 2.5M (delta is small).
- [ ] Update `RealTupleGasSnapshot.t.sol` ceiling expectation (~2.05M → reset to slightly above empirical post-amendment number).
- [ ] No changes to `IdentityEscrowNFT.sol`. No changes to `Groth16VerifierV5Stub.sol` (circuits-eng pumps a new one).

**Effort estimate:** 2-3 days dedicated, matching the lead's estimate. The hardest part is the cross-flow auto-veto interaction in register/rotate; the rest is mechanical.

---

## Out-of-scope flags

- **Pedersen set-membership scheme.** Mentioned by the lead as V6 candidate. Genuinely interesting (cryptographic sybil resistance without persisting fingerprint on-chain) but high complexity. Not in this review.
- **ZK-friendly recovery via social verification.** Out of scope. The amendment's identityReset path subsumes this for V5.
- **EIP-3074 / EIP-7702 wallet authorization.** Could simplify rotateWallet but adds dependency on Pectra rollout. Not in this review.

---

## References

- Current V5 contract: `packages/contracts/src/QKBRegistryV5.sol` (HEAD `c2a13e4`)
- Current V5 spec: `docs/superpowers/specs/2026-04-29-v5-architecture-design.md` (HEAD includes `def6270` gas amendment)
- V4 prior nullifier amendment (context only): `docs/superpowers/specs/2026-04-18-person-nullifier-amendment.md`
- Real-tuple gas snapshot: `packages/contracts/test/integration/RealTupleGasSnapshot.t.sol` (commit `7ff73f2` + `c2a13e4`)
- Contract-side deploy script: `packages/contracts/script/DeployV5.s.sol` (no changes needed for amendment)
