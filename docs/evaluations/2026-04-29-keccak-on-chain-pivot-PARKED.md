# Evaluation: §6.8 keccak — move to contract (PARKED)

**Date:** 2026-04-29
**Author:** contracts-eng
**Status:** PARKED — founder declined the pivot. In-circuit keccak stays per spec at `55e388f`.
**Reason for parking:** Premature optimization. The on-chain move would have been driven by *projected* zkey size (~2.0-2.4 GB at the upper edge of the ≤2.5 GB acceptance gate after the §6.4 constraint-envelope re-amendment to 4.5M), not measured. If empirical ceremony zkey exceeds the acceptance gate, V5.1 SHA-off-circuit becomes the rewrite conversation — with real data — and this evaluation becomes the starting point.

**Resume conditions for V5.1:**
- Ceremony zkey actually exceeds 2.5 GB acceptance gate, OR
- Browser prove-time on flagship mobile (Pixel 9 / iPhone 15) misses the acceptance window after §11, OR
- Audit findings flag the zk-email keccak template as net audit-surface negative.

---

## Verdict (one paragraph)

**Yes, with the noted changes.** Moving the `pk → msg.sender` keccak on-chain is sound, fits cleanly in the existing `register()` 5-gate pattern, costs ~25-30K extra gas (well under the 600K budget), and arguably *reduces* total audit surface (native EVM keccak vs. zk-email's keccak-circom template). The soundness chain stays intact: the binding (signed by Diia QES) asserts the wallet's pk inside its payload; the in-circuit `Secp256k1PkMatch` keeps binding-side bind (witnessed-pk vs. binding-asserted-pk); the circuit emits `pkCommit = Poseidon(Poseidon(X-limbs), Poseidon(Y-limbs))` over the witnessed pk; the contract verifies (a) the calldata-supplied pk's `pkCommit` matches the proof's, AND (b) `keccak(pk_X ‖ pk_Y)[12:] == msg.sender`. The single non-trivial wrinkle is sequencing: the 14→15 public-input count change is a setup-time decision and must lock BEFORE circuits-eng's §8 stub ceremony runs, otherwise we re-do §8.

## Calldata layout proposal

Current `register()` is 11 fields. Add ONE: a fixed-size `bytes32[2]` for the wallet pk's X,Y. Slot it after `intSpki` for proximity grouping (all key materials live together). Use `bytes32[2]` not `bytes` — saves DER-walk overhead, aligns with `leafSig`/`intSig` pattern, drops `0x04` SEC1 prefix that contributes nothing to either keccak or pkCommit.

```solidity
function register(
    Groth16Proof   calldata proof,
    PublicSignals  calldata sig,
    bytes          calldata leafSpki,
    bytes          calldata intSpki,
    bytes32[2]     calldata uncompressedPk,   // NEW — (pkX, pkY) of caller's wallet
    bytes          calldata signedAttrs,
    bytes32[2]     calldata leafSig,
    bytes32[2]     calldata intSig,
    bytes32[16]    calldata trustMerklePath,
    uint256                 trustMerklePathBits,
    bytes32[16]    calldata policyMerklePath,
    uint256                 policyMerklePathBits
) external;
```

**Calldata bump:** +64 bytes. ~2.2-2.4 KB → ~2.3-2.5 KB. Acceptable. Costs ~1K gas at L2 calldata pricing.

**Why bytes32[2] not 65-byte SEC1:** keccak's eth-address derivation already skips the `0x04` prefix; pkCommit feeds X/Y straight into limb decomposition. Carrying the prefix is dead weight + an extra length check + a parser entry.

## Public-signal layout proposal

Append `pkCommit` at index [14]. Layout becomes 15 fields. **Do NOT renumber [0..13]** — keeps existing test fixture indices, preserves `signedAttrsHashHi/Lo` etc. positions, and saves a wave of churn across web-eng's witness builder + contract test suite.

```solidity
struct PublicSignals {
    uint256 msgSender;          // [0]
    uint256 timestamp;          // [1]
    uint256 nullifier;          // [2]
    uint256 ctxHashHi;          // [3]
    uint256 ctxHashLo;          // [4]
    uint256 bindingHashHi;      // [5]
    uint256 bindingHashLo;      // [6]
    uint256 signedAttrsHashHi;  // [7]
    uint256 signedAttrsHashLo;  // [8]
    uint256 leafTbsHashHi;      // [9]
    uint256 leafTbsHashLo;      // [10]
    uint256 policyLeafHash;     // [11]
    uint256 leafSpkiCommit;     // [12]
    uint256 intSpkiCommit;      // [13]
    uint256 pkCommit;           // [14]  NEW — Poseidon₂(Poseidon₆(pkX-limbs), Poseidon₆(pkY-limbs))
}
```

`Groth16VerifierV5.verifyProof` ABI bumps `uint256[14] → uint256[15]` automatically when snarkjs regenerates from the new zkey. No manual verifier surgery.

## Gas estimate revision

Current spec §3 gas budget: ~440-490K register(). Tighter breakdown of the proposed addition:

| Op                                                | Gas    |
|---------------------------------------------------|--------|
| +64 bytes calldata for uncompressedPk             | ~1.0K  |
| `keccak256(abi.encodePacked(pkX, pkY))`           | ~0.05K |
| `uint160(...) == uint160(msg.sender)` compare     | ~0.02K |
| `decomposeTo643Limbs(pkX)` + `(pkY)` (assembly)   | ~0.1K  |
| 2× Poseidon₆ staticcall (PoseidonT7)              | ~16-20K|
| 1× Poseidon₂ staticcall (PoseidonT3)              | ~3-4K  |
| `pkCommit == sig.pkCommit` compare                | ~0.02K |
| Groth16 verifier 14→15 inputs (1 extra G1 mul+add)| ~5K    |
| **Net add**                                       | **~25-30K** |

`sig.msgSender == uint160(msg.sender)` (existing Gate 5) STAYS as defense-in-depth; cost unchanged (~0.02K).

**New register() total: ~465-520K.** Headroom under 600K acceptance: 80-135K (15-23%). Comfortable.

## Risks and wrinkles

1. **Ceremony sequencing — flag.** The 14→15 public-input count is a setup-time parameter. If circuits-eng's §8 stub ceremony freezes pubsig count at 14 before this change lands, we'd need to re-do §8 (and §11 once it lands). **Recommended sequencing for any V5.1 resume:** lock the spec amendment + push the circuit change BEFORE §8 stub runs.

2. **In-circuit `Secp256k1PkMatch` retained.** Keep it. It does the binding-side bind (`parser.pkBytes ↔ pkX/pkY` — i.e., the witnessed pk equals the pk Diia signed inside the binding). The MOVED part is just the `keccakAddress = keccak(pk)[12:]; constrain == msgSender` step. Net circuit change: drop the keccak-circom subtree (~150K constraints), ADD a single output signal `pkCommit` wired through the existing field-domain Poseidon templates (~50-100 constraints — the limb decomposition + Poseidon₆ ×2 + Poseidon₂ pattern is already in V5 for SpkiCommit).

3. **Audit surface — net reduction.** zk-email keccak-circom is well-trodden but a moderate-complexity subcircuit; its proof of correctness sits inside the V5 audit scope. Native EVM keccak is a single op with 8 years of unbroken track record. The contract delta (one keccak + one Poseidon-over-(X,Y)) reuses the *exact same* Poseidon-limb-commit machinery that's already in `lib/P256Verify.sol::spkiCommit`, just over a 64-byte (X,Y) input instead of 91-byte SPKI input. Either add a thin `pkCommit(bytes32 x, bytes32 y)` helper or refactor `spkiCommit` to a private `_commitXY(x, y)` and have both public APIs delegate (cleaner — zero duplication).

4. **Test churn.** All 28 tests in `QKBRegistryV5.register.t.sol` would need updating: extra calldata field, extra public signal, two new revert paths (`BadPkCommit`, and either `BadSender` semantics expansion or new `BadKeccakSender`). Estimate: 2-3 hours of mechanical test refactor + ~6 new positive/negative tests. Doable in one commit.

5. **Witness builder (web-eng).** Trivial: web-eng's V5 witness builder already has the user's wallet keypair to feed into `Secp256k1PkMatch`. After the change it ALSO needs to (a) include uncompressedPk in the `register()` call (already accessible), and (b) verify that the circuit's emitted `public.json` includes pkCommit at index [14] (automatic — circuit emits it). No new dependencies.

6. **Calldata source for pkCommit.** No wrinkle. pkCommit is a circuit OUTPUT, not an input — circuits-eng wires `pkCommit <== Poseidon₂(Poseidon₆(LimbDecompose643(pkX)), Poseidon₆(LimbDecompose643(pkY)))` and exposes as `public output`. Witness builder doesn't need to compute it; it just needs to send the correct (pkX, pkY) which it already does for the binding-side bind.

7. **Frontrunning / replay surface unchanged.** A frontrunner with the proof would need to (a) supply matching uncompressedPk calldata, (b) which keccaks to msg.sender, and (c) which Poseidon-commits to the proof's pkCommit. Forging any of these requires breaking either keccak collision-resistance (post-quantum question, not classical) or the Groth16 soundness (= ceremony toxicity question). Same threat model as today.

8. **`sig.msgSender` redundancy.** With the new pkCommit + keccak gate, the existing `sig.msgSender == uint160(msg.sender)` check at Gate 5 is functionally redundant (the keccak path proves the same thing). Recommend KEEPING it as defense-in-depth: cost is ~6 gas, and it gives a clearer revert reason for the common "user submits proof from wrong wallet" mistake (`BadSender` vs. `BadKeccakSender` — the user's mental model maps to the former).

## Open questions deferred

1. Drop or keep msgSender in public signals? (Recommended KEEP.)
2. Sequencing — lock before §8 stub? (Strongly recommended yes.)
3. Error name for pk-commit mismatch. (Recommended new `error BadPkCommit();` + new `error BadKeccakAddress();`.)
4. Helper API in `lib/P256Verify.sol` — sibling vs. private refactor. (Recommended private refactor.)
5. Documentation churn — spec §0.1, §0.2, §3, constraint-count table all need amendment.
6. Sanity flag: the "circuit shrinks ~150K constraints" claim assumes the keccak-circom template is the *only* thing being removed. Worth circuits-eng confirming exact savings — expected ~120-180K depending on template structure.

## Why this was parked

The on-chain pivot was driven by projection, not measurement. The §6.4 amendment raised the constraint envelope from 1.85M → 3M → 4.5M and projected zkey to 2.0-2.4 GB at the upper edge of the ≤2.5 GB acceptance gate. The fear was that crossing the gate would force a redesign mid-ceremony.

Founder's call: empirical ceremony output is the right trigger for an architectural rewrite, not a projected number. If §11 produces a zkey that exceeds 2.5 GB OR if browser prove-time misses the mobile acceptance window OR if audit findings flag the keccak-circom template, then this evaluation comes off the shelf and the V5.1 SHA-off-circuit + keccak-on-chain rewrite becomes a coordinated multi-package change with real measurements driving the gas/constraint trade-off.

Until then: V5 ships with in-circuit keccak per the locked-in spec at `55e388f`. The 600K gas target stands, the 14-field public-signal layout stands, the 11-arg `register()` ABI stands.

## References

- Spec amendment locking in-circuit keccak: commit `55e388f`
- §6.4 envelope re-amendment 3M→4.5M: commit `77ed00d`
- Spec pass 5 reconciliation (zkey 2.0-2.4 GB, acceptance 2.5 GB): commit `9c866ad`
- A1 plan §6.8 task: `docs/superpowers/plans/2026-04-29-v5-architecture-circuits.md` Task 6.8
- Current `register()` implementation: `packages/contracts/src/QKBRegistryV5.sol` (HEAD `2b4c3b9`)
- Contract-side commit-helper machinery to reuse: `packages/contracts/src/libs/P256Verify.sol::spkiCommit`
