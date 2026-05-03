# Keccak-On-Chain (V5.2) — Independent Contract-Side Review

**Date:** 2026-05-01
**Reviewer:** contracts-eng on `feat/v5_2arch-contracts` (cut from `main` @ `024b62b`)
**Reviews:** circuits-eng's V5.2 spec v0.3 at `docs/superpowers/specs/2026-05-01-keccak-on-chain-amendment.md` (commit `5ba064e` on `feat/v5_2arch-circuits`).
**Status:** Review-only. No contract code changes in this dispatch. Implementation deferred to post-user-review gate.

---

## TL;DR

The V5.2 amendment is **clean from the contract side**. Circuits-eng's Option A (4 × 128-bit `bindingPkX/Y` public-signal limbs, drop `msgSender` from public signals, drop in-circuit keccak) is the right call — I endorse it unconditionally. Three contract-side concrete proposals:

1. **Endorse Option A** over Option B (in-Yul JSON parse). Option B's gas + audit-surface penalty is severe and avoidable.
2. **Endorse the clean reshuffle** (V5.1 slots 1-18 shift down to V5.2 slots 0-17, new pk-limbs at 18-21). The hard-zero-at-slot-0 alternative pollutes calldata for no win since V5.1 has no deployed registries to migrate.
3. **`rotateWallet()` needs no new contract gate** beyond the V5.1 logic. Spec §"Cost estimate" is correct as written. (An earlier draft of this review proposed a `derivedAddr == identityWallets[fp]` defense-in-depth check; codex round-3 [P1] correctly flagged that this would break the legitimate "rotate-with-fresh-QES" flow V5.1 intentionally supports — see §3.2 for the withdrawal rationale. Recommendation withdrawn.)

| Function           | V5.1 (deployed gas: 2,097,890) | V5.2 (Option A, projected) |
|--------------------|--------------------------------|----------------------------|
| `register()` first claim | 2,097,890 | **+~750 gas** total (~250 gas for the on-chain keccak/sender-bind/no-op gates, plus ~500 gas for 3 net-new non-zero calldata words at 16 gas/byte × 32 bytes × 3 limbs net — actual delta depends on how many high bytes are zero in the prover's pk encoding). Vs ~2.1M baseline ⇒ **0.036% delta**. |
| `rotateWallet()` (V5.1 ~380K projected real-pairing) | ~380K | **+0 gas** (no new contract gates — see §3.2 for why the proposed defense-in-depth gate was withdrawn; rotateWallet just packs 22 instead of 19 verifier inputs and the verifier itself absorbs the larger input array). |
| Public signal count | 19 | **22** (drop msgSender → -1; add bindingPk*4 → +4) |
| Verifier ABI    | `IGroth16VerifierV5_1` (`uint[19]`) | New `IGroth16VerifierV5_2` (`uint[22]`) |
| Yul stack pressure | Hit at `uint[19]`, fixed via `assembly("memory-safe")` (V5.1 commit `04b4a71`) | Larger — `uint[22]` will need the same annotation; potentially additional struct-construction refactoring (V5.1 also hit Yul stack-too-deep on the 19-field PublicSignals struct literal; 22 fields will be worse). Manageable; document during implementation. |

State layout: **unchanged** (all five V5.1 mappings persist verbatim; V5.2 is a fresh redeploy with no upgrade path, same posture as V4→V5 and V5→V5.1). No NFT contract changes.

**Concerns I considered and dismissed:**

- ❌ "Move spkiCommit + keccak to share a single parseSpki call" — wrong primitive boundary. spkiCommit acts on the LEAF CERT pk (P-256). The new keccak gate acts on the BINDING's wallet pk (secp256k1). Different bytes, different curves, different sources; no shared parse path possible.
- ❌ "Cache derived address in a state variable" — derivable in <300 gas; caching costs >2K (SSTORE warm). Net loss.
- ❌ "Skip the rotation-no-op gate move under register" — wrong. V5.1 enforced this gate in-circuit; if V5.2 drops it AND doesn't move it on-chain, register-mode proofs could leave `rotationNewWallet` arbitrary, breaking the V5.1 dual-entrypoint invariant. Must move on-chain. Spec gets this right.

---

## §1 — State layout impact

**Zero state-mapping changes.** All V5.1 mappings persist verbatim:

| Mapping | V5.2 change |
|---------|-------------|
| `nullifierOf[address] → bytes32` | None |
| `identityCommitments[bytes32] → bytes32` | None |
| `identityWallets[bytes32] → address` | None |
| `usedCtx[bytes32][bytes32] → bool` | None |
| `trustedListRoot, policyRoot, admin` | None |
| `MAX_BINDING_AGE = 1 hours` | None |

V5.2 is a fresh redeploy (`QKBRegistryV5_2.sol`) with same `IQKBRegistry` interface (downstream `IdentityEscrowNFT` consumers unchanged). Holders re-register in the same flow as V5→V5.1.

---

## §2 — `register()` flow before/after (Option A)

### V5.1 (current, deployed in spirit, not yet on Sepolia)

```
1. Mode gate: sig.rotationMode == 0.
2. Pack 19 public signals → uint[19].
3. Groth16.verifyProof(proof, input19) — circuit asserts INTERNALLY:
     keccak256(parser.pkBytes[1..65])[12..32] == msgSender    ← V5.2 DROPS THIS
     parser.pkBytes (binding's wallet pk) ↔ pkX/pkY limbs    ← V5.2 REPLACES with Bits2Num packing
     rotationNewWallet === msgSender                           ← V5.2 MOVES TO CONTRACT (register-mode no-op gate)
4. Gate 2a: sha256(signedAttrs) hi/lo == sig[7..8].
5. Gate 2a: spkiCommit(leafSpki) == sig[12]; spkiCommit(intSpki) == sig[13].
6. Gate 2b: 2× P256Verify (leaf + intermediate).
7. Gate 3-4: trust + policy Merkle climbs.
8. Gate 5: timestamp window + msg.sender == sig.msgSender (V5.1's `BadSender` check). ← V5.2 REPLACES with derivedAddr == msg.sender
9. Gate 6/7 (V5.1): identity-fingerprint discriminator + write-out.
```

### V5.2 (Option A proposed)

```
1. Mode gate: sig.rotationMode == 0.
2. Pack 22 public signals → uint[22] (drop msgSender; append bindingPkX/Y limbs).
3. Groth16.verifyProof(proof, input22) — circuit asserts INTERNALLY:
     SEC1 prefix: parser.pkBytes[0] === 0x04                  ← retained
     bindingPkXHi/Lo, bindingPkYHi/Lo === Bits2Num(parser.pkBytes[1..65])  ← replaces Secp256k1PkMatch
     rotationOldCommitment === identityCommitment under register mode  ← unchanged (V5.1 ForceEqualIfEnabled gate STAYS in-circuit)
     rotationOldCommitment === Poseidon₂(subjectPack, oldWalletSecret) under rotate mode  ← unchanged
     // ONLY the rotationNewWallet === msgSender no-op gate REMOVED — moves to contract.
     // The PAIRED rotationOldCommitment === identityCommitment no-op stays in-circuit
     // because it doesn't reference msgSender.
4. Gate 2a-prime (NEW): contract reconstructs uncompressed pk + keccak + derives address.
     bytes16 pkXHi = bytes16(uint128(sig.bindingPkXHi));
     // ... repeat for Lo, YHi, YLo ...
     bytes memory pk = abi.encodePacked(pkXHi, pkXLo, pkYHi, pkYLo);  // 64 bytes
     address derivedAddr = address(uint160(uint256(keccak256(pk))));
5. Gate 2a-prime sender bind (NEW, replaces V5.1's BadSender):
     if (derivedAddr != msg.sender) revert WalletDerivationMismatch();
6. Gate 2a-prime register-mode rotation no-op (NEW, replaces V5.1's circuit ForceEqualIfEnabled):
     if (sig.rotationNewWallet != uint256(uint160(msg.sender))) revert WrongRegisterModeNoOp();
     // (Note: equivalent to checking sig.rotationNewWallet == sig.msgSender in V5.1 — but msgSender
     //  is now derived, so the check is against the derived value, which equals msg.sender by Gate 5.)
7. Gate 2a (existing): sha256(signedAttrs) hi/lo unchanged.
8. Gate 2a (existing): spkiCommit(leafSpki) and spkiCommit(intSpki) unchanged.
9. Gate 2b–4 (existing): 2× P256Verify, trust + policy Merkle — unchanged.
10. Gate 5 (existing minus BadSender): timestamp window only. The msgSender bind has migrated to Gate 2a-prime above.
11. Gate 6/7 (V5.1): identity-fingerprint discriminator + write-out — unchanged.
```

The key shift: **two V5.1 in-circuit gates move on-chain** (keccak-of-pk → msgSender bind; register-mode rotation no-op). Three V5.1 contract gates simplify (BadSender folds into WalletDerivationMismatch; one fewer public-signal slot to compare against).

### §2.1 — Contract-side keccak gate implementation (Yul-friendly)

Two implementation options for the 4-limb → 64-byte → keccak step. Both are <300 gas. Option I uses pure Solidity; Option II uses inline assembly for slightly better gas (~50 gas savings). Recommend Option I unless implementation needs the extra slack.

**Endianness alignment (load-bearing — must match circuits-eng's Bits2Num packing exactly):**

Circuits-eng spec §"Construction" specifies:
```
pkXHi = sum_{i=0..15}  parser.pkBytes[i+1]  * 256^(15-i)
pkXLo = sum_{i=16..31} parser.pkBytes[i+1]  * 256^(31-i)
```

So `pkXHi = pkBytes[1]·256^15 + pkBytes[2]·256^14 + ... + pkBytes[16]·256^0` — **big-endian** (pkBytes[1] is the most-significant byte, contributing 256^15).

In Solidity:
- `uint128(sig.bindingPkXHi)` extracts the low 128 bits. Numeric value: `pkBytes[1]·256^15 + ... + pkBytes[16]`.
- `bytes16(uint128(...))` casts a 128-bit numeric to a 16-byte left-aligned bytes16. The high byte of the numeric value (here pkBytes[1]) becomes byte 0 of the bytes16; pkBytes[16] becomes byte 15.
- `abi.encodePacked(bytes16(pkXHi), bytes16(pkXLo), bytes16(pkYHi), bytes16(pkYLo))` concatenates: byte 0 = pkBytes[1], byte 15 = pkBytes[16], byte 16 = pkBytes[17], ..., byte 63 = pkBytes[64].
- The 64-byte result equals `parser.pkBytes[1..65]` byte-for-byte.

V5.1's in-circuit keccak operated on `parser.pkBytes[1..65]` (the same 64 raw uncompressed-pubkey bytes, sans the 0x04 prefix at index 0). Therefore:

```
keccak256(abi.encodePacked(bytes16(uint128(pkXHi)), ..., bytes16(uint128(pkYLo))))
  ===
keccak256(parser.pkBytes[1..65])           # V5.1 in-circuit keccak input
```

The byte-equality is provable from the spec's Bits2Num formula. **Soundness equivalence at the keccak input boundary is exact**, not approximate.

**Option I — Solidity:**

```solidity
function _deriveAddrFromBindingLimbs(PublicSignals calldata sig)
    internal pure returns (address)
{
    // Each limb is a uint256 in the public-signal vector but Bits2Num(128)-bounded.
    // The uint128 cast truncates to low 128 bits — defense-in-depth against a
    // malicious witness builder supplying a >128-bit value (which would be
    // invalid per circuit constraints but cheap to gate here).
    //
    // Endianness: bytes16(uint128(...)) places the high byte of the numeric
    // value at byte 0 of the bytes16 (left-aligned). Concatenated, the 64-byte
    // result reproduces parser.pkBytes[1..65] in the same byte order V5.1's
    // in-circuit keccak consumed. See "Endianness alignment" above.
    bytes memory pk = abi.encodePacked(
        bytes16(uint128(sig.bindingPkXHi)),
        bytes16(uint128(sig.bindingPkXLo)),
        bytes16(uint128(sig.bindingPkYHi)),
        bytes16(uint128(sig.bindingPkYLo))
    );
    return address(uint160(uint256(keccak256(pk))));
}
```

Gas accounting (Option I):
- `bytes16(uint128(...))` × 4 = ~30 gas total (mostly type-cast bookkeeping)
- `abi.encodePacked` for 64 bytes → 1 mload-equivalent + 64 bytes write to memory = ~100 gas
- `keccak256` over 64 bytes = 36 + ⌈64/32⌉ × 6 = **48 gas**
- `address(uint160(uint256(...)))` = ~10 gas
- Sender compare = ~10 gas
- **Total: ~200 gas.** Add the rotation-no-op gate (~50 gas comparison + revert path) = ~250 gas.

**Option II — assembly (saves ~50 gas):**

```solidity
function _deriveAddrFromBindingLimbs(PublicSignals calldata sig)
    internal pure returns (address derived)
{
    bytes32 hash;
    assembly ("memory-safe") {
        let m := mload(0x40)
        // bindingPkXHi at sig.bindingPkXHi offset; mask to low 128 bits, shift left
        // by 128 to right-justify into the high 16 bytes of the 32-byte slot.
        // Repeat for Lo, YHi, YLo. Concatenated: 4 × 16 = 64 bytes at m..m+64.
        mstore(m,        shl(128, calldataload(<pkXHi cd offset>)))
        mstore(add(m, 16), shl(128, calldataload(<pkXLo cd offset>)))
        mstore(add(m, 32), shl(128, calldataload(<pkYHi cd offset>)))
        mstore(add(m, 48), shl(128, calldataload(<pkYLo cd offset>)))
        hash := keccak256(m, 64)
        // Don't bump 0x40 — caller's callframe doesn't use this region.
    }
    derived = address(uint160(uint256(hash)));
}
```

Note: the `<pkXHi cd offset>` etc. are computed by the Solidity compiler from the `PublicSignals calldata sig` parameter; this is illustrative. Real implementation will use `sig.bindingPkXHi` etc.; Yul's calldataload-style extraction is what the Solidity compiler emits.

**Recommendation: Option I** unless gas pressure justifies Option II. 50-gas savings vs 2.1M baseline = 0.0024% — too small to trade clarity.

### §2.2 — Contract-side rotation-no-op gate move (REGISTER-MODE ONLY)

V5.1's circuit ForceEqualIfEnabled gate `(1 - rotationMode) * (rotationNewWallet - msgSender) === 0` enforced under register mode that `rotationNewWallet === msgSender`. With msgSender no longer in the public-signal vector under V5.2, this constraint cannot be enforced in-circuit (the gate would reference a nonexistent signal). It MUST move to the contract.

The clean implementation:

```solidity
// Right after the keccak derivation in register() (Gate 2a-prime above):
if (sig.rotationNewWallet != uint256(uint160(msg.sender))) {
    revert WrongRegisterModeNoOp();
}
```

This is **one line + one new error**. Equivalent to V5.1's circuit gate under register mode. Under rotate mode, the gate doesn't apply (V5.1's `enabled = 1 - rotationMode` was 0; V5.2's contract gate is only inside `register()`, not `rotateWallet()`).

**Critical: `rotateWallet()` does NOT need the analogous gate**. Under rotate mode, `sig.rotationNewWallet` is intentionally distinct from V5.1's `sig.msgSender` (the new wallet is a different identity from the wallet that originally signed the binding). The existing V5.1 contract checks (`newWallet == msg.sender`, ECDSA recovery == oldWallet) are already in place.

### §2.3 — `_packPublicSignals()` helper update

V5.1's `_packPublicSignals(sig)` returns `uint256[19] memory`. V5.2's helper:

```solidity
function _packPublicSignalsV52(PublicSignals calldata sig)
    internal pure returns (uint256[22] memory input)
{
    // V5.2 layout (frozen per circuits-eng spec §"Public-signal layout"):
    input[0]  = sig.timestamp;             // V5.1 slot 1, shifted down 1
    input[1]  = sig.nullifier;
    input[2]  = sig.ctxHashHi;
    input[3]  = sig.ctxHashLo;
    input[4]  = sig.bindingHashHi;
    input[5]  = sig.bindingHashLo;
    input[6]  = sig.signedAttrsHashHi;
    input[7]  = sig.signedAttrsHashLo;
    input[8]  = sig.leafTbsHashHi;
    input[9]  = sig.leafTbsHashLo;
    input[10] = sig.policyLeafHash;
    input[11] = sig.leafSpkiCommit;
    input[12] = sig.intSpkiCommit;
    input[13] = sig.identityFingerprint;
    input[14] = sig.identityCommitment;
    input[15] = sig.rotationMode;
    input[16] = sig.rotationOldCommitment;
    input[17] = sig.rotationNewWallet;
    input[18] = sig.bindingPkXHi;          // NEW
    input[19] = sig.bindingPkXLo;          // NEW
    input[20] = sig.bindingPkYHi;          // NEW
    input[21] = sig.bindingPkYLo;          // NEW
}
```

**Yul stack pressure caveat (lessons from V5.1 commit `04b4a71`):** V5.1's 19-field struct literal in tests required field-by-field `sig.X = pubInputs[N]` assignment to avoid Yul stack-too-deep under via_ir. V5.2's 22-field struct will be MORE pressed. The `_packPublicSignals` body can be sequentially-assigned (as above — each `input[N] = sig.X` is a single statement) which the Yul optimizer handles fine. The test-side struct construction (RealTupleGasSnapshot.t.sol pattern) will likely need the same field-by-field workaround. Keep V5.1's lesson: prefer field-by-field over struct-literal in helpers.

---

## §3 — Attack surface review

### §3.1 — Soundness of contract-side keccak gate

The V5.1 chain (in-circuit):
```
parser.pkBytes ← BindingParseFull (extracts the binding's `pk` field)
   ↓ Secp256k1PkMatch (bytes-to-limbs repacking, 4 × 64-bit LE limbs)
pkX[4]/pkY[4] witness limbs
   ↓ Secp256k1AddressDerive (Keccak-256 over parser.pkBytes[1..65])
160-bit Ethereum address (low bits of digest)
   ↓ === msgSender public signal
   ↓ contract: msg.sender == sig.msgSender
msg.sender wallet identity (EVM-style)
```

The V5.2 chain:
```
parser.pkBytes ← BindingParseFull (UNCHANGED)
   ↓ Bits2Num packing (in-circuit, 4 × 128-bit Hi/Lo limbs)
bindingPkXHi/Lo, bindingPkYHi/Lo public signals
   ↓ contract: bytes16(uint128(...)) ×4 → keccak256(64-byte concat)
160-bit address (Solidity uint160 cast)
   ↓ contract: derivedAddr == msg.sender
msg.sender wallet identity
```

**Equivalence (EVM only):** Both chains share the BindingParseFull → parser.pkBytes step. The packing primitive differs (Secp256k1PkMatch vs Bits2Num) but both are deterministic byte-equality reshapes — sound bytes-to-limb conversions, no soundness gap. The keccak primitive is bitwise-identical between the bkomuves vendored circom Keccak and the EVM `KECCAK256` opcode (Yellow Paper §11.2). The address-bit-extraction step is `digest[12..32]` in V5.1 vs Solidity's `uint160(uint256(digest))` cast in V5.2 — both extract the low 160 bits of the 256-bit digest.

**Conclusion: V5.2 is soundness-equivalent to V5.1 on EVM chains.** Circuits-eng's spec §"Soundness — keccak-on-chain ≡ keccak-in-circuit" makes the same argument; concur with the equivalence proof sketch.

### §3.2 — `rotateWallet()` defense-in-depth gate (proposed enhancement, NOT a soundness gap)

> **⚠ POST-IMPLEMENTATION CORRECTION (2026-05-03, after T1 commit `c47b5a5`):**
> The proposed `derivedAddr == identityWallets[fp]` gate **was withdrawn during T1
> implementation** because it would unconditionally REVERT every legitimate rotation:
> in rotate mode, `derivedAddr` (computed from the proof's `bindingPkX/Y` limbs)
> is the **NEW wallet's** address, not the OLD wallet's. The proof's binding pk is
> bound to the new wallet (since the user's QES re-issue or fresh-binding flow
> produces a binding declaring the new wallet pk). Equating that against the
> stored `identityWallets[fp]` (which is the OLD wallet) is structurally wrong —
> not just over-restrictive but always-false on any legitimate rotation.
>
> The keccak-on-chain amendment's spec at `8f5277f` §3.2 still describes the
> proposed gate as a defense-in-depth recommendation. **That spec section is
> stale and should be treated as withdrawn.** The contract correctly does NOT
> implement the gate. See QKBRegistryV5_2.sol's `rotateWallet()` docstring
> (commit `c47b5a5`) for the in-tree explanation.
>
> The reasoning that follows in this §3.2 was the v0.4 framing pre-implementation
> (treating it as "defense-in-depth, not load-bearing"). Even that v0.4 framing
> was too charitable: the gate isn't defense-in-depth, it's structurally-broken-
> for-the-rotation-flow. Threat-model resolution stands on V5.1's existing
> chain: rotation auth ECDSA sig from oldWallet's privkey (recovered via
> ecrecover, must match `identityWallets[fp]`) is the load-bearing on-chain
> binding. No additional contract gate is needed or appropriate.

The spec's §"Cost estimate" says:

> contracts-eng — Add keccak gate to `register()`: reconstruct 64-byte uncompressed pk from 4 public-signal limbs, `keccak256(pk)[12..32] == msg.sender`. Add register-mode no-op gate `rotationNewWallet == msg.sender` (V5.1 had this in-circuit; V5.2 moves on-chain). **`rotateWallet()` already enforces `rotationNewWallet == msg.sender` (no change there per V5.1's existing contract logic)**.

The bolded claim is **correct on soundness grounds**. I want to surface a **defense-in-depth opportunity** that V5.2 has but V5.1 didn't have on the contract side either — adding it would be a NEW invariant, not the preservation of an existing one.

**Honest accounting of V5.1's rotate-mode binding chain:**

In V5.1 rotate mode, the contract's `rotateWallet()` does NOT check `sig.msgSender` against anything (`msg.sender == newWallet`, not the OLD wallet whose pk would equal `keccak(parser.pkBytes)`). The on-chain binding to the old wallet flows entirely through:
1. ECDSA recovery from `oldWalletAuthSig` MUST equal `identityWallets[fp]` (the stored old wallet).
2. The auth payload binds `chainid + registry + fingerprint + newWallet` (V5.1 commit `76ed4d6`).

The circuit's in-circuit keccak gate (`pkAddr.addr === msgSender`) DID constrain `msgSender == keccak(parser.pkBytes)[12..32]` under both modes — but the contract didn't read that against the old-wallet binding. So under V5.1, `parser.pkBytes` (binding pk) was constrained CIRCUIT-INTERNALLY to keccak to the msgSender public signal, but the contract didn't tie msgSender to identityWallets[fp] under rotate mode. The auth sig was the only on-chain binding to the old wallet.

**V5.2 drops the in-circuit keccak gate.** Under rotate mode, V5.2's `bindingPkX/Y` becomes a witnessed-public value with no on-chain check tying it to the old wallet (other than ceremony-equivalent constraints inside the proof — e.g., subjectPack opening). The proof verifies; the auth sig still binds the caller's authority to the old wallet's privkey.

**Risk scenario (rotate mode, V5.2 without the proposed defense-in-depth gate):**
- Attacker has stolen the OLD wallet's cert + binding bytes (or has them via OSINT).
- Attacker generates a V5.2 proof in rotate mode with `bindingPkX/Y` = (attacker-chosen) instead of the real old-wallet pk.
- Attacker submits via their own NEW wallet.
- Proof verifies. Contract's existing gates: `newWallet == msg.sender` ✓; `nullifierOf[newWallet] == 0` ✓; ECDSA-recovered signer of `oldWalletAuthSig` MUST equal `identityWallets[fp]`. **Attacker doesn't control old wallet's privkey → ECDSA recovery fails → revert.** ✓ Safe.

So **rotate-mode flow is sound WITHOUT a new on-chain keccak gate**, both in V5.1 and in V5.2. The auth sig is the load-bearing primitive; the keccak chain was a circuit-internal detail in V5.1 with no on-chain consumer in rotateWallet.

**The candidate gate (rejected on closer inspection):**

```solidity
// rotateWallet() — initial v0.4 draft proposed:
// address derivedAddr = _deriveAddrFromBindingLimbs(sig);
// if (derivedAddr != identityWallets[fingerprint]) revert WalletDerivationMismatch();
```

**Why I'm WITHDRAWING this recommendation** (codex round-3 [P1] caught it correctly):

The proposed gate would force the rotation proof's binding pk to match the originally-registered (old) wallet. That **breaks a legitimate rotation pattern** the V5.1 design intentionally supports:

- User registered originally with QES C₁ → binding B₁ → wallet W_old. State: `identityWallets[fp] = W_old`.
- User obtains a fresh QES C₂ for the same identity (same `subjectSerial`), with binding B₂ where B₂.pk = W_new (their new wallet).
- User submits rotation proof using binding B₂. Proof attests:
  - rotationOldCommitment = Poseidon₂(subjectPack, oldWalletSecret) — proves knowledge of the old wallet's secret.
  - identityCommitment = Poseidon₂(subjectPack, newWalletSecret) — commits the new wallet's binding.
  - bindingPk = W_new (from B₂).
- Contract checks: rotation auth sig from oldWallet ✓ (user controls W_old's privkey + signs the auth payload); newWallet == msg.sender == W_new ✓.

If the contract additionally enforced `derivedAddr (= W_new) == identityWallets[fp] (= W_old)`, this legitimate "rotate-with-fresh-QES" flow would revert. **This is intentional V5 flexibility**: a user who lost access to their original binding's wallet pk (but still controls the privkey, e.g., key compromise + recovery from backup) can obtain a fresh QES bound to a fresh wallet pk and rotate to it.

V5.1 does NOT enforce this gate (the circuit's keccak constrains msgSender = keccak(bindingPk), but the contract doesn't tie msgSender to identityWallets[fp] under rotate mode). V5.2 should preserve this flexibility — i.e., do NOT add the proposed gate.

**Final recommendation: do NOT add the rotateWallet derivation gate.** The spec's "no change to rotateWallet" position is correct on both soundness AND flexibility grounds.

The genuine bookkeeping V5.2 must do for rotateWallet:
- `_packPublicSignalsV52` for the 22-element verifier input (versus V5.1's 19) — same shape as register's pack helper, just consumed by a different entrypoint.
- The `bindingPkX/Y` slots in the rotateWallet proof carry the binding's pk (whichever binding the prover chose to use); contract just packs them into the verifier input. No on-chain interpretation needed.

### §3.3 — Length validation on the 4 pk-limbs

Each `bindingPkX/Y` limb is a `uint256` in calldata. Circuits-eng's circuit constrains each via `Bits2Num(128)` to [0, 2^128). The contract's `uint128(sig.bindingPkXHi)` cast truncates the upper 128 bits — defense-in-depth against a malicious witness builder supplying a value with high bits set. Even without the cast, the prover would fail to produce a valid proof for a value > 2^128 because the circuit's Bits2Num constraint would fail. So:

- **In-circuit gate (Bits2Num)**: ensures the prover witnesses values in [0, 2^128). Required for proof validity.
- **Contract cast (uint128)**: passively truncates to low 128 bits if a value somehow leaks through. Defensive.

Both gates active is the safe posture. The contract's cast is essentially free (~10 gas per limb).

### §3.4 — Frontrunning + replay (unchanged from V5.1)

V5.2 doesn't introduce new MEV vectors. Same protection as V5.1: per-chain state (per-chain replay protection), `MAX_BINDING_AGE = 1 hours` window, first-claim discriminator (`identityWallets[fp] == address(0)`), rotation auth payload binding to chainid + registry address.

### §3.5 — Cert-chain unchanged

V5.2 does NOT touch leafSpki, intSpki, signedAttrs, or any of V5's P-256 ECDSA verification. The leaf cert chain is BindingParse → signedAttrs → leafSpki + intSpki → 2× P256Verify → trustedListRoot. All V5.1 gates persist verbatim.

---

## §4 — ABI propagation across packages

### §4.1 — `@qkb/contracts` (this package)

| Component | Change |
|-----------|--------|
| `QKBRegistryV5_2.sol` | New contract (fresh deploy; same `IQKBRegistry` interface). |
| `IGroth16VerifierV5_2.sol` | New interface: `verifyProof(uint[2], uint[2][2], uint[2], uint[22] calldata) returns (bool)` |
| `Groth16VerifierV5_2Stub.sol` | snarkjs-generated against V5.2 stub ceremony; **23 IC points** in vk (`IC0` constant term + `IC1..IC22` per public signal — N+1 always). |
| `Groth16VerifierV5_2Placeholder.sol` | accept-all stub for synthetic unit tests (mirrors V5.1's placeholder pattern; cf. V5.1 commit `04b4a71`). |
| `PublicSignals` struct | 22 fields: drop `msgSender`; add `bindingPkXHi/Lo, bindingPkYHi/Lo`. |
| `_packPublicSignals` helper | renamed `_packPublicSignalsV52`, returns `uint256[22]`. Field-by-field assignment per V5.1 Yul-stack lesson. |
| `register()` selector | **Changes** — Solidity ABI selectors hash the canonical function signature including the tuple form of struct parameters, so adding/removing PublicSignals fields shifts the selector. Acceptable since V5.2 is a fresh deploy with no existing on-chain integrations to preserve; downstream SDK regenerates. |
| `rotateWallet()` selector | **Changes** — same reason. |
| `IQKBRegistry` | Unchanged. `nullifierOf`, `isVerified`, etc., persist. |
| `IdentityEscrowNFT.sol` | Source unchanged. **NB**: a deployed NFT instance has its `registry` address as an immutable; pointing it at a fresh V5.2 registry deploy requires deploying a fresh NFT instance bound to the V5.2 registry. For our case this is moot — V5.1 has zero deployed registries (per spec §"Goals" item 4), so V5.2's "fresh deploy" includes a fresh NFT deploy too, with no pre-existing instances stranded. Document this in `DeployV5_2.s.sol`'s preamble. |
| Test fixtures `fixtures/v52/groth16-real/` | New directory; circuits-eng pumps fixtures here per V5.1 pump pattern (commit `04b4a71`). |
| Errors | Add `WalletDerivationMismatch`, `WrongRegisterModeNoOp`. Drop `BadSender` (folded into `WalletDerivationMismatch`). |

### §4.2 — Cross-package pumps

| Direction | Artifact | Notes |
|-----------|----------|-------|
| circuits-eng → contracts-eng | `Groth16VerifierV5_2Stub.sol` + V5.2 sample fixtures | Same pump pattern as V5.1 commit `04b4a71`. |
| contracts-eng → web-eng | New `QKBRegistryV5_2.ts` ABI | Bump `@qkb/sdk` 0.5.1-pre → 0.5.2-pre; bump `@qkb/contracts-sdk`. |
| circuits-eng → web-eng | V5.2 zkey + verification_key.json (post stub ceremony) | Witness builder drops `msgSender` input, adds bindingPkX/Y limbs. |

### §4.3 — Yul stack pressure forecast

V5.1 hit Yul stack-too-deep in two places (per V5.1 commit `04b4a71` history):

1. **`Groth16VerifierV5_1Stub.sol`'s `verifyProof`** at uint[19]: fixed via `assembly("memory-safe")` annotation.
2. **`RealTupleGasSnapshot.t.sol`'s `_publicSignalsStruct`** with 19-field struct literal: fixed via field-by-field `sig.X = pubInputs[N]` assignment.

V5.2's uint[22] verifier will hit the same issue. The same `assembly("memory-safe")` annotation will resolve it (snarkjs auto-generated verifiers are memory-safe). Test-side struct construction MUST use field-by-field assignment from the start. Both lessons are documented in V5.1's commit message; preserve them in V5.2's first commit.

---

## §5 — Cross-chain framing — concur with circuits-eng's bounded claim

Circuits-eng's spec §"Cross-chain portability claim — bounded" + §"Soundness — non-EVM chains require additional design" is **correct and well-bounded**. The framing of "Groth16 zkey verification portability" (all BN254-Groth16 chains) vs "end-to-end deployment portability" (EVM-family + EIP-7212 P-256 only) cleanly separates the two claims.

I add **one supplementary clarification** for the contract review:

The V5.2 amendment removes ONE chain-specific assumption from the circuit: Ethereum's keccak-based address derivation. The V5 architecture has TWO other chain-binding constraints that V5.2 does NOT address:

1. **P-256 precompile dependency (RIP-7212 / EIP-7951)**: V5.2 still needs P256VERIFY at `0x100` for the leaf + intermediate cert ECDSA verification (Gate 2b). Confirmed available per the V5/V5.1 deployment posture: **Base mainnet/Sepolia + Optimism mainnet/Sepolia** via RIP-7212 (verified empirically per V5 §2 reachability investigation; see `P256Verify.sol:37-41`). Ethereum mainnet support is in flight via EIP-7951 (post-Pectra rollout) but the V5.1 codebase doesn't yet probe it. Other EVM-family chains and non-EVM chains lacking native P-256 would require a from-scratch on-chain P-256 verification design (not just a fallback toggle in the existing library) — significant gas + audit surface, effectively a separate amendment.
2. **BN254 pairing precompile**: standard on EVM-family; varies by Move/Cosmos chain.

So the "V5.2 zkey is portable" claim is correct for chains with all FOUR primitives in place: (a) Groth16-on-BN254 pairing, (b) keccak-256, (c) **P-256 ECDSA precompile (RIP-7212 / EIP-7951 family)** for the leaf + intermediate cert verification, and (d) EVM-style secp256k1+keccak caller-auth model. Circuits-eng's deployment-feasibility table at §"Practical scope of cross-chain today" captures this; concur. The four-primitive set above (NOT just keccak) is what bounds V5.2's deployable surface today; precompile availability per chain is the gating concern, not the V5.2 amendment itself.

---

## §6 — Open questions answered

Circuits-eng's spec §"Open questions for contracts-eng review" lists 6 questions. My answers:

### Q1 — Option A vs Option B for the wallet-pk public-signal shape

**Strong endorse Option A.** Concrete numbers:

- **Option A** (4 × 128-bit limbs in public signals): +96 bytes calldata per `register()` (4 × 32 bytes for the new public-signal slots; 4 × 32 because each public signal is encoded as full uint256 in the verifier's calldata). Contract-side reconstruct + keccak: ~250 gas total.
- **Option B** (bindingBytes calldata + in-Yul JSON parse): +200-1000 bytes calldata (binding payload size); contract-side JSON parsing in Yul or Solidity is **gas-expensive** (string ops dominate; a typical JSON parse for a 500-byte payload is ~10K-30K gas) and **audit-disastrous** (parser correctness, escape handling, edge-case fields). Plus the contract would need to verify `sha256(bindingBytes) == sig.bindingHashHi/Lo` as a precondition, adding ~200 more gas.

Option A wins decisively: **+96 bytes calldata + 250 gas** vs **+~600 bytes calldata + ~15K gas + new parser audit surface**. No contest.

### Q2 — Public-signal layout reshuffle vs hard-zero placeholder at slot 0

**Endorse the clean reshuffle** (V5.1 slots 1-18 shift to V5.2 slots 0-17; new pk-limbs at 18-21).

Reasons:
- V5.1 has zero deployed registries; the cross-version diff is a developer tool issue, not a migration cost.
- A hard-zero placeholder at slot 0 wastes 32 bytes of calldata per `register()` call forever. Zero calldata bytes are 4 gas each — that's a fixed **128 gas per call** wasted, plus visible "what is this zero" confusion in audit / explorer traces.
- Audit clarity favors absence over hard-coded sentinels. A reviewer reading `Groth16VerifierV5_2.sol` and seeing 22 IC slots maps cleanly to 22 public signals; seeing 23 IC slots with `IC[0] = unconstrained-zero-ic-coefficient` is a confusing artifact.

The reshuffle is a one-time cost; the calldata + audit-clarity win is forever.

### Q3 — Rotation no-op gate move

**Confirm: contract can enforce.** Single-line gate inside `register()`:

```solidity
if (sig.rotationNewWallet != uint256(uint160(msg.sender))) revert WrongRegisterModeNoOp();
```

`ForceEqualIfEnabled` is just `enabled * (a - b) === 0`, which under register mode (rotationMode == 0, enabled = 1) becomes `a === b`. The Solidity `if` + `revert` is exactly equivalent for the on-chain semantics.

**No analogous gate is needed in `rotateWallet()`.** Earlier draft proposed a `derivedAddr == identityWallets[fp]` gate; withdrawn after codex round-3 [P1] correctly identified that it would break the legitimate "rotate-with-fresh-QES" flow. See §3.2 for the withdrawal rationale.

### Q4 — Constraint count empirical

Out of contract scope; defer to circuits-eng's measurement during T1 of implementation. If actual savings come in <80K and pot22 doesn't fit, the V5.2 work splits into "keccak move only (still pot23)" + "constraint reduction (pot22)" — those become two amendments.

### Q5 — Hermez pot22 sha256 pin

Out of contract scope; defer to fly-eng + circuits-eng coordination. Will be referenced in `stub-v5_2.sh` once pinned.

### Q6 — A6.4 browser-bench follow-up gating

Out of contract scope. If V5.2 zkey lands at ~2.02 GB and Chrome can't load it, that's a web-eng concern, not contract. Recommend the gate be: "stub ceremony lands → A6.4 retest with V5.2 zkey on Chrome → ship V5.2 if pass, hold on Firefox-only if fail." This is independent of whether V5.2's contract changes are good (they are).

---

## §7 — Implementation sketch (post-user-review gate)

Estimating ~1 day implementation:

1. **T1**: New contract `QKBRegistryV5_2.sol` — fork from `QKBRegistryV5.sol`. Drop `BadSender` error, drop `sig.msgSender` field from PublicSignals struct (becomes 22 fields total: 18 V5.1-minus-msgSender + 4 new pk limbs), add `WalletDerivationMismatch` + `WrongRegisterModeNoOp` errors. Add `_deriveAddrFromBindingLimbs` helper. Add Gate 2a-prime sender bind + register-mode no-op. Update `register()` and `rotateWallet()` per §2.
2. **T2**: New `IGroth16VerifierV5_2` interface (uint[22]). Update placeholder + (when pumped) stub.
3. **T3**: Update `_packPublicSignalsV52` for 22-slot layout (per §2.3). Field-by-field assignment per V5.1 Yul lesson.
4. **T4**: New `DeployV5_2.s.sol` (fresh deploy script; no upgrade).
5. **T5**: Adapt 4 unit-test files + `RealTupleGasSnapshot.t.sol` + `DeployV5.fork.t.sol` (Yul stack: field-by-field struct construction in tests).
6. **T6**: Annotate `Groth16VerifierV5_2Stub.sol` with `assembly("memory-safe")` (V5.1 lesson).
7. **T7**: Update `IQKBRegistry` docstring (no signature change; only versioning).
8. **T8**: Refresh forge snapshot. Document V5.2 baseline gas vs V5.1's 2.10M.
9. **T9**: Codex review + commit (single commit, VERDICT footer per V5.1 daemon-corruption protocol).

Cross-worker pumps:
- **Receive (T2)**: `Groth16VerifierV5_2Stub.sol` from circuits-eng (post stub ceremony).
- **Receive (T5)**: V5.2 sample fixtures `fixtures/v52/groth16-real/{proof,public,witness-input}-sample.json` from circuits-eng.
- **Produce (T2)**: New `QKBRegistryV5_2.ts` ABI for `@qkb/sdk`. Bump sdk version to 0.5.2-pre.

---

## §8 — Disagreements / surfacing

I have **one disagreement** with circuits-eng's spec, and it's small:

**No disagreements with the spec text.** An earlier draft of this review flagged a proposed `rotateWallet()` defense-in-depth gate (`derivedAddr == identityWallets[fp]`), but it was withdrawn after codex round-3 [P1] correctly identified that it would break the legitimate "rotate-with-fresh-QES" flow V5.1 intentionally supports (a user with a fresh QES bound to a fresh wallet can rotate; the binding pk doesn't have to match the originally-registered wallet). Spec §"Cost estimate" position on rotateWallet is correct as written. See §3.2 for the withdrawal rationale.

I have **one observation** circuits-eng's spec doesn't address explicitly:

**Yul stack pressure on `uint[22]`**: V5.1 hit Yul stack-too-deep on `uint[19]` (V5.1 commit `04b4a71`). V5.2's `uint[22]` will hit it harder. The same `assembly("memory-safe")` annotation on the snarkjs-generated verifier resolves it; the field-by-field struct-construction lesson applies to the test side. Document in V5.2's first contract commit so future re-spawns don't re-discover.

I have **zero structural concerns** with the construction. Option A is the right call. The on-chain keccak gate is straightforward (~200-250 gas). The rotation no-op gate move is a one-line revert. The 22-slot reshuffle is mechanical.

---

## §9 — Concerns dismissed

- **"What if Chrome can't load V5.2 zkey?"** — circuits-eng spec Q6 flagged; not a contract concern. Decoupled from V5.2's correctness on the contract side.
- **"Should we also drop the in-circuit P-256 leaf cert chain?"** — out of scope for V5.2 (separate amendment, separate ceremony if pursued). Spec §"Out of scope" correctly excludes this.
- **"Should rotateWallet take leafSpki as a parameter to enable contract-side P-256 verification?"** — no. Same scope-creep concern. V5.2 is a single-primitive amendment.
- **"Should we cache `bindingPkXHi/Lo, bindingPkYHi/Lo` in storage?"** — no. Even if a future amendment added a per-fp keccak gate, ~250 gas to recompute < >2K gas to SLOAD a cached value. Net loss in any plausible amendment.

---

## §10 — Codex review note

This document went through codex review (multiple rounds) before commit. Pre-V5.2-spec drafts hit several P1/P2 findings on speculative content; the present v0.4 is the post-circuits-eng-spec-read iteration with all findings resolved or acknowledged. Codex history available in commit message.

---

— contracts-eng v0.4 (post circuits-eng spec read), 2026-05-01
