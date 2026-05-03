# Keccak-On-Chain — V5.2 Cross-Chain Portability Amendment

> **Status:** Draft v0.5 — incorporates pot22 size correction (4.83 GB empirical, NOT 600 MB as v0.1–v0.4 claimed) + sha256 pin from T3 implementation. Pending user-review gate, then T3 stub ceremony lands + Phase B planning.
>
> **Date:** 2026-05-01.
>
> **Amends:** §6.8 of `2026-04-29-v5-architecture-design.md` ("Secp256k1PkMatch + Keccak256 → msgSender bind"). **Partially amends** the V5.1 wallet-bound nullifier amendment (`2026-04-30-wallet-bound-nullifier-amendment.md`): the nullifier construction (`Poseidon₂(walletSecret, ctxHash)`) and rotate-mode soundness gate (`rotationOldCommitment === Poseidon₂(subjectSerialPacked, oldWalletSecret)`) are unchanged, but **the V5.1 register-mode no-op gate `rotationNewWallet === msgSender` moves from circuit to contract** (because msgSender is no longer circuit-emitted in V5.2). V5.2 is otherwise scoped to WHERE the wallet-pubkey-to-msg.sender keccak gate fires.
>
> **Sequencing:** Lands BEFORE Phase B (§11) ceremony kickoff. Phase B is currently gated on user contributor recruitment; that recruitment defers by the V5.2 implementation window (~3-5 days end-to-end).
>
> **Owner:** circuits-eng (drafter); contracts-eng (independent contract review at `docs/superpowers/specs/2026-05-01-keccak-on-chain-contract-review.md` — to be written during this design pass).
>
> **Branch:** `feat/v5_2arch-circuits` (cut from `main` @ `024b62b`).
>
> **Revision history:**
> - v0.1 (2026-05-01 ~13:00 UTC): initial draft.
> - v0.2 (2026-05-01 ~14:00 UTC): codex pass 1 corrections (4 findings, all legit):
>   (1) **Public-signal declarations**: spec now uses `signal input` (not `signal output`) for the new bindingPk fields, matching V5.1's existing pattern of pinning all public-signal slots via internal equality constraints — required because snarkjs emits `[outputs..., public_inputs...]` and the V5/V5.1 layout is fully `signal input` to control ordering.
>   (2) **Cross-chain portability claim narrowed**: the keccak-on-chain equivalence only holds for chains using Ethereum-style address derivation (`address = keccak256(uncompressedPk[1..65])[12..32]`). Solana, Cosmos, Aptos, Sui all use different caller-auth schemes (ed25519 / blake2b / native account models); V5.2 unlocks the ZKEY VERIFICATION PORTABILITY but each non-EVM port requires a separate caller-auth design. Reframed as "EVM-family portability" + "open question for non-EVM ports".
>   (3) **Rotation-gate amendment scope**: header now correctly says V5.2 amends V5.1's register-mode no-op rotation gate (it moves on-chain) while NOT amending the rotate-mode soundness gate. §"Construction delta" + §"Cost estimate" reconciled.
>   (4) **SEC1 prefix check retention**: the V5.1 `Secp256k1PkMatch.circom` check `pkBytes[0] === 0x04` is preserved in V5.2 as a cheap (~3 constraint) standalone assertion outside the dropped primitive, not silently lost.
> - v0.3 (2026-05-01 ~14:30 UTC): codex pass 2 corrections (1 P2 finding on cross-chain narrowing not fully propagated to Goal 1, Goal 3, Open Question 6) + codex pass 3 corrections (3 findings: zkey-size estimate inconsistency, redundant `[12..32]` slice on `address(uint160(uint256(keccak256(...))))` formula, stale `v0.1` labels in body):
>   (1) Goal 1 + Goal 3 reframed to distinguish "Groth16 zkey verification portability" (all Groth16+BN254 chains) from "end-to-end deployment portability" (EVM-family only without auth-shim work). EVM equivalence proof bounded explicitly.
>   (2) Open Question 6 (browser bench follow-up) updated: V5.2 zkey size estimated at ~2.02 GB (using -200K constraint estimate); -100K conservative case yields ~2.07 GB; both within ±50 MB of V8 cap; Chrome viability genuinely uncertain pre-measurement; Firefox A6.4 empirical (93s wall, ~20 GB RAM, end-to-end success on V5.1) noted.
>   (3) EVM soundness formula consolidated to `address(uint160(uint256(keccak256(uncompressedPk)))) == msg.sender` (Solidity's `uint160` cast naturally takes the low 160 bits) — the redundant `[12..32]` slice removed.
>   (4) Stale `v0.1` labels in §Construction body and §End-of-spec marker updated.
> - v0.4 (2026-05-01 ~16:00 UTC): contracts-eng v0.4 independent review (substantively endorses Option A + clean slot reshuffle + -200K constraint claim after Secp256k1PkMatch.circom:1-65 read-through; finds 2 substantive items I missed):
>   (1) **§3.2 rotateWallet defense-in-depth (P2)**: V5.1's in-circuit keccak implicitly bound the binding's pk to the OLD wallet (msgSender) under rotate mode. V5.2 drops that. The auth sig from oldWallet (already enforced contract-side via the typed-message scheme) is load-bearing, so this is technically unchanged — but losing defense-in-depth is real. Contracts-eng recommends adding `derivedAddr == identityWallets[fp]` check inside `rotateWallet()` after the contract reconstructs the address from `bindingPkX/Y` limbs (~150 gas, single line). Spec now folds this into §"Construction delta — Contract changes" + §"Cost estimate".
>   (2) **§5 cross-chain clarification (informational)**: P-256 verification (RIP-7212 / EIP-7951) is the OTHER EVM-portability dependency beyond keccak — V5.2 removes 1 of 3 chain-portability assumptions (keccak), NOT 1 of 1. The other two remain (Groth16-on-BN254 verifier; P-256 ECDSA primitive for the leaf-cert signature in §6.8 of the V5 architecture). Spec's cross-chain table now annotates this explicitly. Post-Pectra status: P-256 is on mainnet, Base, OP; **NOT yet on Arbitrum or Polygon zkEVM** (corrected from v0.3's "partial on zkEVM"). Spec's table updated.
>   Plus contracts-eng's v0.4 endorsements (informational — fold into implementation phase): Option A (4 × 128-bit Hi/Lo limbs) over Option B unconditional; clean V5.1 → V5.2 slot reshuffle (vs hard-zero placeholder at slot 0); Yul stack pressure forecast — same fix pattern as V5.1's commit `04b4a71` (verifier-side public-input array unpacking; mention in implementation T2 commit message).
> - v0.5 (2026-05-03 ~10:00 UTC): pot22 size correction during T3 implementation. circuits-eng (running T3 stub ceremony) HEAD-requested the canonical Polygon zkEVM mirror and discovered pot22 is **4.83 GB** (4,831,921,304 bytes), NOT ~600 MB as v0.1–v0.4 claimed (the source of the wrong number was likely confusion with a "lite" or compressed ptau format that Hermez does not publish). Implications:
>   (a) §"pot22 vs pot23" rewritten with the empirical size + Phase B contributor download savings recalc: **4.6 GB savings** vs pot23 (NOT 8.5 GB as advertised). EU broadband download time pot22 ~30-90 min (NOT 5-15 min).
>   (b) Open Question #5 (sha256 pin) PARTIALLY ANSWERED: T3 measured + pinned `68a21bef870d5d4a9de39c8f35ebcf04e18ef97e14b2cd3f4c3e39876821d362` for the stub ceremony, first-trust-on-use. Phase B ceremony still needs cross-validation against an independent Hermez manifest source before production dispatch.
>   (c) The cross-chain portability win (the LOAD-BEARING reason for V5.2) is independent of pot file size — unaffected. Phase B contributor recruitment remains plausible at the corrected 4.6 GB savings.
>   (d) Same drift affected the broader docs (V5 design doc lines 411/413/533, Fly cookbook entrypoint.sh:69); lead handles those post-T3 in a separate sweep.

## Motivation — chain-binding the V5.1 design accidentally inherits

Today's V5 main circuit (post-§6.8 amendment) computes `msgSender` in-circuit via:

```
msgSender = keccak256(parser.pkBytes[1..65])[12..32]
```

where `parser.pkBytes[1..65]` is the user's 64-byte uncompressed secp256k1 wallet pubkey (extracted from the binding's `pk` field), and the keccak runs through the vendored `bkomuves/hash-circuits` Keccak-256 template (§V5.6).

This pins the proof to **Ethereum's address derivation function**: `keccak256(pk)[12:32]`. The choice of keccak (vs. blake2b, sha3-256, hash-to-curve, …) is an **EVM-specific** convention — Solana addresses are SHA-256/ed25519 paths, Cosmos uses bech32 with various inner hashes, Aptos/Sui use blake2b-256, etc.

By computing keccak in-circuit, the V5.1 zkey is effectively single-target: it can be verified on any Groth16-supporting chain, but the `msgSender` semantics it enforces only match Ethereum's address rule. A Cosmos contract verifying the V5.1 proof would still need to cross-validate that its own native address matches a keccak-derived Ethereum-style address — adding logic, gas, and an awkward dual-derivation footprint.

**The fix is structural**: move the keccak gate OUT of the circuit and INTO the host chain's contract layer. Each chain enforces its own native address derivation against the same circuit-emitted secp256k1 pubkey commitment. The zkey becomes chain-portable.

## Goals

A construction that satisfies all of:

1. **Groth16 zkey portable across all Groth16-on-BN254 chains.** The same `verification_key.json` + `*.zkey` verifies on Ethereum, Solana (via Light Protocol Groth16 verifier or similar), Cosmos (cosmwasm Groth16), Aptos / Sui (Move Groth16 libs), without circuit recompile. **Note**: zkey verification portability ≠ end-to-end deployment portability. Non-EVM chains require a chain-specific caller-auth shim (see §"Cross-chain portability claim — bounded" + §"Soundness — non-EVM chains"); EVM-family chains (Ethereum mainnet + OP-stack rollups + zk-rollups with EIP-7212 P256) get the full V5.2 deployment with no extra design.
2. **Constraint count strictly reduced** vs V5.1 (4,022,171). Target: under pot22's 2^22 = 4,194,304 capacity with ≥4% headroom; concretely, ≤4,025,000 constraints leaves zero headroom on pot22, so the win must be substantive (≥80K constraints removed).
3. **Soundness equivalent** to V5.1 ON EVM CHAINS: a Solidity contract enforcing `address(uint160(uint256(keccak256(uncompressedPk)))) == msg.sender` (Solidity's `uint160` cast naturally takes the low 160 bits, matching the keccak-digest [12..32] slice) against the circuit-emitted wallet-pk commitment is provably equivalent to V5.1's in-circuit keccak-to-msgSender chain. Non-EVM chains break the equivalence proof (different caller-auth model) and need a per-chain auth-shim design before V5.2 deploys there.
4. **No deployed-registry migration cost**: V5.1 has zero on-chain Sepolia/Mainnet deployments today (per Phase B gating); V5.2 supersedes V5.1 cleanly with a fresh stub ceremony + tag bump.

## Threat model — explicit

Same in/out-of-scope adversaries as V5.1 (see §"Threat model" in the wallet-bound nullifier amendment). The keccak-on-chain change does NOT introduce new adversary classes; it relocates ONE gate's enforcement layer.

**Critical additional consideration**: the security claim that "circuit + contract together enforce wallet-pk-to-msg.sender binding" now distributes across two trust boundaries (circuit prover + contract executor). This is **identical to the V5 status quo** for every other gate the contract layer enforces — five gates in V5's `register()` already verify cert chains, signedAttrs hashes, leaf P-256 sigs, Merkle proofs, and policy roots, all on-chain. Adding a keccak gate to the same `register()` is a strict subset of the V5 trust model, not an expansion.

**Specifically NOT compromised:**
- Cert authenticity (still circuit-enforced via signedAttrs SHA-256 + leaf P-256 sig).
- Wallet-secret privacy (V5.1's `walletSecret` is a private input; V5.2 doesn't expose it).
- Anti-Sybil (V5.1's `nullifierOf` + `usedCtx` mappings unchanged).
- Identity-fingerprint commitment (V5.1's `identityFingerprint` public signal unchanged).

## Construction delta vs V5.1

### Circuit changes (`packages/circuits/circuits/QKBPresentationV5.circom`)

**Drop** (§6.8 main primitives, ~200K constraints):

- `Secp256k1PkMatch` — bound `parser.pkBytes` (the binding's claimed wallet pubkey, 65 bytes including SEC1 0x04 prefix) to witness limbs `pkX[4]`, `pkY[4]`. ~50K constraints (limb pack + range checks).
- `Secp256k1AddressDerive` — Keccak-256 over `parser.pkBytes[1..65]` (the 64 raw uncompressed pubkey bytes) → low 160 bits packed as `msgSender` field. ~150K constraints (Keccak_256_bytes(64) single-absorb-block).
- The `pkAddr.addr === msgSender` equality assertion.

**Retain** (cheap standalone check, ~3 constraints):

- `parser.pkBytes[0] === 0x04` SEC1-uncompressed-prefix assertion. Currently lives inside `Secp256k1PkMatch.circom`; in V5.2 it's a single `signal === const` line at the top of the §6.8 block. Without this, a malicious witness could supply `pkBytes` with a non-`0x04` prefix and the contract's keccak-over-bytes-1..65 would still bind correctly — but the BindingParseFull's range check on each pkBytes element only constrains 0..255, so dropping this would let `parser.pkBytes[0]` take any byte value. Cheap to keep; flagged by codex pass 1 §4 as a real (if minor) relaxation otherwise.

**Drop** from `component main { public [...] }`:

- `msgSender` (slot 0 in V5.1) — no longer circuit-emitted. Public-signal layout shrinks by 1.

**Add** to `component main { public [...] }` (one of the two options below):

#### Option A — emit packed wallet-pk limbs (RECOMMENDED, contracts-eng review pending)

Add 4 new public signals carrying the binding's claimed wallet pubkey, declared as `signal input` (NOT `signal output`) to match V5/V5.1's public-signal-ordering convention. snarkjs orders public signals as `[outputs..., public_inputs...]`; V5/V5.1 use `signal input` for every public slot and pin each via internal equality constraints (e.g., V5.1's `leafSpkiCommit` is a `signal input` constrained to equal `Poseidon₂(Poseidon₆(leafXLimbs), Poseidon₆(leafYLimbs))`). V5.2 follows the same pattern:

```circom
signal input bindingPkXHi;   // upper 128 bits of parser.pkBytes[1..33]
signal input bindingPkXLo;   // lower 128 bits of parser.pkBytes[1..33]
signal input bindingPkYHi;   // upper 128 bits of parser.pkBytes[33..65]
signal input bindingPkYLo;   // lower 128 bits of parser.pkBytes[33..65]
```

Each holds 128 bits, fitting the BN254 ~254-bit field with a generous margin. The 128-bit split avoids the 256-bit-vs-254-bit issue that would arise from packing pkX whole into one field.

These four signals are **constrained to equal the corresponding 16-byte slices of `parser.pkBytes`** via in-circuit `Bits2Num` packing — no new range checks beyond what `BindingParseFull` already enforces (each pkBytes element is already constrained to a byte by the parser). The packing is straightforward:

```circom
// pkXHi = sum_{i=0..15}  parser.pkBytes[i+1]  * 256^(15-i)
// pkXLo = sum_{i=16..31} parser.pkBytes[i+1]  * 256^(31-i)
// pkYHi = sum_{i=0..15}  parser.pkBytes[i+33] * 256^(15-i)
// pkYLo = sum_{i=16..31} parser.pkBytes[i+33] * 256^(31-i)
// (hi = leftmost 16 bytes, lo = rightmost 16 bytes — big-endian convention
//  matching Ethereum's natural pk serialization)
component xHiPack = Bits2Num(128); // ... (sketch — full impl in T2)
xHiPack.out === bindingPkXHi;
// (similar for xLo, yHi, yLo)
```

The `signal input` declaration matters: it's what places these slots in the snarkjs public-signals array AT THE END, after the existing 18 V5.1-public-input slots (post-msgSender-removal).

**Rotation gate retention**: V5.1's rotation-mode gates currently reference `msgSender` on slot 0:
```
register mode: rotationOldCommitment === identityCommitment
register mode: rotationNewWallet      === msgSender         ← references public signal
rotate mode:   rotationOldCommitment === Poseidon₂(subjectSerialPacked, oldWalletSecret)
```

In V5.2, `msgSender` is no longer a circuit-emitted public signal. Two clean options:

(i) **Move the register-mode `rotationNewWallet === msgSender` no-op to contract-side**. Contract derives msgSender from `bindingPkX/Y` via host-native keccak, then enforces the rotation no-op equality. Circuit drops the no-op.

(ii) **Keep `msgSender` as a circuit *private* input**, equality-constrained to `bindingPkX/Y` packed into a 160-bit address via... no, that requires keccak in-circuit again. Doesn't work without keccak.

Therefore (i) is the only viable option. The contract layer gains:
```solidity
require(
  uint256(uint160(uint256(keccak256(uncompressedPk)))) == sig.rotationNewWallet,
  "rotationNewWallet ≠ msg.sender (register mode no-op)"
);
```

(For rotate mode, contract enforces `sig.rotationNewWallet == msg.sender` directly; circuit's open-gate on `rotationOldCommitment === Poseidon₂(subjectPack, oldWalletSecret)` is unchanged.)

**Net public-signal count**:

V5.1: 19 signals.
V5.2 Option A: 19 - 1 (msgSender) + 4 (pkXHi/Lo, pkYHi/Lo) = **22 signals**.

This is a slight INCREASE in calldata footprint (~3 × 32 = 96 bytes more per `register()` call) but a SHARP DECREASE in circuit constraints. Contracts-eng should weigh the trade-off in their review.

#### Option B — pass bindingBytes as register() calldata, contract parses (alternative)

Skip the new public signals entirely. Add `bytes calldata bindingBytes` to `register()`'s ABI. Contract:

1. Verifies `sha256(bindingBytes) == (sig.bindingHashHi << 128) | sig.bindingHashLo` (pre-existing public signal).
2. Parses bindingBytes JSON to extract the `pk` field (65-byte hex string).
3. Decodes the 64-byte uncompressed pubkey.
4. Computes `keccak256(pk[1..65])[12..32] == msg.sender` (register mode) or `== sig.rotationNewWallet` (rotate mode).

**Pros**: Public-signal layout shrinks to 18 (V5.1's 19 minus msgSender). No new circuit-emitted signals.

**Cons**: ABI breaking change to `register()`; calldata grows by ~bindingBytes size (~200-1000 bytes); EVM JSON parsing is gas-expensive (string ops); contract-side parser is a new audit surface.

**Recommendation**: Option A. Cheaper gas, smaller audit surface, no JSON-in-EVM. Defer final choice to contracts-eng review.

### Public-signal layout V5.1 → V5.2 (Option A — recommended)

| Slot | V5.1 | V5.2 (Option A) | Note |
|---|---|---|---|
| 0  | `msgSender` | `timestamp` | V5.2 shifts everything down by 1 (msgSender removed) |
| 1  | `timestamp` | `nullifier` | (V5.1 nullifier was slot 2, becomes slot 1) |
| 2  | `nullifier` | `ctxHashHi` | |
| 3  | `ctxHashHi` | `ctxHashLo` | |
| 4  | `ctxHashLo` | `bindingHashHi` | |
| 5  | `bindingHashHi` | `bindingHashLo` | |
| 6  | `bindingHashLo` | `signedAttrsHashHi` | |
| 7  | `signedAttrsHashHi` | `signedAttrsHashLo` | |
| 8  | `signedAttrsHashLo` | `leafTbsHashHi` | |
| 9  | `leafTbsHashHi` | `leafTbsHashLo` | |
| 10 | `leafTbsHashLo` | `policyLeafHash` | |
| 11 | `policyLeafHash` | `leafSpkiCommit` | |
| 12 | `leafSpkiCommit` | `intSpkiCommit` | |
| 13 | `intSpkiCommit` | `identityFingerprint` | (V5.1 slot 14) |
| 14 | `identityFingerprint` | `identityCommitment` | (V5.1 slot 15) |
| 15 | `identityCommitment` | `rotationMode` | (V5.1 slot 16) |
| 16 | `rotationMode` | `rotationOldCommitment` | (V5.1 slot 17) |
| 17 | `rotationOldCommitment` | `rotationNewWallet` | (V5.1 slot 18) |
| 18 | `rotationNewWallet` | **`bindingPkXHi`** | NEW |
| 19 |  | **`bindingPkXLo`** | NEW |
| 20 |  | **`bindingPkYHi`** | NEW |
| 21 |  | **`bindingPkYLo`** | NEW |

**Total: 22 public signals.**

**Frozen** per orchestration plan §1.1 — adding/reordering is a cross-worker breaking change. Contracts-eng's `Groth16VerifierV5_2.sol` and web-eng's `packages/sdk/fixtures/v5_2/verification_key.json` will both pin to this exact order.

The reshuffle (everything between slots 1-13 shifts down) is unfortunate but unavoidable given snarkjs's `[outputs..., public_inputs...]` ordering convention (the keccak removal removes msgSender from `output`s, freeing slot 0). All four new signals are appended at the end to preserve the V5.1 layout for slots 1-17 (post-shift).

**Alternative**: keep V5.1's slot order frozen and emit `bindingPkX/Y` at the end with a placeholder zero at slot 0 (where msgSender was). Cleaner cross-version diff but ugly artifact (a hard-coded zero in calldata). Contracts-eng's choice.

### Constraint envelope

**V5.1 empirical**: 4,022,171 constraints (post-A6.1, measured).

**V5.2 estimate**: ~3,820,000 constraints (V5.1 minus ~200K from §6.8 keccak removal, plus ~3K for the new `Bits2Num` packing of pkX/pkY into 4 fields). Lead's task brief estimated -100K (more conservative); the actual savings depend on whether the bigint range checks in Secp256k1PkMatch share with other primitives or were unique to this gate. **Empirical re-measurement is the first implementation step** — if the savings are <80K, pot22's headroom (~94%) drops below 4% and the amendment's pot-shrink claim is at risk.

**Cap**: 4,194,304 (pot22 capacity = 2^22).

**Headroom estimate**: 4,194,304 - 3,820,000 = 374,304 = ~9% — comfortable.

**Empirical floor**: 4,025,000 — leaves zero headroom; if measurement lands here, V5.2 must stay on pot23 (defeating one of the amendment's stated wins).

### pot22 vs pot23 (sizes corrected v0.5)

V5.1 ceremony uses pot23 (8.39M constraint capacity, **9.1 GB** transcript file). V5.2 fits pot22 (4.19M capacity, **4.83 GB** transcript file — empirically measured 2026-05-03 against the canonical Polygon zkEVM mirror; HTTP HEAD reported `content-length: 4831921304` bytes).

**v0.1–v0.4 misstatement corrected**: prior versions of this spec (and the A7 dispatch) claimed pot22 = "~600 MB" — that figure was wrong, likely conflated with a "lite" or compressed ptau format that Hermez does NOT publish. The Hermez pot22 transcript exists only in its full 4.83 GB form. Lead surfaced cross-doc drift the same source affected V5 design doc (`docs/superpowers/specs/2026-04-29-v5-architecture-design.md`) and the Fly cookbook (`scripts/ceremony-coord/cookbooks/fly/entrypoint.sh:69`); lead handles the broader sweep post-T3.

**Win**: **4.6 GB savings** on every Phase B contributor's download (9.1 GB pot23 → 4.83 GB pot22). Material but less dramatic than the originally-advertised 8.5 GB. On typical EU residential broadband (50-100 Mbps): pot23 takes ~75-150 min, pot22 takes ~30-90 min. Plus the zkey download (~2.0 GB for V5.2) which is ceremony-output, not pot-input.

**Hermez pot22 file**: `powersOfTau28_hez_final_22.ptau`, available from the Polygon zkEVM mirror at `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_22.ptau`. **sha256 pin (measured 2026-05-03 during T3 stub ceremony):**

```
68a21bef870d5d4a9de39c8f35ebcf04e18ef97e14b2cd3f4c3e39876821d362
```

This pin is **first-trust-on-use** as of 2026-05-03 — pinned against the downloaded file from the canonical Polygon zkEVM mirror, not yet against an independent Hermez announcement source. Phase B ceremony (real, multi-contributor) MUST cross-validate against the official Hermez ceremony manifest before dispatch — see Open Question #5 (now answered for the stub but pending for production).

## Soundness — keccak-on-chain ≡ keccak-in-circuit (on EVM-family chains)

The V5.1 §6.8 chain that V5.2 splits across the trust boundary:

```
parser.pkBytes (binding-attested wallet pubkey)
    ↓ Secp256k1PkMatch (in-circuit, V5.1)
pkX/pkY witness limbs
    ↓ Secp256k1AddressDerive (Keccak in-circuit, V5.1)
160-bit Ethereum address
    ↓ === msgSender public signal (V5.1)
    ↓ contract: msg.sender == sig.msgSender
msg.sender wallet identity (EVM-style)
```

V5.2 (EVM chains) splits this at the public-signal boundary:

```
parser.pkBytes (binding-attested wallet pubkey)
    ↓ Bits2Num packing (in-circuit, V5.2)
bindingPkX/Y public signals
    ↓ contract: address(uint160(uint256(keccak256(uncompressedPk))))
160-bit address (Ethereum native rule)
    ↓ contract: derived address == msg.sender
msg.sender wallet identity
```

**Equivalence proof sketch (EVM-family chains only)**:

1. The CIRCUIT's bind from `parser.pkBytes` to `bindingPkX/Y` is a deterministic byte-equality (Bits2Num is just a witness encoding of the same bits the parser already constrained). Same soundness as Secp256k1PkMatch's limb-bind, minus ~50K constraints.

2. The CONTRACT's bind from `bindingPkX/Y` to msg.sender via Solidity's `keccak256` is a deterministic hash evaluation. The keccak primitive is bitwise-identical between in-circuit (bkomuves vendored, MIT) and on-chain EVM (precompile-equivalent op `KECCAK256` per yellow paper) — both implement Keccak-f[1600] with the same padding rule.

3. Therefore on an EVM chain, the COMPOSITE CHAIN (circuit + EVM contract together) accepts EXACTLY the same set of (proof, msg.sender) pairs as V5.1's all-in-circuit chain.

**Critical scope narrowing — non-EVM chains require additional design**:

The above equivalence assumes the contract enforces `address(uint160(uint256(keccak256(uncompressedPk)))) == msg.sender` (Solidity's `uint160` cast naturally takes the low 160 bits, matching the keccak-digest [12..32] slice). This is the Ethereum/EVM caller-auth model — a transaction's sender is the keccak-derived address of an externally-owned secp256k1 keypair.

**Other chains have different caller-auth models**:

- **Solana**: caller is identified by an ed25519 keypair (`Pubkey` type, 32 bytes); secp256k1+keccak doesn't naturally apply. A V5.2 deployment on Solana would need to either (a) require users to ALSO sign with a secp256k1 wallet (e.g., via `secp256k1_recover` syscall + a second signature) or (b) redesign the wallet binding entirely (e.g., bind to ed25519 pk).
- **Cosmos / cosmwasm**: callers identified by bech32-encoded SHA-256 of secp256k1 (or ed25519) pks — different hash, different format. V5.2 on Cosmos would require a Cosmos-side adapter contract that maps the EVM-style secp256k1 pk to a Cosmos address via the host's RIPEMD160(SHA256(pk)) rule — possible but explicit work.
- **Aptos / Sui**: account models built on ed25519 by default; secp256k1 wallets are second-class citizens via ECDSA/ed25519 multi-signature schemes.

**Therefore the V5.2 cross-chain claim is**: the **Groth16 zkey is portable** (same verification key, same circuit). The **contract-side wallet-binding logic is NOT portable** — each non-EVM chain needs its own auth-shim that maps the circuit's `bindingPkX/Y` to the host's native caller identity.

In practice, EVM-family chains (mainnet, all OP-stack rollups, Polygon zkEVM, zkSync, Linea, BSC, Avalanche C-chain, etc.) — many of which are exactly where Identity Escrow's target audience lives today — get V5.2 portability for free. Non-EVM chains require additional design work scoped per chain.

**The only thing keccak-in-circuit gave that on-chain doesn't**: a malicious contract operator cannot bypass the wallet-pk binding. But the contract operator is what enforces `register()` semantics in V5 generally — they're the verifier, not the prover. If the operator is malicious, the entire registry is meaningless regardless of where the keccak fires. So this isn't a real loss of security.

## Cross-chain portability claim — bounded

V5.2 removes **1 of 3 EVM-portability assumptions** that V5.1 baked into the circuit (the in-circuit keccak gate). The other two — Groth16-on-BN254 verifier, and EIP-7212-style P-256 ECDSA verification — are NOT addressed by V5.2 and remain chain-portability gates in their own right. V5.2 is therefore a STEP TOWARD cross-chain portability, not a complete delivery.

V5.2 zkey deployable on any chain providing ALL of:

1. **Groth16 verifier on BN254**. Native or library: Ethereum (precompiles 0x06, 0x07, 0x08), Solana (Light Protocol's groth16-solana), Cosmos (cosmwasm-groth16 / `arkworks`-via-CosmWasm), Aptos (`aptos_std::groth16_algebra`), Sui (`sui::groth16`), Polygon zkEVM, zkSync, Linea (all EVM-equivalent).

2. **Keccak256 primitive in contract logic**. Native opcode (Ethereum) or syscall (Solana `keccak`, Aptos `aptos_hash`, Sui `hash`) or std-lib (Cosmos cosmwasm). **THIS is the assumption V5.2 unlocks** by moving the gate from circuit (where it was hard-coded) to contract (where it becomes opt-in per host chain).

3. **EIP-7212-style P256Verify or equivalent secp256r1 ECDSA primitive**. This is the OTHER chain-binding constraint inherited from V5 architecture (§6.8 leaf-cert ECDSA-P256 verification, separate from the wallet-pubkey gate). NOT addressed by V5.2. Post-Pectra status (corrected from v0.3 per contracts-eng v0.4 review): implemented on Ethereum mainnet, Base, Optimism (and other OP-stack chains where the precompile is included in the L1-sequenced opcodes); **NOT YET on Arbitrum, NOT YET on Polygon zkEVM** (v0.3 said "partial" for zkEVM and listed Arbitrum as ✓; both were inaccurate — see contracts-eng v0.4 §5). Solana has `secp256r1` syscall, Cosmos / Aptos / Sui need work for P256Verify-compatible primitives.

4. **EVM-style secp256k1+keccak caller-auth** (FOR EVM CHAINS ONLY). Non-EVM chains need a custom auth shim — see Soundness §"non-EVM chains require additional design".

**Practical scope of "cross-chain" today** (table corrected per contracts-eng v0.4 §5 review):

| Chain family | Groth16 | Keccak | P256 | secp256k1 caller-auth | V5.2 deployable? |
|---|---|---|---|---|---|
| Ethereum mainnet (post-Pectra) | ✓ precompile | ✓ opcode | ✓ | ✓ native | **YES** |
| Base, Optimism (OP-stack with P256 precompile) | ✓ | ✓ | ✓ | ✓ | **YES** |
| Arbitrum | ✓ | ✓ | **✗ not yet** | ✓ | **NO until P256 lands** |
| Polygon zkEVM | ✓ | ✓ | **✗ not yet** | ✓ | **NO until P256 lands** |
| zkSync / Linea / BSC / Avalanche-C | ✓ | ✓ | varies (check before deploy) | ✓ | conditional on P256 status |
| Solana | ✓ Light Protocol | ✓ syscall | ✓ secp256r1 syscall | ✗ ed25519 | needs auth shim |
| Cosmos / cosmwasm | ✓ | ✓ | needs work | ✗ bech32 | needs auth shim |
| Aptos / Sui | ✓ | ✓ | needs work | ✗ ed25519 | needs auth shim |

The **immediate, free win** is "EVM-family with P256 support" — currently mainnet + OP-stack + (some) zk-rollups. **The longer-term win** is the SHIPPING of a single circuit/zkey that any chain CAN port to with bounded auth-shim work, instead of compiling a fresh circuit per chain.

## Cost estimate (end-to-end)

| Worker | Scope | Estimate |
|---|---|---|
| circuits-eng | Drop §6.8 main primitives, retain SEC1 0x04 prefix check (~3 constraints), add 4-signal pkX/Y `signal input` packing with `Bits2Num` constraints, regenerate stub on pot22, re-run V5 §6.10 E2E suite | ~1.5 day |
| contracts-eng | Add keccak gate to `register()`: reconstruct 64-byte uncompressed pk from 4 public-signal limbs, `address(uint160(uint256(keccak256(pk)))) == msg.sender`. Add register-mode no-op gate `rotationNewWallet == msg.sender` (V5.1 had this in-circuit; V5.2 moves on-chain). Add `rotateWallet()` defense-in-depth check: after computing `derivedAddr` from `bindingPkX/Y` limbs, assert `derivedAddr == identityWallets[fp]` — closes the regression where V5.1's in-circuit keccak implicitly tied binding pk to OLD wallet under rotate mode. ~150 gas, single line per contracts-eng v0.4 review. The auth sig from oldWallet (via the typed-message scheme) remains the load-bearing rotate-mode check; this is defense-in-depth. Update Groth16VerifierV5_2Stub.sol's public-input array (22-element). Forecast: Yul stack-pressure on the 22-element verifier follows V5.1's commit `04b4a71` fix pattern (verifier-side public-input array unpacking). Gas snapshot. | ~1 day |
| web-eng | Drop keccak/pkBytes from witness builder; update `@qkb/sdk` v5_2 fixtures; update register() ABI | ~0.5 day |
| Integration | Cross-package E2E; new stub ceremony pump; update CI gates | ~1 day |
| **Total** | | **~3-5 days** |

## Out-of-scope (explicit list — prevent scope creep)

- DOB / age proof (V6+).
- SCW automated key recovery (V6+).
- Cross-chain implementation (this amendment ONLY enables it; actual Solana port / Cosmos port / Aptos port are separate workstreams).
- V5.1 → V5.2 migration for any deployed registries (none exist; tag `v0.5.2-pre-ceremony` from `v0.5.1-pre-ceremony`).
- Pan-eIDAS deduplication (carried forward from V5.1; ETSI namespacing unchanged).
- EIP-7212 P-256 portability (the OTHER chain-binding; flagged as future work).
- Browser proving feasibility re-measurement against V5.2 stub (separate dispatch — A6.4 re-fire, currently deferred).

## Open questions for contracts-eng review

These are flagged for the contract-review pass before user gate:

1. **Option A vs Option B for the wallet-pk public-signal shape**. Contracts-eng to measure gas of (a) reading 4 extra calldata fields + reconstructing pkX/pkY vs (b) parsing bindingBytes JSON. Recommend (a) sight-unseen but defer to gas-numbers.

2. **Public-signal layout reshuffle**: clean shift-down (recommended) vs hard-zero placeholder at slot 0. Contracts-eng's preference between calldata-clarity (zero placeholder) and audit-clarity (clean reshuffle).

3. **Rotation no-op gate move**: the V5.1 register-mode `rotationNewWallet === msgSender` gate must move to contract-side. Confirm the contract can enforce this without breaking the `ForceEqualIfEnabled` pattern that V5.1 used in-circuit.

4. **Constraint count empirical**: lead's task brief said "-100K"; circuit comments suggest "-200K". Implementation must measure and document. If actual savings <80K, V5.2 stays on pot23 and the pot-shrink win is forfeited (cross-chain portability remains).

5. **Hermez pot22 sha256 pin** [PARTIALLY ANSWERED in v0.5, T3 implementation pass]. Stub ceremony pins to `68a21bef870d5d4a9de39c8f35ebcf04e18ef97e14b2cd3f4c3e39876821d362` measured against the Polygon zkEVM mirror (`https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_22.ptau`) — see §"pot22 vs pot23" above. **Still open for Phase B**: cross-validate this hash against the official Hermez announcement / ceremony manifest before production-grade ceremony. Stub uses first-trust-on-use; production needs independent attestation.

6. **A6.4 browser-bench follow-up gating**: the V5.2 stub zkey is **~2.02 GB** (estimated, scaling linearly from V5.1's 2.12 GB at 4.022M / 3.82M-constraint ratio — per the §"Constraint envelope" estimate of -200K constraints). This sits RIGHT AT the V8 ~2.05 GB single-ArrayBuffer cap (per A6.4 empirical findings on V5.1). If actual savings come in lower (e.g., -100K per lead's conservative brief), the V5.2 zkey lands at ~2.07 GB and stays over the cap. **Either way, the V5.2 zkey is within ±50 MB of the cap** — Chrome browser-proving viability is genuinely uncertain until measured. Worth a measurement gate after stub lands, before user-review of V5.2 — adds context to the EVM-portability narrative ("V5.2 portable across all EVM-family chains AND fixes Chrome browser proving — or just unlocks EVM-family chains"). Firefox 64-bit users already have working browser proving on V5.1 today (per A6.4 user-empirical run, 93s wall, ~20 GB RAM, end-to-end success); V5.2 should remain ≥equivalent.

---

End of v0.5 spec. Contracts-eng v0.4 review folded in; T3 pot22 size correction + sha256 pin folded in. Implementation phase actively in progress on `feat/v5_2arch-circuits` (circuits T1 + T2 shipped at `9d6b305` + `15dd47f`; T3 stub ceremony in flight; T4 CLAUDE.md update pending T3).
