# V5.3 — Subject-serial OID-anchor + rotationNewWallet range-check (V5.2 codex follow-ups)

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **Status:** v0.2 — implementation in flight (T1+T2+T3 committed; tests + ceremony stub + doc invariants pending). v0.2 amends v0.1's cost projections, witness-builder framing, F2 contract-side scope, and adds the circom -O1 optimizer footgun discovered during T2.
>
> **Date:** 2026-05-03 (v0.1) → 2026-05-03 (v0.2 same-day amendment from T1/T2 measurements).
>
> **Amends:** `circuits/QKBPresentationV5.circom` (V5.2 in-place; V5.3 is the third in-place amendment after V5.1 wallet-bound nullifier and V5.2 keccak-on-chain). All V5/V5.1/V5.2 invariants remain in force.
>
> **Predecessor work (READ FIRST):**
> - V5 architecture: `docs/superpowers/specs/2026-04-29-v5-architecture-design.md`
> - V5.1 wallet-bound nullifier: `docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md`
> - V5.2 keccak-on-chain: `docs/superpowers/specs/2026-05-01-keccak-on-chain-amendment.md` (v0.5)
> - V5 main circuit: `packages/circuits/circuits/QKBPresentationV5.circom` (post-V5.2, commit `ce4ac41`)
> - V5 subject-serial extractor: `packages/circuits/circuits/primitives/X509SubjectSerial.circom`
> - V5 §6.9 leafTbs ↔ leafCert byte-consistency gate: same .circom, lines 620-668
>
> **Three findings to address:**
> - **F1 (HIGH)**: subject serial-number bytes are not anchored to OID 2.5.4.5 — Sybil vector via "any 32-byte window in signed TBS that looks like a serial number"
> - **F2 (MEDIUM)**: `rotationNewWallet` lacks a 160-bit circuit-side range check — defense-in-depth
> - **F3 (LOW/DOC)**: `walletSecret` ↔ `msgSender` binding is contract-side only — restate explicitly + add circuit comment pointing to the contract gate

## TL;DR

Three minimal in-place changes to the V5.2 circuit. **Public-signal layout is UNCHANGED** (still 22 signals frozen per V5.2 §"Public-signal layout") — V5.3 is private-input + constraint-only. Constraint envelope grows by **+20,052 measured** (3,876,304 → 3,896,356); pot22's 4,194,304 cap holds with **7.10% headroom**, above the 4% safety floor. No web-eng witness-builder API change for F2/F3; F1 adds **one** new private witness input (`subjectSerialOidOffsetInTbs`, derived as `subjectSerialValueOffsetInTbs − 7` — no X.509 walker change).

The full ceremony rolls (V5.3 = new circuit = new zkey = new pot22-based ceremony, ~5-10 contributors, ~1-2 weeks wall) per Phase B planning. The V5.2 ceremony at `ceremony/v5_2/` becomes the V5.2 archive; V5.3 lands at `ceremony/v5_3/`.

## Goals

1. **Close the F1 Sybil vector**: prove the 32-byte serial-number window is bytes inside an actual `AttributeTypeAndValue { type=OID 2.5.4.5, value=DirectoryString }` ASN.1 structure, not arbitrary bytes that happen to look serial-number-shaped.
2. **F2 defense-in-depth**: assert `rotationNewWallet < 2^160` at the circuit boundary, even though the contract already enforces this — eliminates the fragile contract-checks-everything assumption.
3. **F3 doc**: make the wallet-uniqueness storage gate's contract-side responsibility explicit at the circuit's call site, so future contributors don't reintroduce a circuit-side check that breaks rotation semantics.
4. Preserve V5.2's frozen public-signal layout (22 signals) so contracts-eng's calldata + web-eng's SDK fixtures need ZERO calldata adapter changes.
5. Cost ≤ 30K added constraints (stays inside pot22 cap with safe headroom).

## Non-goals

- **No new public signals.** All V5.3 changes are private inputs + new constraints over existing public signals.
- **No re-architecture.** V5.3 is amendment-shaped; not a redesign.
- **No expansion of the "trustless eIDAS" ambition.** F1 closes a Sybil hole; doesn't extend the trust model.
- **No contract ABI break.** F2's contract side is a one-line revert in the existing register/rotateWallet function; F1/F3 are circuit-only.

## Background — F1 vector in detail

The current V5.2 circuit binds the 32-byte serial-number window via two gates:

1. **§6.6 X509SubjectSerial** extracts 32 bytes from `leafCertBytes` at `subjectSerialValueOffset`, masks tail-positions ≥ `subjectSerialValueLength` to zero, packs into 4 × uint64 LE limbs, emits `subjectSerialLimbs[4]` + `rawBytes[32]`.

2. **§6.9 leafTbs ↔ leafCert byte-consistency** asserts the 32 bytes at `subjectSerialValueOffset` (in `leafCertBytes`) match the bytes at `subjectSerialValueOffsetInTbs` (in `leafTbsBytes`), under the active-length mask. `leafTbsBytes` is bound to a real cert via SHA-chained leafTbsHash → intSpki P256Verify on-chain — so the bytes at the witnessed TBS-offset are pinned to the actual issuer-signed cert.

**The vector**: nothing constrains `subjectSerialValueOffsetInTbs` to point at the actual `subject.serialNumber` attribute's value. A malicious prover can pick ANY 32-byte window in the signed TBS that:
- has length 1-32 (passes the X509SubjectSerial range check)
- has all bytes 0-255 (vacuous — every byte qualifies)

That includes byte windows in extension OIDs, CRL distribution points, subjectAlternativeName values, etc. The QTSP-issued cert's signature is over the *whole* TBS, so any sub-window has the QTSP's "this exact byte pattern was authorized by us." The circuit's identityFingerprint + identityCommitment are derived from those bytes — so the prover can produce DIFFERENT (fingerprint, commitment) pairs from the same cert by selecting different windows.

**Combined with rotateWallet** (which clears the old `identityCommitment` slot from contract storage), this becomes a multi-mint Sybil:

1. Holder uses real subject.serialNumber bytes → mints identity #1 → registers at slot[fp1]
2. Holder rotates identity #1 to a discard wallet → contract clears slot[fp1]
3. Holder picks DIFFERENT bytes from the same cert (e.g., bytes from subjectAltName) → fingerprint fp2, commitment cm2 → registers identity #2 at fresh slot[fp2]
4. Repeat. One QES → N identities.

**The fix**: anchor the offset to the OID 2.5.4.5 + AttributeTypeAndValue ASN.1 structure.

DER encoding of the relevant frame:

```
AttributeTypeAndValue ::= SEQUENCE {
  type   OBJECT IDENTIFIER,    -- 2.5.4.5 = id-at-serialNumber
  value  ANY -- DirectoryString
}

DER bytes:
  30 LL                                    -- SEQUENCE, length LL
    06 03 55 04 05                         -- OID 2.5.4.5 (id-at-serialNumber)
    13 NN <NN bytes>                       -- PrintableString, length NN
    -- OR --
    0c NN <NN bytes>                       -- UTF8String, length NN
```

(In practice, real Diia + EU QTSPs use PrintableString `0x13`; UTF8String `0x0c` is permitted by the X.520 spec for international namespaces.)

> **v0.2 amendment — ETSI string-tag scope.** The two tags accepted by F1.2 (`0x13` PrintableString, `0x0c` UTF8String) are the only DirectoryString choices that ETSI EN 319 412-1 §5.1.3 expects to encounter for `id-at-serialNumber` in QTSP-issued natural-person QES certs:
>
> - `0x13` PrintableString — used by all observed Ukrainian (Diia), Polish, German, French QTSPs to date
> - `0x0c` UTF8String — permitted by X.520 DirectoryString and reserved for future EU QTSPs that issue serial-numbers containing non-PrintableString characters (rare but spec-legal)
>
> X.520 also defines `0x14` (TeletexString), `0x16` (IA5String), and `0x1e` (BMPString) as DirectoryString choices. **These are intentionally NOT accepted by F1.** A QES cert using one of those tags for `id-at-serialNumber` would fail F1's string-tag XOR check and be rejected at proof time. Rejection is preferred to acceptance because:
>
> 1. The byte-pattern → field-element pack in §6.6 X509SubjectSerial assumes 1-byte-per-character UTF-8-or-PrintableString semantics. Treating BMPString (UTF-16BE) bytes as PrintableString silently produces wrong identityFingerprint values.
> 2. ETSI EN 319 412-1's namespace strings are all PrintableString-compatible (`TINUA-…`, `PNODE-…`, etc.), so widening to the X.520 superset adds attack surface without serving a real namespace.
> 3. Any future QTSP that requires another DirectoryString choice triggers a V5.4 spec amendment + ceremony — appropriate gate for adding a new accepted tag.

## Construction

### F1 — OID-anchor (recommended: minimal version)

#### F1.1 New private witness input

```circom
signal input subjectSerialOidOffsetInTbs;
```

#### F1.2 Constraint set

At `subjectSerialOidOffsetInTbs` inside `leafTbsBytes`, assert the 5-byte OID prefix:

```circom
// OID 2.5.4.5 (id-at-serialNumber) DER encoding: 06 03 55 04 05.
// Pinned via 5 Multiplexer(1, MAX_LEAF_TBS=1408) reads + 5 byte-eq.
component oidByte[5];
var EXPECTED_OID[5] = [0x06, 0x03, 0x55, 0x04, 0x05];
for (var i = 0; i < 5; i++) {
    oidByte[i] = Multiplexer(1, MAX_LEAF_TBS);
    for (var j = 0; j < MAX_LEAF_TBS; j++) oidByte[i].inp[j][0] <== leafTbsBytes[j];
    oidByte[i].sel <== subjectSerialOidOffsetInTbs + i;
    oidByte[i].out[0] === EXPECTED_OID[i];
}

// String-tag byte: PrintableString (0x13) OR UTF8String (0x0c).
// IsZero(b - 0x13) + IsZero(b - 0x0c) trick — exactly one fires.
component stringTag = Multiplexer(1, MAX_LEAF_TBS);
for (var j = 0; j < MAX_LEAF_TBS; j++) stringTag.inp[j][0] <== leafTbsBytes[j];
stringTag.sel <== subjectSerialOidOffsetInTbs + 5;
component isPS = IsEqual(); isPS.in[0] <== stringTag.out[0]; isPS.in[1] <== 0x13;
component isU8 = IsEqual(); isU8.in[0] <== stringTag.out[0]; isU8.in[1] <== 0x0c;
isPS.out + isU8.out === 1;  // exactly one matches

// Length byte equals subjectSerialValueLength.
component lenByte = Multiplexer(1, MAX_LEAF_TBS);
for (var j = 0; j < MAX_LEAF_TBS; j++) lenByte.inp[j][0] <== leafTbsBytes[j];
lenByte.sel <== subjectSerialOidOffsetInTbs + 6;
lenByte.out[0] === subjectSerialValueLength;

// Value-offset is OID-offset + 7 (5 OID bytes + 1 string tag + 1 length).
subjectSerialValueOffsetInTbs === subjectSerialOidOffsetInTbs + 7;
```

After these constraints, `subjectSerialValueOffsetInTbs` is no longer a free witness — it's fully determined by `subjectSerialOidOffsetInTbs` AND the OID prefix bytes at that offset are pinned to the actual `06 03 55 04 05 <13|0c> NN` ASN.1 frame.

#### F1.3 Cost

> **v0.2 amendment — corrected projection.** v0.1 projected ~10-11K linear from a per-multiplexer cost of ~1,408 (one constraint per `inp[j]`). The empirical T1 cold-compile measured **+19,892 constraints** for the F1 minimal block.
>
> Root cause: circomlib `Multiplexer(1, MAX_LEAF_TBS=1408)` is **not** a linear scan — it instantiates a `MultiMux{n}` (binary-tree decomposition) plus a per-bit `Num2Bits` selector. Per-multiplexer cost is **~2,800 constraints**, not ~1,408.
>
> Corrected v0.2 breakdown:
>
> - 7 × `Multiplexer(1, MAX_LEAF_TBS=1408)` × ~2,800/mux ≈ ~19,600 constraints
> - 5 byte-equality + 2 IsEqual + 1 sum-eq + 1 offset-eq ≈ ~15 constraints
> - Byte-range checks on mux outputs are absorbed into the MultiMux selector cost (no extra ~56 from v0.1)
>
> **Total empirical: +19,892 constraints.** This is ~2× v0.1's projection. The same projection error explained §6.9's leafTbs↔leafCert byte-consistency gate at ~90K rather than v0.1's 33-50K — both use `Multiplexer(1, 1408)` for the in-TBS lookup.
>
> Pot22 envelope still holds: V5.3 measured = **3,896,356** (+20,052 from V5.2's 3,876,304), giving **7.10% headroom** vs the 4% safety floor.

#### F1.4 Stronger version (optional defense-in-depth, +5-10K)

Adds two more witness inputs:

```circom
signal input subjectDnOffsetInTbs;
signal input subjectDnLength;
```

Plus constraints:
1. `leafTbsBytes[subjectDnOffsetInTbs] === 0x30` (Subject DN must be a SEQUENCE)
2. `subjectSerialOidOffsetInTbs >= subjectDnOffsetInTbs` (OID falls inside the DN range start)
3. `subjectSerialValueOffsetInTbs + subjectSerialValueLength <= subjectDnOffsetInTbs + subjectDnLength` (and inside the DN range end)

This catches the case where a `06 03 55 04 05 <13|0c> NN` byte sequence appears OUTSIDE the subject DN (e.g., in an extension that happens to embed a serial-number-shaped attribute). Cost: +1 multiplexer + 2 LessEqThan ≈ +5-6K constraints.

**Strongest interpretation** (subjectDn anchored to its own outer ASN.1 frame, the TBS structure walked in-circuit): out-of-budget. ~100-200K constraints, breaks pot22 envelope. Not pursued in V5.3.

#### F1.5 Recommendation: **minimal version (F1.2)**, defer F1.4 to V5.4

Reasoning:
- Minimal closes the practical attack: a malicious prover would need a QTSP-signed cert whose TBS contains TWO instances of `06 03 55 04 05 <13|0c> NN <bytes>` — i.e., two attribute structures with OID 2.5.4.5 and string-tag value. QTSP-issued production certs have ONE subject.serialNumber attribute by definition (per X.520 + ETSI EN 319 412-1 namespace conventions).
- Stronger (F1.4) defends against maliciously-CRAFTED certs only — and that's already mitigated by the QTSP trust assumption (the cert chain → trusted root must verify).
- **Deferring F1.4 to V5.4** keeps the V5.3 ceremony cycle short (5-10 contributors, ~1-2 weeks). If V5.3 deployment surfaces real attempts to game the OID anchor, V5.4 adds the DN bounds.
- V5.4 deferral is cheap insurance — F1.4 is a strict superset of F1.2 (adds witness inputs + constraints, no breaking changes to F1.2's interface).

**Founder decision (recorded 2026-05-03):** minimal version (F1.2). Implementation lands as F1.2 only; F1.4 spec text below is kept as design reference for V5.4 if the threat model warrants.

> **v0.2 amendment — SDK derivation, not parser edit.** F1's new private input `subjectSerialOidOffsetInTbs` does NOT require any change to the X.509 walker in `src/build-witness-v5.ts`. The walker already locates the subject.serialNumber VALUE bytes (`subjectSerial.offset` returned by `findSubjectSerial`). The OID-anchor offset is **derivable trivially** from the existing parser output:
>
> ```ts
> const subjectSerialOidOffsetInTbs = subjectSerialValueOffsetInTbs - 7;
> ```
>
> The 7-byte constant is the fixed ASN.1 frame width: 5 OID bytes (`06 03 55 04 05`) + 1 string-tag byte (`13` or `0c`) + 1 length byte. This holds for ALL DER-encoded `AttributeTypeAndValue { type=OID 2.5.4.5, value=DirectoryString }` instances per X.690 + X.520 (length is single-byte definite-form because subject serial-number namespace strings are ≤ 127 bytes per ETSI EN 319 412-1 §5.1.3).
>
> The witness-builder change is therefore a **single-line addition** in `src/build-witness-v5.ts` — no new walker logic, no new pkijs traversal. T2's "witness builder" task is bounded accordingly.

### F2 — `rotationNewWallet` 160-bit range check

#### F2.1 Circuit side

> **v0.2 amendment — circom -O1 optimizer footgun.** v0.1's bare pattern (`Num2Bits(160)` with the input wired in but bit outputs unused) **does not actually fire** under circom 2.1.9's `-O1` optimizer when `rotationNewWallet` has no other consumer in the circuit. Empirically measured during T2: the bare component adds **0 R1CS constraints** because the optimizer prunes the entire `Num2Bits` chain (input not consumed → output not consumed → entire component dead-code-eliminated).
>
> The optimizer-prune rule, observed empirically: **`Num2Bits(N)` is preserved if and only if either (a) at least one of its bit outputs is consumed by another constraint, OR (b) its input signal is consumed elsewhere in the circuit (which forces the input to be alive, which forces the bit-decomposition to be alive).** V5.2's `walletSecret` and `oldWalletSecret` Num2Bits(254) checks fire because `walletSecret` flows into Poseidon₂ for nullifier + identityCommitment downstream — the input is consumed. `rotationNewWallet` was orphaned post-V5.2 (the V5.1 in-circuit equality gate against keccak got dropped when keccak moved on-chain), so the bare Num2Bits gets pruned.
>
> Fix: parent-level boolean re-assertion + weighted-sum equality. This pattern forces both legs of the optimizer rule to engage:

Add this constraint set to the V5 main circuit:

```circom
// V5.3 F2 — Range-check: rotationNewWallet fits in 160 bits.  Eliminates
// the fragile "trust the contract to bound it" assumption — circuit
// proves a true Ethereum-address-shaped value.  Fires unconditionally
// (both register and rotate modes; both produce a 160-bit value).
//
// circom -O1 footgun: a bare `Num2Bits(160)` whose bit-outputs are
// unused gets dead-code-eliminated when the input has no other
// downstream consumer.  Counter the prune by (a) re-asserting each
// bit's booleanity at parent level + (b) reconstructing the input as
// a weighted sum of its bits — this forces both the bits AND the
// input to be alive, defeating both legs of the optimizer rule.
component rotationNewWalletBits = Num2Bits(160);
rotationNewWalletBits.in <== rotationNewWallet;
var rotationBitWeightedSum = 0;
for (var rnb = 0; rnb < 160; rnb++) {
    rotationNewWalletBits.out[rnb] * (rotationNewWalletBits.out[rnb] - 1) === 0;
    rotationBitWeightedSum += rotationNewWalletBits.out[rnb] * (1 << rnb);
}
rotationBitWeightedSum === rotationNewWallet;
```

Cost: **161 R1CS constraints empirical** (160 booleanity checks + 1 weighted-sum equality). Matches v0.1's projection — the constraint cost is unchanged, only the IMPLEMENTATION pattern needed adjustment to survive optimizer pruning.

##### Canonical optimizer-aliveness pattern (recipe, for future amendments)

Whenever a private input needs an in-circuit range-check but is otherwise unconsumed by downstream constraints, use this template:

```circom
// Range-check N-bit: <signalName>
component <name>Bits = Num2Bits(N);
<name>Bits.in <== <signalName>;
var <name>WeightedSum = 0;
for (var b = 0; b < N; b++) {
    <name>Bits.out[b] * (<name>Bits.out[b] - 1) === 0;     // booleanity
    <name>WeightedSum += <name>Bits.out[b] * (1 << b);     // sum
}
<name>WeightedSum === <signalName>;                         // equality
```

The booleanity re-assertion + weighted-sum equality together force the optimizer to keep the chain alive even when no other circuit signal reads from `<name>Bits.out[*]` or `<signalName>`. This pattern should be the default for any "defense-in-depth" range-check on an otherwise-orphaned input.

> **DO NOT** rely on `LessThan(N+1).in[0] <== signal; LessThan.in[1] <== (1 << N);` as a workaround. Empirically (T2 measurement) this only adds +1 constraint under `-O1` because the LessThan output is unused — same orphan-prune rule applies.

##### Post-mortem — V5.1 → V5.2 cascading aliveness loss

The optimizer-pruning vulnerability for `rotationNewWallet` was not introduced by V5.3 work; it was a **latent cascading effect from the V5.2 amendment** that V5.3 was the first to surface. Timeline:

- **V5.1**: `rotationNewWallet` was kept alive (under `-O1`) by the in-circuit equality gate `rotationNewWallet === msgSender` (V5.1's wallet-uniqueness anchor). That gate's existence forced `rotationNewWallet`'s value to be consumed by another constraint, which transitively forced any range-check chain on it to stay live. A bare `Num2Bits(160)` would have fired in V5.1.
- **V5.2 keccak-on-chain amendment**: dropped the in-circuit `=== msgSender` equality (the keccak gate moved to the contract, msgSender was removed from public signals). That dropped the ONLY consumer of `rotationNewWallet` inside the circuit.
- **Latent effect**: any future bare `Num2Bits(160)` over `rotationNewWallet` would silently be optimized away, because the input is now orphaned. V5.3's F2 defense-in-depth range-check was the first amendment to attempt one, exposing the issue.

**Generalized rule (canonical for future amendments):**

> When a public-signal slot is no longer constrained by any in-circuit gate (e.g., V5.2's `rotationNewWallet` after dropping the in-circuit equality with `msgSender`), bare `Num2Bits()` range checks may be optimized away by circom -O1. Use parent-aliveness pattern (boolean re-assert outputs at parent scope + weighted-sum equality reconstruction) for orphaned signals.

**Previous-amendment lesson**: constraint deletions can void range-check assumptions in unrelated amendments added later. When dropping an in-circuit constraint, audit downstream amendments that may have implicitly relied on it for aliveness.

##### Why V5.2's `walletSecret` / `oldWalletSecret` Num2Bits(254) ARE sound (T2.5 fold-in NOT needed)

Lead/founder considered folding the parent-aliveness fix into V5.3 as T2.5 to cover V5.2's `walletSecret` and `oldWalletSecret` Num2Bits(254) checks. **Empirical verification (task #63, 2026-05-03) confirmed these checks ARE firing at V5.2; T2.5 is not needed.**

Measurement: V5.2 baseline 3,876,304 constraints minus both `walletSecret` and `oldWalletSecret` Num2Bits(254) calls = 3,875,796. Delta: **−508 = 254 + 254** — both bare Num2Bits chains landed in the r1cs.

Why these survive while `rotationNewWallet`'s did not: `walletSecret` flows into Poseidon₂ for nullifier (`Poseidon₂(walletSecret, ctxHash)`) + identityCommitment (`Poseidon₂(subjectPack, walletSecret)`) — the input is **consumed downstream**, which keeps the bit-decomposition chain alive without parent-aliveness. `oldWalletSecret` similarly flows into identityCommitment-of-old-fp via Poseidon₂ under the rotate-mode gate. Both have a downstream consumer.

**Process learning** (logged 2026-05-03 by lead): workers should question "skip verification, just fix" calls when verification is cheap. The empirical compile (~10 min wall) was cheaper than the cost of a defensive fix — would have added 508 redundant constraints, muddied the auditor narrative ("each Num2Bits provably fires" beats "we verified the optimizer didn't prune it on this specific compiler version" only when the fix is necessary), and committed the team to a non-needed amendment. V5.3 scope stays at T1 (F1 OID-anchor) + T2 (witness builder + tests) + T3 (ceremony stub) + docs. Pot22 headroom remains 7.10%.

#### F2.2 Contract side

> **v0.2 amendment — rotate-only.** v0.1 specified the contract-side check on BOTH `register()` and `rotateWallet()`. Per contracts-eng commit `1b260d8`, the correct scope is **`rotateWallet()` only**:
>
> - In `register()`, the contract sets `rotationNewWallet` itself by deriving from the keccak chain over `bindingPkX/Y` limbs — the resulting value is `uint160(uint256(keccak256(...)))`, which is structurally 160-bit by construction. Adding a range-check would be dead code.
> - In `rotateWallet()`, the holder supplies `rotationNewWallet` as a free witness (the new EOA address they're rotating to). A buggy SDK or malicious client could pass a value with high bits set; the contract-side check catches it.

Add ONE check to `rotateWallet()` in `QKBRegistry` (NOT `register()`):

```solidity
if (sig.rotationNewWallet != uint256(uint160(sig.rotationNewWallet))) revert InvalidNewWallet();
```

~50 gas overhead per `rotateWallet` call, negligible. Belt-and-suspenders with the V5.3 circuit-side `Num2Bits(160)` (which DOES fire unconditionally — register flow's `rotationNewWallet` is also a 160-bit address, just one the contract derived itself).

### F3 — `walletSecret` ↔ `msgSender` binding doc

No code change. Add a comment to V5 main circuit's wallet-secret block (current line ~270, near the `walletSecret` private input declaration) referencing:

- V5.1 wallet-bound nullifier amendment §"Wallet-uniqueness gate location"
- The contract-side storage gate: `identityWallets[fp]` mapping enforces "one wallet per identity fingerprint" at register time
- Why this is contract-side: the circuit can't see on-chain state; the wallet-uniqueness invariant requires comparing against ALL prior identities for the same fp, which requires storage reads

The comment should make it explicit so a future contributor doesn't see "msgSender isn't a private input in the circuit, must be wrong, let's add it" and break the contract-side gate's correctness.

```circom
// V5.3 F3 — wallet-secret ↔ msgSender binding is intentionally
// contract-side, not circuit-side.  The walletSecret private input
// is bound to the holder's identity via Poseidon₂(walletSecret,
// ctxHash) → nullifier (§6.7) and Poseidon₂(subjectSerialPacked,
// walletSecret) → identityCommitment (§V5.1).  But the circuit
// cannot prove "the prover holds the wallet at msg.sender" because
// the wallet-pubkey ↔ msg.sender relation requires the contract's
// storage gate at identityWallets[fp].  See:
//   docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md
//   §"Wallet-uniqueness gate location"
// for the full rationale.  Future contributors: do NOT add a
// circuit-side check on msgSender's relation to walletSecret —
// it would either be ineffective (V5.2 dropped msgSender as a
// public signal) or break the rotation flow's storage semantics.
```

## Public-signal layout (UNCHANGED from V5.2)

V5.3 keeps the V5.2 frozen layout exactly:

| Slot | Signal | Source | Δ from V5.2 |
|---|---|---|---|
| 0 | timestamp | unchanged | — |
| 1 | nullifier | unchanged | — |
| 2-12 | (V5 base + V5.1 SPKI commits) | unchanged | — |
| 13 | identityFingerprint | unchanged construction | — |
| 14 | identityCommitment | unchanged construction | — |
| 15 | rotationMode | unchanged | — |
| 16 | rotationOldCommitment | unchanged | — |
| 17 | rotationNewWallet | **+ Num2Bits(160) circuit-side check** | F2 |
| 18-21 | bindingPkXHi/Lo + bindingPkYHi/Lo | unchanged | — |

**No calldata change.** Contracts-eng's `verifyProof` keeps `uint[22] publicSignals`. Web-eng's SDK fixture (`verification_key.json`) shape unchanged (length 22). Browser-side proof submission unchanged.

## Witness-builder API

### Private inputs added (F1)

```ts
interface BuildWitnessV5Input {
  // ... existing V5.2 inputs ...
  // V5.3 NEW (F1):
  subjectSerialOidOffsetInTbs: number;  // offset of `06 03 55 04 05` byte in leafTbs
}
```

The witness builder computes this offset by walking the cert DER for the `id-at-serialNumber` (OID 2.5.4.5) attribute structure inside the subject RDN. Existing parsing code in `src/build-witness-v5.ts` already locates `subjectSerialValueOffset`; the new offset is `subjectSerialValueOffset - 7` (from the parser's perspective; concrete computation in T2 below).

### F1.4 stronger version (if greenlit)

```ts
  // V5.3 NEW (F1.4):
  subjectDnOffsetInTbs: number;
  subjectDnLength: number;
```

### F2 + F3

No witness-builder API changes. F2 is purely circuit-internal; F3 is documentation.

## Constraint envelope

> **v0.2 amendment — empirical numbers replace projections.** F1.3 root-cause analysis revised the per-multiplexer cost from ~1,408 (linear projection) to ~2,800 (measured); the table below shows BOTH the v0.1 projection and the v0.2 measurement so the calibration error is visible in the historical record.

| Source | V5.2 measured | V5.3 minimal projected (v0.1) | V5.3 minimal **measured (v0.2)** |
|---|---|---|---|
| Base (V5.2) | 3,876,304 | 3,876,304 | 3,876,304 |
| F1 minimal: 7 × Mux(1, 1408) + bytes-eq | — | +~10,500 | **+19,892** |
| F2: Num2Bits(160) parent-aliveness | — | +~160 | **+161** |
| F3: doc | — | 0 | 0 |
| **Total** | **3,876,304** | **~3,886,964** | **3,896,356** |
| Pot22 cap | 4,194,304 | 4,194,304 | 4,194,304 |
| Headroom | **7.6%** | **~7.3%** | **7.10%** |

The +20,052 delta stays above the 4% safety floor (V5 §spec amendment 9c866ad). Pot22 ceremony output is reusable; no need to step up to pot23.

**F1.4 stronger version** (deferred to V5.4 per §F1.5): adds 1 more Multiplexer + 2 LessEqThan ≈ +6-8K constraints (corrected projection per the same ~2,800/mux constant). Still inside pot22 budget.

**If V5.4 lands later constraint-shrinking work** (e.g., mux-less subject-serial extraction, on-chain SHA chain), the headroom comes back. The F1 + §6.9 multiplexer cost dominates V5.3's added footprint.

## Implementation tasks

### T1 (circuits-eng): F1 + F2 + F3 in V5 main circuit

- [ ] Add `signal input subjectSerialOidOffsetInTbs` to `QKBPresentationV5.circom`.
- [ ] Insert the 7-multiplexer OID-anchor block + tag/length/offset constraints (§F1.2 above).
- [ ] If founder picks F1.4 stronger: add `subjectDnOffsetInTbs` + `subjectDnLength` private inputs, plus the DN-bounds constraints (§F1.4 above).
- [ ] Add `Num2Bits(160)` for `rotationNewWallet` (§F2.1 above).
- [ ] Add F3 comment block (§F3 above).
- [ ] Run `compile:v5` to confirm constraint count lands in the projected range; surface back to lead if more than 5K above projection.
- [ ] Update `test/integration/qkb-presentation-v5.test.ts`:
  - Add a positive test: real Diia binding + correct OID offset → witness round-trips.
  - Add a negative test: tamper the witnessed `subjectSerialOidOffsetInTbs` to point at a non-OID byte → witness calc fails.
  - Add a negative test: tamper the OID bytes in leafTbs → witness fails.
  - Add a positive test: rotationNewWallet = 2^160 - 1 → witness round-trips.
  - Add a negative test: rotationNewWallet = 2^160 → witness fails (out-of-range).
- [ ] Update CLAUDE.md with V5.31-V5.33 invariants:
  - V5.31: subject-serial-OID anchor — public-signal layout still 22, F1 closure
  - V5.32: rotationNewWallet 160-bit gate (circuit-side, defense-in-depth)
  - V5.33: walletSecret ↔ msgSender contract-side (F3 doc note)

### T2 (circuits-eng): witness builder + tests

- [ ] Update `src/build-witness-v5.ts`:
  - New input field `subjectSerialOidOffsetInTbs` on `BuildWitnessV5Input`.
  - Emit it in the witness output.
  - The offset is computable from existing parser state: `subjectSerialOidOffsetInTbs = subjectSerialValueOffsetInTbs - 7`.
- [ ] If F1.4 stronger: add `subjectDnOffsetInTbs` + `subjectDnLength` similarly.
- [ ] Update `src/types.ts` header docstring.
- [ ] Update `test/integration/build-witness-v5.test.ts` with the new field assertions.
- [ ] Update `test/integration/v5-prove-verify.test.ts` slot indices (no change needed — public layout unchanged) but verify that the new private inputs flow through to a successful prove.

### T3 (circuits-eng): V5.3 stub ceremony script

- [ ] Copy `ceremony/scripts/stub-v5_2.sh` → `ceremony/scripts/stub-v5_3.sh`.
- [ ] Update paths (`v5_2/` → `v5_3/`, `qkb-v5_2-stub.zkey` → `qkb-v5_3-stub.zkey`, etc.).
- [ ] Run cold ceremony: `pnpm -F @zkqes/circuits ceremony:v5_3:stub`.
- [ ] Verify pot22 sha256 cache hit (no re-download).
- [ ] Confirm ~3.89-3.90M constraint count.
- [ ] Generate stub artifacts at `ceremony/v5_3/`.
- [ ] Pump verifier .sol to contracts-eng + vkey/proof/public/witness-input to web-eng.

### T4 (contracts-eng): F2 contract-side

- [ ] Add `if (sig.rotationNewWallet != uint256(uint160(sig.rotationNewWallet))) revert InvalidNewWallet();` to `register()` AND `rotateWallet()` (both flows expose `rotationNewWallet`).
- [ ] Define `error InvalidNewWallet();`.
- [ ] Update Foundry tests with positive (valid 160-bit) + negative (high bits set) cases.
- [ ] Gas snapshot delta: expect ~50 gas/call.

### T5 (web-eng): witness-builder consumer + SDK fixtures

- [ ] If F1 minimal: pump V5.3 stub vkey + proof + public + witness-input to web's `packages/sdk/fixtures/v5_3/`.
- [ ] If F1.4 stronger: same plus the new `subjectDnOffsetInTbs`/`subjectDnLength` witness fields.
- [ ] No browser-prove-path code change (public layout unchanged).
- [ ] Re-run V5 happy-path Playwright e2e against V5.3 fixtures.

### Phase B ceremony

- [ ] V5.3 = new circuit = new zkey = new ceremony.
- [ ] Coordinator (lead): re-use the V5.2 ceremony coordination scaffold at `scripts/ceremony-coord/`.
- [ ] 5-10 independent contributors via the Fly cookbook (already in tree).
- [ ] Same pot22 input; only the V5.3 R1CS changes (Phase 2 ceremony, not Phase 1).
- [ ] Wall time: ~1-2 weeks (contributor recruitment + the actual contribution chain).
- [ ] Output: `ceremony/v5_3/qkb-v5_3.zkey` + verifier .sol + sample proof bundle.

## Open questions (for founder review)

1. **F1 minimal vs F1.4 stronger?** My read: minimal (~10K) is sufficient given QTSP trust. Lead's read: stronger (+5-10K) defense-in-depth. Both fit the constraint envelope. Founder's call.
2. **F2 also fires under register mode?** Yes per F2.1. Register mode's `rotationNewWallet` slot is set to `msgSender` by the contract gate; it's still a 160-bit value. Range check fires unconditionally — no `ForceEqualIfEnabled` wrapping.
3. **F3 spec wording**: should the comment also reference the V5.2 spec's wallet-secret commentary or only V5.1? Both make sense; default to V5.1 since that's where the gate-location decision lives.
4. **V5.3 ceremony pot file**: pot22 stays. Confirmed — V5.3 envelope is well under pot22's 4.19M cap.
5. **Worker dispatch order**: T1+T2+T3 sequential (one worker, circuits-eng); T4 parallel (contracts-eng); T5 gates on T3's pump. Confirm with lead.

## Backwards compat / migration

V5.3 supersedes V5.2 the same way V5.2 superseded V5.1: in-place amendment to `QKBPresentationV5.circom`, new ceremony, new vkey, new verifier .sol. Old V5.2 register flows on-chain stay registered (no migration); new register/rotate calls go through the V5.3 verifier.

The V5.2 stub at `ceremony/v5_2/` becomes the V5.2 archive (matching the V5.1 pattern). The V5 stub at `ceremony/v5-stub/` (pre-A6.1) remains the older archive.

**Migration**: contracts-eng's deploy script swaps `Groth16VerifierV5_2.sol` → `Groth16VerifierV5_3.sol`. The `QKBRegistry` contract address stays the same (unless founder wants a fresh deploy for clarity); the verifier address is the only change.

**Existing identities are unaffected.** Slot data (nullifier, identityCommitment, identityWallets) was generated under the V5.2 verifier; it remains valid. New register calls produce V5.3-shaped proofs that the new verifier accepts. Dual-verifier transition (accept both V5.2 and V5.3 proofs for a grace window) is OPTIONAL; defer to lead's deploy plan.

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| F1 attack discovered during design but not closed by minimal — needs F1.4 | Medium | Founder picks F1.4 stronger upfront if attack model warrants |
| Real Diia certs use a non-standard subject.serialNumber encoding (e.g., extra wrapper) | Low | Verified during T1: real-Diia .p7s integration test exercises the actual cert structure. If real certs use a wrapper, F1 spec adjusts; otherwise the OID-anchor code works as designed |
| Constraint count exceeds projected envelope (>4.0M) | Low | T1 measures cold-compile constraint count first, surfaces back if over by >5K |
| Phase B ceremony contributor recruitment slips | Medium | Existing scaffolding from V5.2 ceremony reused; lead handles recruitment timeline as separate dispatch |
| F2 circuit-side check breaks register-mode (e.g., msgSender computation changes) | Low | Range check is unconditional + agnostic to mode; covered by negative test |

## Test plan summary

- **F1 positive path**: real Diia .p7s end-to-end through `qkb-presentation-v5.test.ts`'s integration suite. Witness builder produces correct OID offset; circuit verifies; on-chain accepts.
- **F1 negative path 1**: synthetic witness with tampered `subjectSerialOidOffsetInTbs` pointing at a non-OID byte → circuit witness calc fails on the OID-prefix equality check.
- **F1 negative path 2**: synthetic leafTbs with a tampered byte at the OID position → same failure mode.
- **F2 positive**: rotationNewWallet = 2^160 - 1 → round-trips.
- **F2 negative**: rotationNewWallet = 2^160 → witness fails on Num2Bits(160) range check.
- **F3**: no functional test (doc-only); CLAUDE.md V5.33 invariant catches future regressions.

## References

- V5.2 spec: `docs/superpowers/specs/2026-05-01-keccak-on-chain-amendment.md`
- V5.1 wallet-bound nullifier (§"Wallet-uniqueness gate location"): `docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md`
- V5 architecture (§6.6 X509SubjectSerial, §6.9 leafTbs ↔ leafCert byte-consistency): `docs/superpowers/specs/2026-04-29-v5-architecture-design.md`
- iden3/rapidsnark v0.0.8 release: `https://github.com/iden3/rapidsnark/releases/tag/v0.0.8`
- ETSI EN 319 412-1 §5.1.3 (subject serial-number namespace): public spec
- ITU-T X.520 (DirectoryString definition): public spec
- DER OID 2.5.4.5 encoding: `06 03 55 04 05`

## Revision history

- v0.1 (2026-05-03): initial draft — three findings (F1 OID-anchor, F2 160-bit range check, F3 wallet-secret doc), minimal F1 recommended, ceremony pot22-reusable. Pending user-review gate.
- v0.2 (2026-05-03, same-day): post-T1/T2-implementation amendments. Six corrections + post-mortem:
  1. **F1.3 cost projection** revised from ~10-11K to **+19,892 measured** (root cause: circomlib `Multiplexer(1, 1408)` is ~2,800 constraints/mux via MultiMux binary-tree decomposition, not ~1,408 linear). Pot22 envelope holds at 7.10% headroom.
  2. **F2.1 implementation pattern** updated. v0.1's bare `Num2Bits(160)` is dead-code-eliminated by circom 2.1.9 -O1 when the input has no other consumer (empirically confirmed during T2 — 0 constraints added). Replaced with parent-level boolean re-assertion + weighted-sum equality (canonical optimizer-aliveness pattern documented as a recipe).
  3. **F2.2 contract scope** narrowed from "register + rotateWallet" to **rotateWallet only** (per contracts-eng commit `1b260d8`). register() derives `rotationNewWallet` from keccak internally; no malicious-input vector.
  4. **F1.5 SDK derivation note**: clarified that the new private input `subjectSerialOidOffsetInTbs` is computed by trivial subtraction (`subjectSerialValueOffsetInTbs - 7`) — no X.509 walker change needed.
  5. **ETSI string-tag scope note** added: F1 accepts `0x13` PrintableString + `0x0c` UTF8String only; X.520's `0x14`/`0x16`/`0x1e` are intentionally rejected (incompatible with §6.6 byte-pack semantics + outside ETSI EN 319 412-1 §5.1.3 namespace).
  6. **Founder decision recorded**: F1.2 minimal selected (not F1.4 stronger). F1.4 spec text retained as design reference for V5.4 if threat model warrants.
  7. **§F2.1 post-mortem added**: V5.1 → V5.2 cascading aliveness loss documented (V5.1's `rotationNewWallet === msgSender` was load-bearing for keeping Num2Bits live; V5.2's keccak-on-chain amendment removed that gate without replacing the aliveness anchor). Rule generalized for future amendments. Process learning from task #63: workers should question "skip verification, just fix" calls when verification is cheap. Empirical (a) verified V5.2's walletSecret/oldWalletSecret Num2Bits(254) checks ARE firing (delta -508 = 254+254) — T2.5 fold-in NOT needed; V5.3 scope stays at T1+T2+T3+docs.

End of v0.2 spec.
