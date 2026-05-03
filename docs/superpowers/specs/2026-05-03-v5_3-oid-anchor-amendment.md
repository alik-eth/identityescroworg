# V5.3 — Subject-serial OID-anchor + rotationNewWallet range-check (V5.2 codex follow-ups)

> **Status:** Draft v0.1 — pending user-review gate, then T1-T3 implementation dispatch.
>
> **Date:** 2026-05-03 (post-V5.2 ship at `v0.5.2-pre-ceremony`).
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

Three minimal in-place changes to the V5.2 circuit. **Public-signal layout is UNCHANGED** (still 22 signals frozen per V5.2 §"Public-signal layout") — V5.3 is private-input + constraint-only. Constraint envelope grows by ~15-25K (well inside pot22's 4,194,304 cap; 7.6% headroom on V5.2 → 6.9-7.2% on V5.3, comfortably above the 4% safety floor). No web-eng witness-builder API change for F2/F3; F1 adds three new private witness inputs (`subjectSerialOidOffsetInTbs`, optionally `subjectDnOffsetInTbs` + `subjectDnLength`).

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

- 7 × `Multiplexer(1, MAX_LEAF_TBS=1408)` ≈ 7 × 1408 = ~9.9K linear constraints
- 5 byte-equality + 2 IsEqual + 1 sum-eq + 1 offset-eq ≈ ~15 constraints
- Plus byte-range checks on the multiplexer outputs (8 bits each) ≈ 56 constraints

**Total: ~10-11K constraints.** Codex's "10-20K" estimate; lands at the low end.

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

**Open for founder review:** lead's read favors F1.4 (stronger). If founder picks stronger, the ceremony cycle is the same effort (one new circuit either way); the choice is purely cost-vs-belt-and-suspenders.

### F2 — `rotationNewWallet` 160-bit range check

#### F2.1 Circuit side

Add ONE constraint to the V5 main circuit:

```circom
// Range-check: rotationNewWallet fits in 160 bits.  Eliminates the
// fragile "trust the contract to bound it" assumption — circuit
// proves a true Ethereum-address-shaped value.  Fires unconditionally
// (both register and rotate modes; both produce a 160-bit
// new-wallet value).
component rotationNewWalletBits = Num2Bits(160);
rotationNewWalletBits.in <== rotationNewWallet;
```

Cost: **160 constraints + 1 Num2Bits sum = ~161 constraints.**

#### F2.2 Contract side

Add ONE check to `register()` and `rotateWallet()` in `QKBRegistry`:

```solidity
if (sig.rotationNewWallet >= (1 << 160)) revert InvalidNewWallet();
```

Or equivalently:

```solidity
if (sig.rotationNewWallet != uint256(uint160(sig.rotationNewWallet))) revert InvalidNewWallet();
```

Both forms are equivalent; the latter is clearer. ~50 gas overhead per call, negligible. Belt-and-suspenders with the circuit-side check.

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

| Source | V5.2 measured | V5.3 minimal projected | V5.3 stronger projected |
|---|---|---|---|
| Base (V5.2) | 3,876,304 | 3,876,304 | 3,876,304 |
| F1 minimal: 7 × Mux(1, 1408) + bytes-eq | — | +~10,500 | +~10,500 |
| F1.4 stronger: +1 Mux + 2 LeqThan | — | — | +~5,500 |
| F2: Num2Bits(160) | — | +~160 | +~160 |
| F3: doc | — | 0 | 0 |
| **Total projected** | **3,876,304** | **~3,886,964** | **~3,892,464** |
| Pot22 cap | 4,194,304 | 4,194,304 | 4,194,304 |
| Headroom | **7.6%** | **~7.3%** | **~7.2%** |

Both versions stay above the 4% safety floor (V5 §spec amendment 9c866ad). Pot22 ceremony output is reusable; no need to step up to pot23.

**If V5.4 lands later constraint-shrinking work** (e.g., mux-less subject-serial extraction, on-chain SHA chain), the headroom comes back. F1's mux cost dominates V5.3's footprint.

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
- [ ] Run cold ceremony: `pnpm -F @qkb/circuits ceremony:v5_3:stub`.
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

End of v0.1 spec.
