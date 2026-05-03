# `@qkb/circuits` — Maintainer Notes

## Purpose

Circom 2 circuits for the QKB presentation proof (relation `R_QKB`), plus the
Groth16 ceremony scripts that produce the runtime artifacts shipped to web +
contracts. Phase 1 delivers the **ECDSA-leaf** variant wired against real Diia
QES fixtures; the RSA variant is scaffolded but deferred until non-Diia QES
test material is available.

Proof split (spec §5.4 fallback, forced by the 22 GB compile budget):

- `QKBPresentationEcdsaLeaf.circom` — constraints 1, 2, 5, 6 (binding parse,
  pk/timestamp match, message-digest, ctx/decl, leaf ECDSA-P256 verify).
  Outputs `leafSpkiCommit = Poseidon(Poseidon(Xlimbs), Poseidon(Ylimbs))`.
- `QKBPresentationEcdsaChain.circom` — constraints 3, 4 (intermediate signs
  leaf TBS, intermediate in Merkle-rTL). Outputs the **same** `leafSpkiCommit`.
  On-chain glue: `QKBRegistry` asserts the two commits are equal and that
  `rTL` matches the current flattener root. **Not yet implemented** — Phase 1
  ships leaf-only with the chain constraint enforced off-circuit by the
  trusted-list admin (documented risk in §5.4 of the spec).

## How to run

All commands assume repo root, pnpm 9.x, and Node 20.

```bash
# Full test suite (~15 min — includes the heavy leaf E2E against real QES)
pnpm --filter @qkb/circuits test

# Type-check (fast)
pnpm --filter @qkb/circuits lint

# Ceremony scripts (one-shot each, idempotent)
bash packages/circuits/ceremony/scripts/compile.sh
bash packages/circuits/ceremony/scripts/fetch-ptau.sh      # 9.1 GB
bash packages/circuits/ceremony/scripts/setup.sh           # OOMs on <32 GB dev boxes
bash packages/circuits/ceremony/scripts/prove.sh           # witness + prove + verify round-trip
bash packages/circuits/ceremony/scripts/stub-ceremony.sh   # dev-only (for contracts/web wiring)
```

Setup runs locally; the constraint count of the V5 circuit (~1 M planned)
fits comfortably on a dev box. The Phase-1 ECDSA-leaf legacy circuit
(7.6 M constraints, ~30 GB peak) requires a 32+ GB machine to run
`setup.sh` without OOM — bump `MEM_CAP=32G` and `NODE_HEAP=30720`
accordingly when reproducing legacy artifacts.

## Invariants — do not violate

1. **Never commit `.p7s` files.** They carry a real natural person's legal
   identity under QES. Global `.gitignore` covers them; if one ever slips
   through, `git reset --soft` + `git gc --prune=now --aggressive`
   immediately. A pushed `.p7s` requires QES revocation, not just git
   surgery.

2. **Memory cap every circuit compile + test run at 28 GB.** Pattern:
   `systemd-run --user --scope -p MemoryMax=28G -p MemorySwapMax=0
   NODE_OPTIONS='--max-old-space-size=24576' <cmd>`. Without this, the
   machine swaps itself to death before the OOM killer acts — you lose
   unsaved work across the whole desktop, not just the compile.

3. **Test cache is sticky.** `test/helpers/compile.ts` auto-detects a
   prior compile in `build/test-cache/<hash>/` and re-uses its `.wasm` +
   `.r1cs` + `.sym`. That's how repeat test runs are 30 s instead of
   30 min. **Do not set `recompile: true` manually**; modifying the
   circuit source already invalidates via hash.

4. **JCS canonicalization is non-negotiable.** `BindingParseFull` and
   `buildEcdsaWitness` both assume RFC 8785 encoding of the binding JSON.
   If a future fixture disagrees on field ordering or whitespace, the
   SHA-256 inside signedAttrs won't match and the circuit will reject —
   the bug is in the producer, not the circuit.

5. **Two templates must never share include paths with the vendor
   bigint libs.** zk-email and circom-ecdsa-p256 both define
   `CheckCarryToZero`; we disambiguate by removing the dead `fp.circom`
   include from `primitives/vendor/zk-email/lib/sha.circom`. If a new
   vendor drop reintroduces the collision, fix the include — do NOT
   rename the template.

6. **ECDSA-P256 limb encoding is fixed at n=43, k=6 (6×43-bit LE limbs).**
   Any witness helper producing limbs must round-trip through
   `Bytes32ToLimbs643`. secp256k1 pk-match uses a different encoding:
   4×64-bit LE. These are independent — don't reuse helpers.

7. **Constraint count budget: 8 M hard cap, split at ~7 M.** The ECDSA
   leaf is already at 7.63 M. Any new constraints require either removing
   unused sub-circuits or splitting another proof (chain-style). A new
   sub-circuit that pushes past 8 M will OOM even on 40 GB machines
   for the setup phase.

8. **Snarkjs orders `public.json` as `[outputs…, public_inputs…]`**, not
   by declaration order. The Solidity verifier's `input[N]` array matches
   this (with the leading `1` from the witness stripped). If your on-chain
   verifier expects a specific public-signal index layout — and contracts-
   eng's split-proof `QKBVerifier.verify` does (orchestration §2.1/§2.2
   pin `leafSpkiCommit` at `leafArr[12]` and `chainArr[2]`, both LAST) —
   make ALL public signals `signal input` and add an internal equality
   constraint (`computedValue === publicInputSignal`) for any value that
   would otherwise be a `signal output`. This applies to
   `QKBPresentationEcdsa{Leaf,Chain}.circom`: `leafSpkiCommit` is a
   `signal input` declared LAST in the `component main public [...]`
   list, constrained to equal
   `Poseidon2(Poseidon6(leafXLimbs), Poseidon6(leafYLimbs))`. Caught
   pre-ceremony during the 2026-04-18 split-proof pivot; would have
   produced a silent byte-misalignment between the ceremony stubs and
   contracts-eng's K1 layout.

## Ceremony artifact flow

```
compile.sh      → build/qkb-presentation/QKBPresentationEcdsaLeaf.{r1cs,wasm,sym}
setup.sh        → build/qkb-presentation/{qkb.zkey, verification_key.json,
                                          QKBGroth16Verifier.sol, zkey.sha256}
prove.sh        → build/qkb-presentation/{proof.json, public.json}
                  (round-trip test against real Diia fixture)
upload to R2    → ceremony/urls.json  (committed — URLs + sha256 + metadata)

ceremony/QKBGroth16Verifier.sol   → committed (11 KB, drop-in for the stub)
ceremony/verification_key.json    → committed (4.9 KB, public)
ceremony/zkey.sha256              → committed (integrity reference)
qkb.zkey (4.2 GB)                 → R2 at prove.identityescrow.org/qkb.zkey
.wasm    (41 MB)                  → R2 at prove.identityescrow.org/QKBPresentationEcdsaLeaf.wasm
```

Consumers (web + contracts) read `ceremony/urls.json` at build time. The
zkey is deliberately NOT committed (git will reject >100 MB objects and GH
rejects >2 GB repos outright); R2's 10 GB free tier + 0 egress fees covers
it with headroom for a Phase-2 re-ceremony.

## Stub vs real verifier

- `circuits/QKBPresentationEcdsaLeafStub.circom` — trivial 1-constraint
  circuit with identical public-signal layout (11 inputs + 1 output). Used
  by `stub-ceremony.sh` to produce a dev verifier that forge-compiles and
  contracts can integrate against while the real ceremony runs elsewhere.
- `ceremony/QKBGroth16VerifierStub.sol` — NOT committed; build artifact
  only. Real `ceremony/QKBGroth16Verifier.sol` IS committed (11 KB).
- At deploy: contracts import `QKBGroth16Verifier.sol`. Swap between stub
  and real happens via this path — both contracts have identical
  `verifyProof(uint[2], uint[2][2], uint[2], uint[12]) → bool` ABI.

## Fixtures

- `fixtures/integration/admin-ecdsa/` — real Diia admin binding: full .p7s
  is gitignored (privacy), but the unsigned JSON, signed-attrs DER, leaf
  cert DER, and Merkle path ARE committed because they encode no private
  material beyond what the public admin certificate already publishes.
- `fixtures/x509-samples/` — synthetic RSA + ECDSA SPKI DER for unit tests.
- `fixtures/jcs/` — RFC 8785 vectors (committed, versioned with circuit).

Regenerating a committed fixture is a breaking change — bump a version
comment in the fixture file and update every downstream test in the same
commit, or test suites in other packages will silently drift off it.

## When a test run feels slow

1. Check `build/test-cache/` exists and isn't larger than 30 GB (it caches
   every compile permutation). Stale entries can be deleted; `.mocharc`
   will recompile on hash miss.
2. `mocha --no-config path/to/foo.test.ts` to isolate one file (the
   project `.mocharc.cjs` adds `spec:` which otherwise glob-matches all).
3. A single ECDSA E2E test takes 4–5 min just for witness calculation —
   that's the cost of 1× ECDSA-P256 + 3× SHA256Var + JCS parser in R1CS.
   Not fixable without restructuring the circuit.

## What this package does NOT own

- On-chain verifier deployment → `packages/contracts`.
- Witness construction from a user's fresh QES → `packages/web` builds
  witness inputs client-side using snarkjs + this package's public
  URL artifacts.
- LOTL Merkle root updates → `packages/lotl-flattener`.
- QES attestation service (Phase 2) → `packages/qie-*`.

---

## V5 architecture (current)

V5 collapses the V4 leaf+chain split into a **single ~3.88M-constraint
circuit** (`circuits/QKBPresentationV5.circom`) that takes the QES
verification on-chain via EIP-7212 P256Verify. **V5.1 amends V5 in-place
on the same .circom file (wallet-bound nullifier); V5.2 amends in-place
again (keccak-on-chain).** Empirical envelope is now ~3.876M constraints
with a **22-signal** public-input layout (V5 base shipped 14; V5.1 added
5 → 19; V5.2 dropped 1 + added 4 → 22 — see §V5.11 + §V5.18 below).
The layout is FROZEN per V5 spec §0.1 + V5.1 orchestration §1.1 + V5.2
keccak-on-chain spec §"Public-signal layout V5.1 → V5.2" — adding /
reordering fields is a cross-worker breaking change.

The V4 invariants above (`.p7s` hygiene, test cache stickiness,
fixture provenance, etc.) remain in force. V5 adds the items below;
where V5 numbers replace V4 numbers (memory cap, constraint envelope),
prefer V5.

### V5.1 — Memory caps for compile / ceremony / heavy tests

V4 used `MemoryMax=28G`. **V5 uses 48G.** Empirical peaks:

| Operation | Peak RSS | Why |
|---|---|---|
| `circom --r1cs --wasm` (cold compile) | ~14 GB | 4.02M-constraint R1CS construction in Rust binary |
| `circom_tester.wasm()` (mocha cold compile) | ~32 GB | circom output + V8 holds the witness-calc graph in heap |
| `snarkjs groth16 setup` (zkey new) | ~30 GB | 9.1 GB pot23 + R1CS matrices + G1/G2 scratch tables |
| `snarkjs.groth16.fullProve` (mocha runtime) | ~26 GB | 2.2 GB zkey + V8 BigInt MSM scratch |

V4's 28 GB cap was tight for V4-leaf (which compiled at ~6.5M
constraints in ~22 GB) and **does not fit V5** — `circom_tester.wasm()`
OOMs reproducibly at 28 GB. New pattern:

```bash
systemd-run --user --scope -p MemoryMax=48G -p MemorySwapMax=0 \
  NODE_OPTIONS='--max-old-space-size=46080' \
  <cmd>
```

For `circom` CLI direct (not `circom_tester.wasm()`), the cap can drop
to 24G — the binary doesn't double-buffer the witness-calc graph.

### V5.2 — `--exit` flag in mocha test scripts

`snarkjs.groth16.fullProve` leaks Worker threads (open issue against
snarkjs). mocha 4+ waits for the event loop to drain before exiting,
so the runner hangs indefinitely after tests pass — observed an
~85 s test session sit at 20 GB RSS for 8+ hours overnight without
exiting until manually killed.

**Fix: `mocha --exit`** in every script that runs heavy V5 tests.
Already applied to package.json's `test` and `test:v5` scripts.

### V5.3 — Cold-compile pattern (avoid `circom_tester.wasm()` for V5 main)

For ad-hoc constraint-count probes, run circom directly:

```bash
circom circuits/QKBPresentationV5.circom --r1cs --wasm \
  -l circuits -l node_modules -o build/qkb-presentation/
pnpm exec snarkjs r1cs info build/qkb-presentation/QKBPresentationV5.r1cs
```

(`pnpm -F @qkb/circuits compile:v5` packages the above.)

The mocha test path uses `circom_tester.wasm()` which is convenient
but ~2× memory-heavier; it's fine for warm-cache replay (cheap) but
the FIRST run (cache cold) will OOM under V4's 28 GB cap.

### V5.4 — Constraint envelope

- Empirical V5 base (post-§6.10): **4,020,936 constraints** (snarkjs r1cs info).
- Empirical V5.1 (post-A6.1 wallet-bound nullifier): **4,022,171 constraints** (+1,235 vs V5: T1 +738, T3 +497).
- Cap: **4,500,000** per spec amendment 9c866ad. Headroom ~10.6% (V5.1).
- Wires (V5.1): ~3,956,793. Public inputs: **19** (V5: 14). Private inputs: 10,526 (V5: 9,756).
- V4 hard cap was 8M; V5's tighter envelope reflects ECDSA-on-chain.

**Don't widen the cap without surfacing.** A bigger envelope means
slower prove time + larger zkey, both of which threaten the
mobile-browser acceptance gate (web-eng spec-pass-5).

### V5.5 — `MAX_LEAF_TBS = 1408` (1024 → 1408 empirical bump)

Real Diia leaf TBSCertificate measures **1203 bytes** (admin-ecdsa
fixture). Spec amendment eeb2f4a bumped from the original 1024
(estimated assuming "~700-900 bytes") to 1408 to fit. ~17% headroom
over the 1216 padded-length floor — matches the spec convention
established by MAX_BCANON (real 849, ~21%) and MAX_SA (real 1388,
~10%).

### V5.6 — Vendored Keccak: bkomuves/hash-circuits @ `4ef64777` (MIT)

V5 §6.8 needs in-circuit Keccak-256 for the `msgSender` ←
`keccak256(uncompressed_pk[1:])[12:]` derivation. We vendor
**bkomuves/hash-circuits** at commit `4ef64777cc9b78ba987fbace27e0be7348670296`
(Faulhorn Labs / Balazs Komuves, MIT, last commit 2025-01-24).

| Why bkomuves over alternatives | |
|---|---|
| vocdoni/keccak256-circom | GPL-3.0, 4-year stale, "WIP experimental" |
| rarimo/passport-zk-circuits | MIT but pulls in transitive bitify+sha2 deps + bit-level API |
| **bkomuves/hash-circuits** | **MIT, 4 self-contained files, byte-level `Keccak_256_bytes(input_len)` API** |

PROVENANCE.md in `circuits/primitives/vendor/bkomuves-keccak/`
documents the pin + sha256 of each vendored file. Updates require a
new provenance entry, fresh checksums, and a new ceremony.

### V5.7 — pot23 ptau

Phase 2 ceremony uses `powersOfTau28_hez_final_23.ptau` (cap 8.39M
constraints, ~110% headroom over the 4.5M circuit envelope).

**Empirical file size: 9.1 GB** (Polygon zkEVM mirror at
`https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_23.ptau`,
sha256 `047f16d75daaccd6fb3f859acc8cc26ad1fb41ef030da070431e95edb126d19d`).
Spec amendment 9c866ad's "~1.2 GB" estimate was wrong — that's
roughly the size of pot21's "lite" form, not pot23's full Hermez
ceremony output. **Cross-check pending** against canonical Hermez
sha256 manifest before §11 real ceremony.

Disk usage: 9.1 GB ptau + ~1 GB R1CS + ~2.2 GB zkey ≈ 13 GB scratch
during ceremony. Goes into `build/qkb-presentation/` (gitignored).

### V5.8 — `build-witness-v5` public API

Witness construction lives in `src/build-witness-v5.ts` and exports
the stable surface via `src/index.ts`:

```ts
import {
  buildWitnessV5,
  parseP7s,
  type BuildWitnessV5Input,
  type WitnessV5,
} from '@qkb/circuits';

const cms = parseP7s(p7sBuffer);
const witness = await buildWitnessV5({
  bindingBytes,
  leafCertDer: cms.leafCertDer,
  leafSpki, intSpki,
  signedAttrsDer: cms.signedAttrsDer,
  signedAttrsMdOffset: cms.signedAttrsMdOffset,
});
// `witness` is plain JSON ready for snarkjs.wtns.calculate.
```

CLI: `pnpm -F @qkb/circuits build-witness-v5 ...`. Two modes:
`--p7s <path>` (real Diia ingestion) OR
`--signed-attrs/--md-offset/--leaf-cert` (pre-extracted artifacts).

**Subtle contract**: `signedAttrsMdOffset` is the offset of the
**leading `0x30 0x2f` Attribute SEQUENCE byte** (the start of
`SignedAttrsParser.circom`'s 17-byte EXPECTED_PREFIX walker), NOT
the digest content offset. `parseP7s` byte-checks the leadIn
before returning. Web-eng's vendored copy MUST preserve this
convention or §6.4 breaks silently.

### V5.9 — prove + verify resource envelope (test/integration/v5-prove-verify)

`groth16.fullProve` on the V5 circuit + 2.2 GB zkey: peak RSS
~26 GB, wall ~85 s. **Test gracefully `describe.skip`s** when the
local zkey is missing (typical fresh checkout — `.zkey` is
gitignored). CI runners with <32 GB available memory will OOM if
the zkey IS present; ship the test only if a 48 GB cap is enforced.

The committed sample artifacts (`ceremony/v5_1/proof-sample.json`
+ `public-sample.json`) re-verify against the stub vkey at near-zero
cost — that's the second test in the suite, runs everywhere. Pre-A6.1
artifacts at `ceremony/v5-stub/` are archived (V5 layout, 14 signals);
the V5.1 test consumes `ceremony/v5_1/` exclusively.

### V5.10 — Cross-package isomorphism (#25)

`src/build-witness-v5.ts` and helpers MUST work in a browser bundle
without polyfills. That means:

- **No `node:crypto`** — use `@noble/hashes/sha2#sha256`.
- **No `ethers/lib/utils.keccak256`** — use `@noble/hashes/sha3#keccak_256`.
- **No CJS `require`** — `import { buildPoseidon } from 'circomlibjs'`.

The web-eng vendored copy at `arch-web/sdk/src/witness/v5/` runs a
SHA-256 fingerprint drift-check against this package; any divergence
that requires a polyfill is a drift-check failure, not a "patch
on re-sync" target.

---

## V5.1 — Wallet-bound nullifier amendment (current)

V5.1 layers on top of V5 architecture per
`docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md`
(v0.6, user-approved). All V5 invariants (§V5.1–§V5.10 above) remain
in force; the items below are additive. Spec was originally drafted as
"Issuer-Blind Nullifier" through v0.5 and renamed in v0.6 — older
commits still reference the original name; both refer to the same
amendment.

### V5.11 — Public-signal layout grows from 14 → 19 (FROZEN)

V5.1 inherits the V5 14-signal core (slots 0-13) and appends 5 new
public outputs at slots 14-18:

| Slot | Signal | Source |
|---|---|---|
| 14 | `identityFingerprint` | `Poseidon₂(subjectSerialPacked, FINGERPRINT_DOMAIN)` |
| 15 | `identityCommitment` | `Poseidon₂(subjectSerialPacked, walletSecret)` |
| 16 | `rotationMode` | 0 = register, 1 = rotateWallet |
| 17 | `rotationOldCommitment` | prior `identityCommitment` (rotate) / no-op equal to slot 15 (register) |
| 18 | `rotationNewWallet` | new wallet (rotate) / no-op equal to `msgSender` (register) |

**Slot 2 (`nullifier`) keeps its index but its construction changes**:
V5 derived it from `Poseidon₂(subjectSerial-derived-secret, ctxHashField)`;
V5.1 re-derives it as `Poseidon₂(walletSecret, ctxHashField)`. Slot
position is preserved for forward-compat with V5 calldata indexing,
but the value differs across the version boundary — fixtures from V5
will NOT round-trip against the V5.1 stub vkey.

This layout is **FROZEN** per orchestration §1.1. Reorderings or
insertions are cross-worker breaking changes — the contracts-eng
calldata indices (`uint[19] publicInputs[14..18]`) and web-eng SDK
(`packages/sdk/fixtures/v5_1/verification_key.json`) both pin against
this exact order.

### V5.12 — `walletSecret` private input + mod-p reduction strategy

V5.1 adds **one** new private input: `signal input walletSecret` —
a single BN254 field element (NOT 2 limbs, NOT a 254-bit mask).

**Why mod-p, not mask:** an earlier draft used `walletSecret = (input & ((1<<254)-1))`
to keep values in `[0, 2^254)`. **This was unsound**: BN254's scalar
field `p ≈ 0.756 × 2^254`, so values in `[p, 2^254)` silently wrap
mod p in-circuit, allowing two distinct secrets `x` and `x+p` to
collide on `identityCommitment` and `nullifier` while still passing
`Num2Bits(254)`. **Codex pass 1 [P1] caught this** before T2 shipped.

The correct approach is `walletSecret = u256 mod p_bn254` (canonical
field element). Lives in `src/wallet-secret.ts:reduceTo254()` (function
name preserved for backwards compat despite the semantics rename).
This guarantees no aliasing collisions.

The single-field-element (NOT two limbs) choice trades 2 bits of
entropy for ~600 fewer constraints + simpler witness shape. Acceptable
since the input is 256-bit HKDF/Argon2id output (uniformly random).

**Don't change this back to a mask** — soundness loss is real.

### V5.13 — `rotationMode` gate semantics

`rotationMode` is a 1-bit boolean public input. Both modes are
serviced by the SAME circuit (β-fold per spec §"Architecture decision");
the mode flag gates branch-specific constraints via `ForceEqualIfEnabled`.

**Register mode (`rotationMode = 0`):**
- `rotationOldCommitment === identityCommitment` (no-op echo for downstream calldata uniformity).
- `rotationNewWallet === msgSender` (no-op echo).
- Both gates fire under `ForceEqualIfEnabled(rotationMode = 0 ? 1 : 0)` — i.e., enabled when mode is 0.

**Rotate mode (`rotationMode = 1`):**
- `rotationOldCommitment === Poseidon₂(subjectSerialPacked, oldWalletSecret)` — open gate against the prior wallet's secret. **Load-bearing soundness gate**: without it, anyone with cert + on-chain commitment value could craft a valid rotation proof to ANY new wallet. Codex pass 3 [P2] caught this gap in T1; fixed in T3 (+497 constraints).
- `rotationNewWallet` is unconstrained by the circuit (consumer / contract supplies; the contract enforces `rotationNewWallet == new EOA`).
- Old-wallet *authority* (i.e., proving the user controls the prior wallet's private key) is contract-side via a typed-message sig over (chainId, registry, oldCommit, newWallet) — NOT the circuit's job.

The contract enforces the `rotationOldCommitment` matches the on-chain
stored commitment for the caller's identity fingerprint — the circuit
cannot enforce that (no on-chain state inside R1CS).

### V5.14 — Wallet-uniqueness rule (anti-Sybil invariant)

A user's `identityCommitment` is keyed by `(subjectSerialPacked, walletSecret)`.
Per ETSI EN 319 412-1 semantics-identifier namespacing (carried forward
from the V4 person-nullifier amendment), `subjectSerialPacked` is
stable across cert renewals **inside** the identifier namespace
(e.g., all `PNOUA-…` certs from any QTSP collapse to the same value).

**Implication**: the same human holding both `PNOUA-…` and `PNODE-…`
certs (different Member States) produces TWO distinct commitments
+ TWO distinct fingerprints. This is intentional — eIDAS does NOT
require pan-EU identifier collapse; cross-namespace dedup belongs in
a separate identity-escrow layer ABOVE QKB.

**Implication**: a single user can derive multiple `walletSecret`s
from the SAME identity (e.g., HKDF from different EOA keys), each
producing a different `identityCommitment` for the same `identityFingerprint`.
Wallet-uniqueness is therefore enforced contract-side by **two
`nullifierOf` write-once gates** (per spec v0.6 §"Wallet uniqueness
[v0.5]"):
- `register()` first-claim path: `require(nullifierOf[msg.sender] == 0)`
  before writing `nullifierOf[msg.sender] = nul`. Prevents a wallet
  that already claimed identity X from claiming identity Y.
- `rotateWallet()`: `require(nullifierOf[newWallet] == 0)`. Prevents
  rotating to a wallet that already holds another identity.

Repeat-claim paths against the SAME fingerprint go through `register()`'s
repeat-claim branch (`identityCommitments[fp] != 0`); cross-wallet
re-association on the same identity goes through `rotateWallet()`. The
circuit alone does not detect the multi-wallet case — these gates are
strictly contract-side. `usedFp` is NOT used; uniqueness lives entirely
on `nullifierOf` + `identityCommitments[fp]` + `identityWallets[fp]`.

### V5.15 — `usedCtx[fp][ctxKey]` is load-bearing for the no-reset stance

Even without an `identityReset()` primitive (V5.1 ships none), the
nullifier semantics are preserved across `rotateWallet()`: the
`identityFingerprint` is wallet-independent (`subjectSerialPacked +
FINGERPRINT_DOMAIN`), so `usedCtx[fp][ctxKey]` flags persist forever
regardless of how many times the wallet rotates.

This is the anti-Sybil load-bearing invariant. Future V6 reset paths
(time-locked veto, social recovery via M-of-N guardians) MUST preserve
`usedCtx[fp][*]` write-once semantics; otherwise a stolen-QES attacker
who triggers reset can re-claim against a previously-used context.
Out of scope for A6.1 — flagged in spec v0.5 §"identityReset() — V5
decision".

### V5.16 — Witness-builder API: `walletSecret` is required

`buildWitnessV5` in `src/build-witness-v5.ts` REQUIRES `walletSecret:
Buffer` (32 bytes) as a top-level input field. The rotate path requires
`rotationMode: 1` PLUS three additional inputs (`rotationOldCommitment`,
`rotationNewWalletAddress`, `oldWalletSecret`) — all three are required
when `rotationMode === 1`; under register mode (default 0) they default
to no-op self-equal values inside the witness builder.

```ts
const witness = await buildWitnessV5({
  bindingBytes,
  leafCertDer, leafSpki, intSpki,
  signedAttrsDer, signedAttrsMdOffset,
  walletSecret,                            // V5.1 required, 32 bytes
  // -- rotate path (all three required when rotationMode === 1) --
  rotationMode: 0,                         // V5.1 optional, default 0 (register)
  rotationOldCommitment,                   // V5.1 required iff rotationMode=1
  rotationNewWalletAddress,                // V5.1 required iff rotationMode=1 (NB: input field is …Address; the public-signal slot 18 name in the circuit is `rotationNewWallet`)
  oldWalletSecret,                         // V5.1 required iff rotationMode=1
});
```

**Caller responsibility**: derive `walletSecret` via HKDF over a
`personal_sign` signature (EOA path) or Argon2id over a passphrase +
domain-separated salt (SCW path). Per spec v0.6 §"SCW path", the SCW
derivation is:

```
salt = SHA-256("qkb-walletsecret-v1" || chainId || smartWalletAddress)
walletSecret = Argon2id(passphrase, salt, m=64MiB, t=3, p=1, L=32)
walletSecret_field = bytesToField(walletSecret) % p_bn254
```

Web-eng owns the production derivation in `@qkb/sdk`; this package's
`src/wallet-secret.ts` exports `reduceTo254()` + `packFieldToBytes32()`
for circuit-level test fixtures only. **Both paths MUST produce
byte-identical commitments** — cross-package fingerprint drift here
breaks witness exchange.

### V5.17 — Stub ceremony at `ceremony/v5_1/` supersedes `ceremony/v5-stub/`

Task 4 of A6.1 produces V5.1-specific stub artifacts at
`ceremony/v5_1/`:

- `Groth16VerifierV5_1Stub.sol` — 19-public-input Solidity verifier.
- `verification_key.json` — V5.1 vkey (no "-stub" suffix per pump
  contract; web-eng pins to this filename).
- `proof-sample.json` + `public-sample.json` + `witness-input-sample.json` —
  the (witness, public, proof) triple for round-trip integration tests.
- `qkb-v5_1-stub.zkey` — gitignored (~2.1 GB).

The V5 stub at `ceremony/v5-stub/` is left as an archive (different
circuit, 14 public signals). Downstream consumers (contracts-eng's
register/rotateWallet, web-eng SDK fixtures) consume `ceremony/v5_1/`
exclusively after the Task 4 pump.

Reproduce: `bash ceremony/scripts/stub-v5_1.sh` (~20-30 min wall with
pot23 cached, ~30-50 GB peak RSS).

---

## V5.2 — Keccak-on-chain amendment (current)

V5.2 layers on top of V5.1 per
`docs/superpowers/specs/2026-05-01-keccak-on-chain-amendment.md`
(v0.5 draft — user-review gate pending). Every V5.1 invariant
(§V5.11–§V5.17 above —
wallet-bound nullifier, mod-p reduction, rotationMode gate semantics,
wallet-uniqueness rule, usedCtx no-reset stance, witness-builder API
shape) remains in force; the V5.2 items below are amendments to layout
+ ceremony + cross-chain claim, NOT to soundness story.

### V5.18 — Public-signal layout grows from 19 → 22 (FROZEN)

V5.2 inherits the V5.1 19-signal layout, **drops `msgSender` from slot
0** (V5.1's slot 0 was `msgSender`), shifts every other slot up by 1,
then **appends 4 new wallet-pk limb signals at slots 18-21**:

| Slot | Signal | Source / V5.1→V5.2 delta |
|---|---|---|
| 0 | `timestamp` | V5.1 was slot 1; shifted up to 0 after `msgSender` removal |
| 1 | `nullifier` | unchanged from V5.1 (Poseidon₂(walletSecret, ctxFieldHash)) |
| 2-12 | (all V5 base + V5.1 SPKI-commit slots) | unchanged values; slot indices match V5.1 minus 1 |
| 13 | `identityFingerprint` | V5.1 slot 14 → V5.2 slot 13 |
| 14 | `identityCommitment` | V5.1 slot 15 → V5.2 slot 14 |
| 15 | `rotationMode` | V5.1 slot 16 → V5.2 slot 15 |
| 16 | `rotationOldCommitment` | V5.1 slot 17 → V5.2 slot 16 |
| 17 | `rotationNewWallet` | V5.1 slot 18 → V5.2 slot 17 (now contract-enforced equality vs `msg.sender` under register mode, was in-circuit in V5.1) |
| **18** | **`bindingPkXHi`** | **V5.2 NEW** — upper 128 bits big-endian of binding-attested wallet pkX |
| **19** | **`bindingPkXLo`** | **V5.2 NEW** — lower 128 bits big-endian of binding-attested wallet pkX |
| **20** | **`bindingPkYHi`** | **V5.2 NEW** — upper 128 bits big-endian of binding-attested wallet pkY |
| **21** | **`bindingPkYLo`** | **V5.2 NEW** — lower 128 bits big-endian of binding-attested wallet pkY |

This layout is **FROZEN** per spec §"Public-signal layout V5.1 → V5.2".
Reorderings or insertions are cross-worker breaking changes — the
contracts-eng calldata indices (`uint[22] publicInputs[18..21]`) and
web-eng SDK (`packages/sdk/fixtures/v5_2/verification_key.json`) both
pin against this exact order. V5.1 fixtures at `ceremony/v5_1/`
(19-signal layout) will NOT round-trip against the V5.2 stub vkey.

### V5.19 — In-circuit keccak gate removed; contract reconstructs

V5 §6.8 had an in-circuit keccak chain that reduced the binding pk to
`msg.sender` and asserted equality. V5.2 removes that chain entirely:

- `Secp256k1PkMatch.circom` and `Secp256k1AddressDerive.circom` are
  no longer included from the main circuit (still in-tree for V5.1
  archive consumers).
- `bkomuves/hash-circuits` keccak primitive (§V5.6) is no longer
  invoked from the V5.2 main circuit.
- The 4 V5.2 limb publics are byte-identical to V5.1's
  `Secp256k1PkMatch` input bytes (`parser.pkBytes[1..65]`), packed at
  128-bit instead of 64-bit granularity. Contract reassembles via
  `pkX = (Hi << 128) | Lo` per coordinate, prepends `0x04` (SEC1
  uncompressed prefix), runs `keccak256(uncompressed_pk)`, casts the
  low-160 bits, asserts `== msg.sender`. ~150 gas overhead vs V5.1's
  in-circuit gate (the contract-side keccak is the cheap leg).

The SEC1 prefix byte `0x04` IS still asserted in-circuit (`parser.pkBytes[0] === 4`)
to lock the wire format. Removing that constraint would let a malicious
prover supply `0x06`/`0x07` (SEC1 compressed encodings) and the contract
keccak would then hash the wrong bytes.

**Cross-chain implication** (informational): V5.2 unblocks deploying the
verifier on chains without a 256-bit-word keccak gas profile (cheap
keccak is EVM-native). Practical scope today is bounded to EVM-family —
the OTHER chain dependency, P-256 ECDSA via EIP-7212 / RIP-7212, is
still required (mainnet, Base, OP have it; Arbitrum + Polygon zkEVM
do NOT). Non-EVM chains need separate auth shims.

### V5.20 — Constraint envelope drops; pot22 supersedes pot23

| | V5.1 | V5.2 |
|---|---|---|
| Constraints | 4,022,171 | **3,876,304** (-145,867) |
| Public inputs | 19 | **22** |
| Private inputs | 10,526 | **10,518** (`pkX[4]` + `pkY[4]` removed; net -8. `msgSender` was a V5.1 PUBLIC signal, not a private input — its removal shifts public-signal count, not private-input count) |
| Wires | ~3,956,793 | ~3,818,735 |
| Powers-of-tau | pot23 | **pot22** (cap 4,194,304 — 8% headroom over 3.876M) |
| ptau download | 9.1 GB | **4.83 GB** (Phase B contributors save 4.6 GB) |

**Pot22 sha256 (first-trust-on-use)**:
`68a21bef870d5d4a9de39c8f35ebcf04e18ef97e14b2cd3f4c3e39876821d362`
measured 2026-05-03 against the Polygon zkEVM mirror at
`https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_22.ptau`.
Stub-ceremony script `ceremony/scripts/stub-v5_2.sh` pins to this
hash unconditionally on every run. **Phase B real ceremony MUST
cross-validate against an independent Hermez announcement source**
before dispatch (open question #5 in the V5.2 spec).

The `4.5M` constraint cap from §V5.4 still applies; the V5.2 envelope
sits comfortably under both that cap and the pot22 cap. **Don't widen
the cap** — same reasoning as §V5.4 (mobile-browser prove-time + zkey
download).

### V5.21 — Witness-builder API: pk-limb fields are OUTPUT, not input

`buildWitnessV5` no longer accepts `pkX[4]` or `pkY[4]` private-input
fields — those were V5.1's in-circuit Secp256k1PkMatch inputs and have
no analog under V5.2. (V5.1 `BuildWitnessV5Input` never had a `msgSender`
field either — V5.1 derived `msgSender` internally and emitted it as
public-signal output; V5.2 still derives it internally for the
register-mode `rotationNewWallet` no-op default but no longer emits it
to the public-signal vector.) The 4 V5.2 wallet-pk limb fields are
emitted as witness OUTPUT (auto-derived from the SEC1-uncompressed pk
parsed out of `bindingBytes`):

```ts
const witness = await buildWitnessV5({
  bindingBytes,
  leafCertDer, leafSpki, intSpki,
  signedAttrsDer, signedAttrsMdOffset,
  walletSecret,                 // V5.1 required, unchanged
  rotationMode: 0,              // V5.1, unchanged
  // …rotation fields, V5.1, unchanged…
});
// witness.bindingPkXHi / bindingPkXLo / bindingPkYHi / bindingPkYLo
// are computed by the witness builder from parser.pkBytes[1..65],
// packed big-endian at 128-bit halves.  Contract reassembles + keccaks.
```

**Caller responsibility**: NONE for the new fields — the witness
builder owns the derivation. Web-eng SDK consumers do NOT need to
supply pk-limb inputs. The cross-package isomorphism check (§V5.10)
covers the byte-identical packing between Node + browser builds.

The packing is `bytesBeToBigInt(slice)` over 16-byte windows from
`parser.pkBytes[1..17]` / `[17..33]` / `[33..49]` / `[49..65]`. An
asymmetric-pk unit test in `test/integration/build-witness-v5.test.ts`
locks down the windowing — symmetric synthetic fixtures (X = 0x11×32,
Y = 0x22×32) would let a Hi/Lo swap or off-by-16 bug pass silently.

### V5.22 — Stub ceremony at `ceremony/v5_2/` supersedes `ceremony/v5_1/`

T3 of A7.1 produces V5.2-specific stub artifacts at `ceremony/v5_2/`:

- `Groth16VerifierV5_2Stub.sol` — 22-public-input Solidity verifier.
- `verification_key.json` — V5.2 vkey (no "-stub" suffix per pump
  contract; web-eng pins to this filename).
- `proof-sample.json` + `public-sample.json` + `witness-input-sample.json`
  — the (witness, public, proof) triple for round-trip integration tests.
- `qkb-v5_2-stub.zkey` — gitignored (~2.0 GB; pump via R2).
- `zkey.sha256` — atomic-write integrity manifest. Manifest invariant:
  `zkey.sha256 exists ⇔ ceremony script reached the last line`.

The V5.1 stub at `ceremony/v5_1/` is left as an archive (different
circuit, 19 public signals, in-circuit keccak chain). Downstream
consumers (contracts-eng's V5.2 register/rotateWallet, web-eng SDK
fixtures) consume `ceremony/v5_2/` exclusively after the T3 pump.
The V5 stub at `ceremony/v5-stub/` (14 public signals, pre-A6.1)
remains the older archive.

Reproduce: `pnpm -F @qkb/circuits ceremony:v5_2:stub` (~25 min wall
with pot22 cached + R1CS+wasm cached, ~30-50 GB peak RSS; ~60-120 min
cold including pot22 fetch over EU broadband). The script is
idempotent — re-runs short-circuit through cached artifacts and
re-emit a bytewise-stable manifest. Cascade pre-wipe pattern: any
upstream regen wipes `zkey.sha256` BEFORE the risky operation runs,
so a mid-run failure cannot leave a stale manifest validating against
an incoherent bundle.

**Per-step cookbook detail** (calibrated to 2026-05-03 T3 run):
- `snarkjs zkey contribute` runs **~5-7 min** on V5.2's ~2 GB zkey,
  not "~30s" as V5.1's README implied — snarkjs 0.7.6 emits DEBUG-level
  per-65,536-wire progress that V5.1's contribute log didn't surface.
  Phase B contributors who watch their machine sit at "L Section
  327680/3818712" for several minutes will assume something is broken
  unless they read this section first. The work is real; the wall
  scales with L+M+H section size.
