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

## V5 architecture (current — `feat/v5arch-circuits`)

V5 collapses the V4 leaf+chain split into a **single ~4.02M-constraint
circuit** (`circuits/QKBPresentationV5.circom`) that takes the QES
verification on-chain via EIP-7212 P256Verify. The 14-signal public-input
layout is FROZEN per V5 spec §0.1 + orchestration §2.1 — adding /
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

- Empirical (post-§6.10): **4,020,936 constraints** (snarkjs r1cs info).
- Cap: **4,500,000** per spec amendment 9c866ad. Headroom ~10.7%.
- Wires: 3,955,558. Public inputs: 14. Private inputs: 9,756.
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

The committed sample artifacts (`ceremony/v5-stub/proof-sample.json`
+ `public-sample.json`) re-verify against the stub vkey at near-zero
cost — that's the second test in the suite, runs everywhere.

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
