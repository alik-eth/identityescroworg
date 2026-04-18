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

**For the real setup** (7.6M constraints, ~30 GB peak), use Fly.io:

```bash
# See ceremony/scripts/fly-setup-remote.sh — spin up a throwaway
# performance-10x (40 GB) machine, upload .r1cs (compressed 26×) + run.
# Total wallclock: ~60 min setup + 10 min contribute + 3 min prove.
```

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
   sub-circuit that pushes past 8 M will OOM even on 40 GB Fly machines
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
setup.sh / fly  → build/qkb-presentation/{qkb.zkey, verification_key.json,
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
