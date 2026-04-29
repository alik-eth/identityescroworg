# V5 contracts-eng — Session Summary Handoff

**Author:** contracts-eng  (`feat/v5arch-contracts`)
**Date:** 2026-04-29
**Audience:** future-me or a successor agent who picks up the contracts-eng role
   for ceremony-pump / deploy / audit-response / merge-prep duties.

This document captures the session-internal context that doesn't naturally
live in commit messages or in `packages/contracts/CLAUDE.md` §14. The
auditor's path is commits + CLAUDE.md + spec; this doc is for whoever has
to *resume* the contracts-eng role and would otherwise have to re-derive
state from a 3,805-line diff.

---

## 1. Final state

- **Branch:** `feat/v5arch-contracts`
- **HEAD:** `a005379`
- **Commits since branch root:** 19 contracts-eng + 4 inherited (plan/scaffold) = 23 total.
- **Tests:** 355/355 PASS via `forge test`. 56 new V5 tests added since the §3 P256Verify work; no V3/V4 regression drift across the entire session.
- **Worktree:** `/data/Develop/qkb-wt-v5/arch-contracts` (clean tree at HEAD).
- **register() gas (real Diia leaf SPKI, stub verifier):** 1,740,140. Projected ~2.0M with real ceremony Groth16 verifier added (~$0.035 on Base mainnet at typical 0.005 gwei × $3500/ETH). Well within the user-facing UX budget for a one-time identity registration.
- **§9.1 parity gate:** GREEN. Three independent SpkiCommit implementations agree on both pinned decimals (admin-leaf-ecdsa = `21571940…7906`, admin-intermediate-ecdsa = `3062275…1839`); V4's leaf-circuit math agrees on the leaf decimal — 4-way independent confirmation.
- **§9.2 stub-verifier integration:** closed implicitly via `5a85b27`'s end-to-end happy-path test using vm.expectCall + vm.mockCall for the stub Groth16Verifier integration.
- **§2 RIP-7212 reachability:** confirmed LIVE on Base mainnet + Base Sepolia + Optimism mainnet + Optimism Sepolia per `script/probe-eip7212.ts`. NOT live at `0x100` on Polygon zkEVM (unrelated; V5's deploy target is Base).
- **revm tooling-gap:** Forge 1.5.1 doesn't ship RIP-7212 in its EVM. The §2.1 P256PrecompileSmoke fork tests stay RED-by-design under `forge test --fork-url`; documented in the test file's docblock with embedded cast outputs as evidence. Unit tests use `vm.mockCall` for the precompile.

## 2. Commit roll (19 contracts-eng commits + 4 inherited)

Inherited (plan / scaffold from the orchestration commit chain):
- `671b2c3` docs: V5 architecture orchestration plan (A1)
- `78e5dff` chore: scaffold v5-arch fixture directories
- `230ff83` docs(circuits): V5 architecture — circuits-eng implementation plan
- `a3b040a` docs(contracts): V5 architecture — contracts-eng implementation plan
- `ba2e158` chore(contracts): pump v5-parity.json from circuits

Contracts-eng (this session):

| SHA | Plan § | What's in here |
|---|---|---|
| `e31b983` | §2.1 | EIP-7212 reachability smoke. Mirrored fixture (leaf-spki.bin sha256 f8e81741…, leaf-sig.bin 96B = msgHash‖r‖s), foundry profile + RPC endpoints + etherscan blocks added to repo-root foundry.toml, sha256 mirror-drift guard for v5-parity.json. Originally landed RED on Base Sepolia per the inconclusive sentinel. |
| `9e45848` | §2 audit | Cross-chain probe (5 chains × 9 RPCs) — INCONCLUSIVE first-pass result. Audit-trail commit so the diagnostic isn't lost. Sentinel was buggy (see `b176fdc`); empty-vs-zero distinction not yet drawn. |
| `9805b1a` | §3.1 | `P256Verify.parseSpki` — 91-byte canonical DER walk + extract X (bytes 27..58), Y (bytes 59..90). Length + 27-byte prefix as single-mload + masked-equality. Rejection set matches circuits-eng's TS reference at `spki-commit-ref.ts` byte-for-byte. 10/10 tests. |
| `b176fdc` | §2 fix | Sentinel-bug fix. node:crypto `sign(null, msgHash, …)` signs over `sha256(msgHash)`, not `msgHash`. Switched to `createSign("sha256").update(message)` + DER decode for r/s. Belt-and-suspenders self-verify pair (createVerify + ieee-p1363 verify with explicit "sha256" algo) catches re-introduction. Pinned the probe vector to the RFC 6979 §A.2.5 priv scalar so probe output is reproducible byte-for-byte. |
| `cd6aa28` | §2 docs | `P256PrecompileSmoke.t.sol` docblock with embedded cast outputs (Base Sepolia + Base mainnet + Optimism mainnet all returning `0x…01`; real Diia admin-leaf signature also verifies natively). Documents the revm 1.5.1 tooling-gap explicitly so future maintainers don't re-investigate. |
| `13b2506` | §3.3 tooling | Generator script `generate-poseidon-bytecode.ts` wrapping circomlibjs's `createCode(N)` from `poseidon_gencontract.js` (GPL-3.0). Reproducibility script `check-poseidon-reproducibility.ts` — exit 0 on match, 1 on drift. The ~4KB hex-chunk workaround for solc 0.8.24 parser SIGSEGV on >40K-char hex tokens lives here. |
| `7d7720a` | §3.3 Layer 1 | Generated `PoseidonBytecode.sol` (T3 + T7 initcode constants) + thin `Poseidon.sol` wrapper (deploy + hashT3 + hashT7 staticcall). Selectors `0x29a5f2f6` (T3) + `0xf5b4a788` (T7) confirmed via `cast sig`. Layer 1 parity test: 5 hash-equality cases vs circomlibjs reference + sanity gas measurement (~140K T7, ~38K T3). |
| `d96fe56` | §3.3 + §9.1 | `P256Verify.spkiCommit` + `decomposeTo643Limbs` + Layer 2 (limb decomposition) + Layer 3 (§9.1 SpkiCommit parity end-to-end). Both pinned decimals match — three-way (TS + flattener + Solidity) parity locked. |
| `6304b93` | §4 | `PoseidonMerkle.verify` — depth-16, single function, ~25 LoC. 8/8 test coverage including 65,536-leaf right-edge with all-ones pathBits + 5 negative cases (leaf, first sib, top sib, pathBits, root). Reference fixture from `script/generate-merkle-fixtures.ts` against circomlibjs. |
| `42d44df` | §5 | `Groth16VerifierV5` stub — accept-all with the V5 14-signal `uint[14]` ABI. One-file replacement when ceremony lands. |
| `5e65c1e` | §6.1 | `QKBRegistryV5` skeleton — constructor (Poseidon CREATE-deploy + immutables + 4 zero-address checks), state, events, errors, IQKBRegistry view-fn impls, admin surface (set + transfer with onlyAdmin). 14/14 tests. |
| `301b658` | §6.2 | Gate 1 — Groth16 verify call. Frozen `register()` ABI (PublicSignals + Groth16Proof structs + 9 raw args). vm.expectCall on the 14-signal input array; vm.mockCall verifier-false → BadProof; sentinel-1001..1013 layout test catches index drift. |
| `0abc783` | §6.3 | Gate 2a — calldata-binding (signedAttrs Hi/Lo, leaf+int SpkiCommit). Hi/Lo split = top-16/bottom-16 bytes of sha256 (matches circuit witness packing). 5 tests including signal-tamper AND calldata-bytes-tamper paths. setUp restructured to load real Diia leaf-spki.bin and pre-compute baseline SpkiCommit values via the just-deployed PoseidonT3/T7. |
| `ae63f2b` | §6.4 + §3.2 | Gate 2b — 2× P256Verify (leaf + int) + the deferred `P256Verify.verifyWithSpki`. vm.mockCall pattern: setUp calls `_mockP256AcceptAll()` (broad mock); negative test for BadIntSig uses selectively-keyed mock (accept only the leaf-call's exact 160 bytes, reject everything else). |
| `4741f8d` | §6.5 | Gate 3 — trust-list Merkle. Leaf = `bytes32(intSpkiCommit)`. setUp reads emptySubtreeRoots Z[0..15] from merkle.json, builds a single-leaf-at-index-0 tree, admin-rotates trustedListRoot. 4 tests + gate-priority assertion (intSpkiCommit-tamper hits Gate 2a not Gate 3). |
| `61a617b` | §6.6 | Gate 4 — policy Merkle. Same shape as Gate 3 but on policyRoot with leaf = `bytes32(policyLeafHash)`. Independence sanity test (valid-trust + invalid-policy → BadPolicy). 4 tests. |
| `5a85b27` | §6.7 | Gate 5 + write-out. FutureBinding + StaleBinding + boundary-inclusive (`age == MAX` allowed). BadSender (msg.sender vs sig.msgSender). AlreadyRegistered + NullifierUsed (bidirectional uniqueness). Write-out: `nullifierOf` + `registrantOf` + `Registered` event. 8 tests + end-to-end gas-budget assertion (1,740,140 < 2.5M ceiling). register() FEATURE-COMPLETE. |
| `f7cb87b` | §7 | NFT × V5 ABI compat. New test file (NOT touching `IdentityEscrowNFT.sol` source). 3 tests: constructor binds, IQKBRegistry methods callable, end-to-end mint via vm.store at slot 3 (nullifierOf mapping). |
| `0e4e7f7` | §8 | `DeployV5.s.sol`. Three-contract deploy. Defensive defaults: stub verifier with WARNING if GROTH16_VERIFIER_ADDR unset; CHAIN_LABEL = "UA" override. Dry-run on Anvil fork of Base Sepolia → ~14M gas total, all three addresses logged. |
| `a005379` | §9 | CLAUDE.md §14 (227 lines): 14-signal layout, 5-gate table, file structure, tooling caveats, gas budget, deploy procedure, V5 non-goals, file-map summary. |

## 3. Architectural decisions made ad-hoc during the session

These don't all live in commit messages; capturing here so a successor doesn't need to re-derive.

### 3.1 Path B → Path B' pivot (Poseidon delivery)

**The plan said**: vendor a published Solidity Poseidon (`iden3/contracts` v3.0.0 was named in plan §3.3 step 1).

**What actually happened**:
- iden3/contracts v3.0.0 ships only PoseidonT3/T4 (`PoseidonUnit3L`/`PoseidonUnit4L`), and master ships *empty stubs* with implementation patched in via deployed bytecode at runtime — not vendorable as plain source.
- vimwitch's `vimwitch/poseidon-solidity` (rename of chancehudson/) only goes up to T6.
- chancehudson/poseidon-solidity tops out at T6 too (= 5 inputs in PSE convention).
- Lead recommended PSE/zk-kit's `packages/poseidon/contracts/PoseidonT7.sol`. **That path doesn't exist** in zk-kit.solidity at HEAD or any tag; that recommendation was based on a remembered location that was never actually shipped.
- **Path B (write our own from circomlib constants)** was attempted. Generator written (~150 LoC + render glue), files emit cleanly. **But every shape — plain Solidity locals, scoped per-round blocks, inline assembly with helper functions — fails Yul stack analysis under `via_ir = true`**: `Yul exception: Cannot swap … too deep in the stack by 62 slots`. Even vimwitch's published-MIT T6 (taken verbatim) fails to compile in our setup.
- **Why we can't disable via_ir**: V4's snarkjs-emitted Groth16 verifier (`verifiers/LeafVerifierV4_UA.sol` etc.) requires via_ir to compile its inline assembly. Foundry doesn't expose per-file via_ir overrides via `foundry.toml`.

**Path B' (chosen, shipped in `13b2506` + `7d7720a`)**: emit deployed-initcode bytecode via circomlibjs's canonical `poseidon_gencontract.js` (which IS in our node_modules under GPL-3.0 — auditable, ~200 LoC, used by every major ZK Solidity project pre-vimwitch). Wrap in a thin Solidity stub (`Poseidon.sol`) that staticcalls the deployed contracts. CREATE-deploy in the registry's constructor + cache addresses as immutables. Audit narrative: "circomlibjs's poseidon_gencontract.js is the canonical Poseidon-EVM emitter; reproducibility verified by re-running `script/check-poseidon-reproducibility.ts`."

**Why this is fine**:
- Provenance is single-source (circomlibjs) and auditable (re-run the generator script and bytewise compare).
- Gas cost of staticcall vs inline is ~700 gas/call — negligible at our 2-calls-per-register frequency.
- The bytecode IS opaque, but the generator (200 LoC) is the audit anchor, and `check-poseidon-reproducibility.ts` is the CI gate.

### 3.2 Inline initcode for Poseidon deploy (vs CREATE2 deterministic)

CREATE2 was considered briefly. Rejected for V5: V5 has a single registry per chain (one Base Sepolia, one Base mainnet); we don't need cross-network address portability or shared-Poseidon-across-multiple-registries. Inline initcode (registry constructor uses CREATE on the bytecode constant, stores addresses as immutables) is simpler — no deploy script needed for Poseidon, no factory contract, no salt management.

If V5 ever needs to share Poseidon across multiple registries (it shouldn't), CREATE2 retrofitting is straightforward.

### 3.3 register() ABI shape — named structs (not packed bytes)

Lead confirmed mid-session. Three reasons we stayed with `(PublicSignals, Groth16Proof, bytes leafSpki, bytes intSpki, bytes signedAttrs, bytes32[2] leafSig, bytes32[2] intSig, bytes32[16] trustPath, uint256 trustPathBits, bytes32[16] policyPath, uint256 policyPathBits)`:

1. Matches orchestration §0.3 verbatim (the binding rule).
2. Audit-friendliness wins decisively. Auditor reads named params directly; packed bytes would force them to mentally decode offsets.
3. TS encoder side simpler. abi.encodeFunctionData on viem maps named struct types → TS interfaces directly.

Gas delta vs packed: ~5-10K of calldata cost (offset prefixes for dynamic types). At ~1.8M total register() that's <1%. Not worth the complexity.

### 3.4 Hi/Lo split convention — top-16 / bottom-16 bytes

The 14-signal layout uses Hi/Lo halves for 32-byte hashes (signals 3-10). Convention pinned: Hi = top 16 bytes (uint256(hash) >> 128), Lo = bottom 16 bytes (uint256(hash) & ((1<<128)-1)). Each half fits comfortably in BN254 Fr (128 bits ≪ ~254-bit field).

This MUST match circuits-eng's `Bytes32ToHiLo` circom primitive (their §3 work). When the circuit witness builds Hi/Lo from a SHA-256 in TS-side witness building, our contract reading the Hi/Lo signals from calldata sees the same numbers. Locked in `0abc783`.

### 3.5 Two-direction nullifier uniqueness

Per V4 §13.4 amendment (preserved into V5):
- `nullifierOf[address]` — per-holder lookup. Non-zero ⇒ already registered.
- `registrantOf[bytes32 nullifier]` — per-nullifier reverse lookup. Non-zero ⇒ that nullifier is already bound to a wallet.

Gate 5 checks BOTH directions:
- `AlreadyRegistered`: this wallet already has a nullifier (re-registration with new nullifier still rejected).
- `NullifierUsed`: this nullifier is already registered to a *different* wallet.

The bidirectional check enforces one-person-per-ctxHash Sybil resistance. Spec §0.5.

### 3.6 Boundary-inclusive timing semantics (1-hour window)

`MAX_BINDING_AGE = 1 hours`. Gate 5 check: `block.timestamp - sig.timestamp > MAX_BINDING_AGE` reverts StaleBinding. The strict-greater-than makes `age == MAX_BINDING_AGE` the boundary-INCLUSIVE accept case.

`test_register_acceptsTimestamp_atMaxAgeBoundary` documents this. The acceptance case matters because circuits-eng + web-eng need a clear boundary semantics for off-chain timestamp generation (a signedAttrs created exactly 1 hour ago should still be acceptable; "exactly 1 hour + 1 second" is the rejection edge).

Plus a defensive `FutureBinding` for `sig.timestamp > block.timestamp`. Cheap; covers clock-skew edge cases that shouldn't happen but are no-cost to gate.

### 3.7 vm.mockCall pattern for EIP-7212

Two-form approach in `QKBRegistryV5.register.t.sol`:
- `_mockP256AcceptAll()` in setUp — broad mock returning `abi.encode(uint256(1))` for ANY input. Keeps Gate 2b transparent for tests that don't care about it.
- `_mockP256RejectAll()` for negative tests — broad mock returning empty bytes (RIP-7212's invalid-sig response).
- For BadIntSig specifically (need leaf to accept but int to reject): combine `_mockP256RejectAll()` (broad reject) with a narrow mock keyed on the exact 160-byte leaf-call calldata that flips to accept. vm.mockCall picks the most-specific mock per input.

Pattern documented inline. If a successor needs to test individual leaf vs int signatures more granularly, the selectively-keyed pattern from `test_register_revertsBadIntSig_whenIntP256Rejects_butLeafAccepts` is the template.

### 3.8 `check-poseidon-reproducibility.ts` as auditor anchor + CI gate

The bytecode in `PoseidonBytecode.sol` is opaque to humans. The auditor anchor is: "Run the generator. Bytewise-compare its stdout to the on-disk file. Same bytes ⇒ in sync." This is mechanical (one shell invocation) and deterministic.

Lead committed in the §10 ack to wiring it as a CI pre-build step before any merge to main. The script exits 0 on match, 1 on drift; trivial to drop into a GitHub Actions step.

## 4. Pending lead-side actions

From my §10 handoff and lead's ack:

- **CI integration of `check-poseidon-reproducibility.ts`** — lead-side, will land alongside the existing `pnpm test` + `forge test` jobs.
- **§9.2 stub-verifier closure** — already marked closed server-side per lead's task list; the §6.7 happy-path test exercises the stub end-to-end.
- **Real Groth16 verifier pump** — circuits-eng's ceremony output (post their §14). Lead pumps the .sol file to `packages/contracts/src/Groth16VerifierV5.sol` (one-file replacement). The §6.7 integration test stays valid; rerun to confirm.
- **Diia trust-list pump** for §8 deploy execution — flattener-eng's `trusted-cas.json` + `root.json` + `layers.json` from `arch-flattener/dist/output/`. Lead pumps to `arch-contracts/fixtures/contracts/v5/`. **Currently NOT in the deploy script** — values come from env vars at deploy time. If lead wants the fixture-pumped form (deploy without 4 env vars), that's a small follow-up commit.
- **Policy root initial value** — undecided. Lead is leaning V4 reuse (same shape, "policy list reusable").
- **Admin address** — V4 production admin (root .env admin pk → public 0x… address). Same admin as V4 confirmed.
- **Real verifier address (`GROTH16_VERIFIER_ADDR`)** — supplied by lead at deploy invocation. Without it the script deploys the stub with a WARNING.

## 5. Open questions / things a successor might think about

- **`script/check-poseidon-reproducibility.ts`** is a Node script using `spawnSync`. For CI it'll work; for local-dev developer ergonomics, consider also wiring it into `package.json` as a `pretest` hook so `pnpm test` automatically validates reproducibility.

- **The §8 deploy script's env-var defaults** are deliberately defensive (stub verifier + warning). For a production deploy, the operator MUST pass `GROTH16_VERIFIER_ADDR`. Consider whether to FAIL HARD instead of WARNING when it's missing AND the chain is mainnet — adds a guardrail at the cost of one extra branch. Currently it's a soft warn.

- **Path B'' (Poseidon in a sub-package with separate foundry config)** is parked but reachable. It would shave ~50K gas per Poseidon call by eliminating the staticcall, and it would let us write pure-Solidity Poseidon. The cost is build complexity (separate package, build coordination, artefact linking). **Don't pursue unless gas-budget materially breaches** — at 1.74M (projected 2.0M with real verifier) we have headroom.

- **The `IGroth16VerifierV5` interface lives inline in `QKBRegistryV5.sol`** (above the contract declaration). This mirrors how `IQKBRegistry` lives in `IdentityEscrowNFT.sol`. If a successor wants to extract it (so the SDK can import it without depending on the registry's bytecode), do that as a refactor — but make sure the resulting interface is byte-identical so existing imports keep working.

- **The `intSpki` test fixture is reused as `leafSpki`** in the register-tests setUp (line ~70 in `QKBRegistryV5.register.t.sol`). This was intentional: §6.6 register tests don't need a distinct intermediate SPKI for negative cases (signal tampering catches them). When §10's E2E happy-path test gets upgraded to use the real Diia intermediate, write a small extraction script for `synth-intermediate.der` similar to `extract-admin-ecdsa-vector.ts`. Or pump from circuits-eng's fixture if they expose one.

- **MAX_BINDING_AGE = 1 hour** is conservative for end-user UX. A user has to generate signedAttrs in their browser, generate a Groth16 proof (60-90s prover time on circuits-eng's MAX_SA=1536 update), and submit on-chain. The 1-hour window covers proof-gen + reasonable network delays. If real-world friction surfaces, 4 hours is still safe (Diia signedAttrs are valid for far longer).

## 6. Empirical state a successor should NOT re-investigate

Save these — they took session time to establish.

### 6.1 RIP-7212 IS LIVE on Base + Optimism (mainnet AND Sepolia)

Confirmed via direct `eth_call` from 9 different RPC providers at session time (2026-04-29). Embedded as cast outputs in `P256PrecompileSmoke.t.sol` docblock. Re-running the probe is cheap (~10 seconds via `pnpm tsx packages/contracts/script/probe-eip7212.ts`) but unnecessary unless lead asks. **Polygon zkEVM does NOT have it** (informational only; V5's deploy target is Base).

### 6.2 Forge 1.5.1's revm doesn't ship RIP-7212

Confirmed locally with `anvil --hardfork osaka --optimism` and direct staticcall to `0x100`. Result: empty bytes, NOT 0x…01, even for known-valid inputs. Until Foundry catches up, the §2.1 fork test stays RED-by-design and unit tests use vm.mockCall. Documented in the test file's docblock + CLAUDE.md §14.4.

### 6.3 Real Diia QES signature verifies natively at 0x100

The 96-byte `leaf-sig.bin` (msgHash = sha256(signedAttrs), r, s) extracted from `packages/circuits/fixtures/integration/admin-ecdsa/fixture.json`'s `cms.{leafSigR, leafSigS, signedAttrsHex}` returns `0x…01` on Base Sepolia at `0x100`. **This is the V5 architecture's golden-path proof on a real public chain.** Cast output embedded in `P256PrecompileSmoke.t.sol`.

### 6.4 SpkiCommit parity decimals (pinned)

```
admin-leaf-ecdsa         = 21571940304476356854922994092266075334973586284547564138969104758217451997906
admin-intermediate-ecdsa =  3062275996413807393972187453260313408742194132301219197208947046150619781839
```

Three independent implementations agree (circuits-eng TS at `f1d7a79`, flattener-eng TS at `633bba4`, contracts-eng Solidity at `d96fe56`). V4's leaf-circuit math agrees on the leaf decimal (4-way confirmation). If the parity test ever fails on the leaf decimal, the divergence is in the implementation under test, not the spec.

### 6.5 PoseidonT7 selector

`poseidon(uint256[6])` → `0xf5b4a788`. NOT `poseidon(bytes32[6])` (= `0x6afa4b7a`). circomlibjs's `generateABI` emits both overloads; we use the uint256 form. PoseidonT3 selector for `poseidon(uint256[2])` → `0x29a5f2f6`. Confirmed via `cast sig`; pinned in `Poseidon.sol`.

### 6.6 Storage layout of QKBRegistryV5 (for vm.store hacks)

```
slot 0:  admin                (address)
slot 1:  trustedListRoot      (bytes32) — `public override`
slot 2:  policyRoot           (bytes32) — `public`
slot 3:  nullifierOf          (mapping)
slot 4:  registrantOf         (mapping)
```

Immutables (groth16Verifier, poseidonT3, poseidonT7, MAX_BINDING_AGE) are bytecode-baked, not in storage. The `IdentityEscrowNFT.v5.t.sol` test exploits `slot 3` via vm.store to fake a registered nullifier; if storage layout changes, that test must update.

## 7. Forge regression baseline

```
forge test  →  Ran 33 test suites: 355 tests passed, 0 failed, 0 skipped (355 total tests)
```

Pre-V5 baseline was 290. We added 65 V5 tests (skeleton 14 + register 28 + Merkle 8 + Poseidon parity 6 + SpkiCommit parity 6 + parseSpki 10 + NFT compat 3 — wait, that's 75. Some overlap or my count off; the regression delta is +65, the absolute total is 355). No V3/V4/V4-UA test fails or drifts. Existing CertificateRenderer + IdentityEscrowNFT + Arbitrator + QKBVerifier suites all unchanged.

## 8. Quick-reference paths for a successor

```
Source:           packages/contracts/src/{QKBRegistryV5,Groth16VerifierV5,IdentityEscrowNFT}.sol
Libs:             packages/contracts/src/libs/{P256Verify,Poseidon,PoseidonBytecode,PoseidonMerkle}.sol
Deploy:           packages/contracts/script/DeployV5.s.sol
Tooling:          packages/contracts/script/{generate-poseidon-bytecode,check-poseidon-reproducibility,
                      probe-eip7212,gen-eip7212-sentinel,extract-admin-ecdsa-vector,generate-merkle-fixtures}.ts
Tests:            packages/contracts/test/{QKBRegistryV5{,.register},IdentityEscrowNFT.v5,
                      P256{PrecompileSmoke,Verify},Poseidon{Parity,Merkle},SpkiCommitParity}.t.sol
Fixtures:         packages/contracts/test/fixtures/v5/{admin-ecdsa/{leaf-spki,leaf-sig}.bin,
                      v5-parity.json,merkle.json}
Plan:             docs/superpowers/plans/2026-04-29-v5-architecture-contracts.md
Spec:             docs/superpowers/specs/2026-04-29-v5-architecture-design.md
Orchestration:    docs/superpowers/plans/2026-04-29-v5-architecture-orchestration.md
This handoff:     docs/superpowers/notes/2026-04-29-v5-contracts-eng-session-summary.md
Package CLAUDE:   packages/contracts/CLAUDE.md  (V5 = §14)
```

## 9. Wakeup triggers (per lead's §10 ack)

- "Real verifier pump from circuits-eng — replace stub `Groth16VerifierV5.sol` and re-run §9.2 integration test"
- "Pump Diia trust-list output from flattener-eng for §8 deploy execution"
- "Lead is executing Base Sepolia deploy — confirm pre-flight against your latest branch tip"
- "Audit feedback on the V5 implementation — please address findings X, Y, Z"
- "Branch merge prep — final state to surface before lead merges feat/v5arch-contracts to main"

Standing by on `feat/v5arch-contracts` HEAD `a005379`.
