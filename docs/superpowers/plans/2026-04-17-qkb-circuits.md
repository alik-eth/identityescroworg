# @qkb/circuits — Implementation Plan

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Circom 2 circuits that implement relation `R_QKB`, compiled with a documented Groth16 ceremony, exporting Solidity verifier + `verification_key.json` + `.zkey` + `.wasm` for browser proving.

**Architecture:** One top-level circuit `QKBPresentation.circom` composed from reusable sub-circuits. Each sub-circuit is independently unit-tested with `circom_tester`. Fixed max sizes everywhere (no dynamic allocation). RSA verify is adapted from `@zk-email/circuits`; Poseidon and SHA-256 from `circomlib`.

**Tech Stack:** Circom 2.1.x, circomlib, `@zk-email/circuits`, snarkjs, circom_tester, Mocha, Chai, Node 20. Foundry invoked only to compile the exported `Verifier.sol` as a sanity check (not redeployed here).

**Package dir:** `packages/circuits/` (scaffold pre-existing).

---

## File structure

```
packages/circuits/
├── package.json
├── circuits/
│   ├── QKBPresentation.circom        # main
│   ├── primitives/
│   │   ├── RsaPkcs1V15Verify.circom
│   │   ├── Sha256Var.circom          # variable-length SHA-256 wrapper
│   │   ├── MerkleProofPoseidon.circom
│   │   └── PoseidonChunkHash.circom
│   ├── x509/
│   │   ├── X509Parse.circom          # ASN.1 slicing
│   │   └── X509Validity.circom       # notBefore/notAfter check
│   ├── binding/
│   │   ├── BindingParse.circom       # scan JCS bytes for fields
│   │   └── DeclarationWhitelist.circom
│   └── secp/
│       └── Secp256k1PkMatch.circom
├── inputs/
│   └── fixture-builder.ts            # Node helper: real .p7s → witness json
├── ceremony/
│   ├── ptau/                         # gitignored; script downloads
│   ├── scripts/
│   │   ├── compile.sh
│   │   ├── setup.sh                  # phase2 ceremony runner
│   │   └── export.sh                 # zkey → verifier.sol + vkey.json
│   └── ceremony.md                   # transcript
├── build/
│   └── qkb-presentation/             # output: .r1cs, .wasm, .zkey, vkey.json, Verifier.sol
├── test/
│   ├── primitives/
│   │   ├── rsa.test.ts
│   │   ├── sha256.test.ts
│   │   └── merkle.test.ts
│   ├── x509/
│   │   ├── parse.test.ts
│   │   └── validity.test.ts
│   ├── binding/
│   │   ├── parse.test.ts
│   │   └── whitelist.test.ts
│   ├── secp/pkmatch.test.ts
│   ├── integration/
│   │   ├── positive.test.ts
│   │   └── negative.test.ts
│   └── helpers/
│       ├── fixture.ts
│       └── compile.ts
└── fixtures/
    ├── rsa-vectors.json              # known good/bad RSA-2048 sigs
    ├── x509-samples/                 # real DERs
    ├── jcs-bindings/                 # canonical JCS samples, UTF-8 including UK
    └── merkle-paths/                 # precomputed from flattener output
```

## Interface contract

Public signal order frozen in orchestration §2.2. Declaration digests (`declHashEN`, `declHashUK`) hard-coded in `DeclarationWhitelist.circom`, mirrored by web and contracts.

---

### Task 1: Package scaffold + circom_tester harness

- [ ] **Step 1** Create `packages/circuits/package.json` with deps: `circom_tester`, `circomlibjs`, `snarkjs`, `mocha`, `chai`, `@types/node`, `typescript`, `ts-node`. Script: `"test": "mocha -r ts-node/register 'test/**/*.test.ts' --timeout 120000"`.
- [ ] **Step 2** Install circom 2.1.x globally (script `scripts/install-circom.sh`) — document the pinned version.
- [ ] **Step 3** Write `test/helpers/compile.ts` wrapping `circom_tester.wasm` with caching under `build/test-cache/<circuitHash>/`.
- [ ] **Step 4** Minimal smoke circuit `circuits/_smoke.circom`:
  ```circom
  pragma circom 2.1.4;
  template Smoke() { signal input a; signal output b; b <== a + 1; }
  component main = Smoke();
  ```
  + `test/smoke.test.ts` asserting `b === a + 1`.
- [ ] **Step 5** Run: `pnpm --filter @qkb/circuits test`. Expected: 1 pass.
- [ ] **Step 6** Commit: `chore(circuits): circom_tester harness + smoke circuit`.

---

### Task 2: Vendor RSA-PKCS#1 v1.5 verify sub-circuit

- [ ] **Step 1** Pin `@zk-email/circuits` version. Copy `RsaVerifyPkcs1v15.circom` → `circuits/primitives/RsaPkcs1V15Verify.circom`. Document source commit SHA + license header at the top.
- [ ] **Step 2** Author `test/primitives/rsa.test.ts` with fixture `fixtures/rsa-vectors.json` (generate offline with `node:crypto`: one valid 2048-bit sig, one with flipped bit, one with wrong modulus). Fixture committed.
- [ ] **Step 3** Test assertions:
  - Valid vector: circuit accepts (no constraint failures).
  - Invalid sig: circuit `calculateWitness` throws.
  - Wrong modulus: throws.
- [ ] **Step 4** Run — expect pass. ~0.8–1.2M constraints per instance; use `--O2` in compile.
- [ ] **Step 5** Commit: `feat(circuits): RSA-PKCS#1 v1.5 2048 verify with test vectors`.

---

### Task 3: Poseidon chunked hash matching flattener

- [ ] **Step 1** Write failing `test/primitives/poseidon-chunk.test.ts`: given a byte vector, `PoseidonChunkHash` output equals `canonicalizeCertHash` from `@qkb/lotl-flattener` (run via child_process or duplicated TS helper). Use several byte lengths: 0, 31, 32, 500, 2000.
- [ ] **Step 2** Implement `circuits/primitives/PoseidonChunkHash.circom` — pack 31 bytes per field element, append length domain separator, absorb in Poseidon sponge (rate 15, capacity 1). Identical logic to flattener.
- [ ] **Step 3** Run — expect pass. Commit: `feat(circuits): Poseidon chunked hash matching flattener canonicalization`.

---

### Task 4: Variable-length SHA-256 wrapper

- [ ] **Step 1** Test in `test/primitives/sha256.test.ts`: circuit outputs matches `crypto.createHash('sha256')` over byte strings of varied lengths up to 2048. Also: reject lengths > MAX via constraint (test with length > MAX → witness throws).
- [ ] **Step 2** Implement `circuits/primitives/Sha256Var.circom` using `circomlib/circuits/sha256/sha256.circom`. Padded block selection constrained by `len`. Fixed `MAX_BYTES = 2048`.
- [ ] **Step 3** Run — expect pass. Commit: `feat(circuits): variable-length SHA-256 up to 2KB`.

---

### Task 5: Merkle inclusion (Poseidon)

- [ ] **Step 1** Test in `test/primitives/merkle.test.ts` using `merkle-paths/*.json` generated by flattener Task 7: verify accepts valid path; rejects tampered leaf, tampered indices, wrong root.
- [ ] **Step 2** Implement `circuits/primitives/MerkleProofPoseidon.circom` (depth 16) using `circomlib` Poseidon 2→1.
- [ ] **Step 3** Run, commit: `feat(circuits): Poseidon Merkle inclusion proof depth 16`.

---

### Task 6: X.509 ASN.1 slicer

- [ ] **Step 1** Test with real X.509 DER fixtures (from `fixtures/x509-samples/`): given DER bytes + declared offsets for `tbsCertificate`, `subjectPublicKeyInfo.modulus`, `signature`, `validity.notBefore`, `validity.notAfter`, `issuer` — circuit asserts slicing is consistent with DER TLV structure and extracts correct values.
- [ ] **Step 2** Implement `circuits/x509/X509Parse.circom` as a collection of templated slicers taking `(bytes, offset, length)` and enforcing that the byte at `offset - 2` is the expected ASN.1 tag. NOT a full ASN.1 parser — a constrained slicer that trusts prover-supplied offsets and verifies they land on tag boundaries.
- [ ] **Step 3** Companion `X509Validity.circom`: given extracted UTC time bytes + a `timestamp` public input, assert `notBefore ≤ timestamp ≤ notAfter`. Time format: GeneralizedTime `YYYYMMDDHHMMSSZ` only (reject UTCTime — all modern QES uses GeneralizedTime; document).
- [ ] **Step 4** Run, commit: `feat(circuits): X.509 slicer + validity window check`.

---

### Task 7: Binding JCS field parser

- [ ] **Step 1** Test with real JCS fixtures (from `fixtures/jcs-bindings/`, including Ukrainian declaration): circuit extracts `pk`, `ctx`, `declaration`, `scheme`, `timestamp` field values at the declared offsets; asserts fixed JSON template (`"pk":"`, `"scheme":"`, `"timestamp":`, etc. present in the exact canonical positions).
- [ ] **Step 2** Implement `circuits/binding/BindingParse.circom`. Strategy: worker supplies offsets per field; circuit checks the bytes at `offset - keyLen` equal the expected key literal; value runs until next `"` or `,`/`}` per field type. `MAX_B = 1024`.
- [ ] **Step 3** `DeclarationWhitelist.circom`: hard-coded SHA-256 digests of EN and UK canonical declarations. Assert extracted `declaration` bytes hash to one of them. Digests included in circuit as constants derived from `fixtures/declarations/{en,uk}.txt` — committed hashes must match.
- [ ] **Step 4** Run, commit: `feat(circuits): binding JCS parser + declaration whitelist`.

---

### Task 8: secp256k1 pk match

- [ ] **Step 1** Test `test/secp/pkmatch.test.ts`: given 64 bytes (32 x || 32 y) extracted from `Bcanon`, circuit packs into 4×64-bit limbs matching the public-signal layout. Mismatch throws.
- [ ] **Step 2** Implement `circuits/secp/Secp256k1PkMatch.circom`. Pure byte-to-limb packing + equality constraint. No point arithmetic.
- [ ] **Step 3** Run, commit: `feat(circuits): secp256k1 pk byte-to-limb equality check`.

---

### Task 9: Main circuit `QKBPresentation.circom` (wiring only)

**Blocks on:** Tasks 2–8 complete. Lead also must have delivered at least one end-to-end fixture at `fixtures/integration/ua-diia/` (parsed `.p7s`, binding.qkb.json, extracted cert chain, Merkle path). If missing, worker blocks and messages lead.

- [ ] **Step 1** Write `test/integration/positive.test.ts`: builds witness from `fixtures/integration/ua-diia/*` via `inputs/fixture-builder.ts`, runs `circom_tester.calculateWitness`, asserts public signals equal expected.
- [ ] **Step 2** Compose `QKBPresentation.circom` wiring all sub-circuits per spec §5.3 constraints (1)–(7). 13 public signals in the frozen order.
- [ ] **Step 3** Run — expect pass. Measure total constraints; commit constraint count to `build/constraint-report.txt`. If > 8M, message lead to trigger fallback split.
- [ ] **Step 4** Commit: `feat(circuits): main QKBPresentation circuit integration`.

---

### Task 10: Negative integration tests

- [ ] **Step 1** Write `test/integration/negative.test.ts` with cases:
  - tampered `Bcanon` byte → digest mismatch → witness throws
  - wrong `pk` → pk match constraint throws
  - intermediate not in Merkle root → path verify throws
  - declaration altered (typo) → whitelist throws
  - `timestamp` outside cert validity → validity throws
  - scheme string ≠ `"secp256k1"` → throws
- [ ] **Step 2** Run — all throws expected. Commit: `test(circuits): negative integration coverage`.

---

### Task 11: Ceremony scripts (Phase 1 / Phase 2)

- [ ] **Step 1** `ceremony/scripts/compile.sh`: runs `circom QKBPresentation.circom --r1cs --wasm --sym -o build/qkb-presentation`.
- [ ] **Step 2** `ceremony/scripts/setup.sh`: downloads pinned Powers of Tau (Hermez 2^24), runs `snarkjs groth16 setup` to produce `qkb.zkey`, then a documented `--name=dev` contribution as a placeholder. Production Phase 2 contributions documented in `ceremony/ceremony.md` (transcript to be expanded with real contributors before production; Phase 1 demo acceptable with single-contributor entropy from system RNG).
- [ ] **Step 3** `ceremony/scripts/export.sh`: exports `verification_key.json`, `QKBGroth16Verifier.sol`. Writes SHA-256 of `.zkey` to `build/qkb-presentation/zkey.sha256`.
- [ ] **Step 4** Run all three in CI (`reproducibility.yml`) and assert `zkey.sha256` matches a committed baseline (baseline updates only when ceremony is re-run intentionally).
- [ ] **Step 5** Commit: `feat(circuits): compile + setup + export ceremony scripts`.

---

### Task 12: Export artifacts to consumers

- [ ] **Step 1** Add build script that copies `Verifier.sol` → `packages/contracts/src/verifier/QKBGroth16Verifier.sol`, and `vkey.json` + `.wasm` + `.zkey` → `packages/web/public/circuits/` (or publishes as a `@qkb/circuits-artifacts` workspace package — prefer the latter for clean boundaries).
- [ ] **Step 2** Create `packages/circuits-artifacts/` sibling package exporting file paths + parsed `vkey`.
- [ ] **Step 3** Commit: `feat(circuits): publish artifacts package for contracts + web consumers`.

---

## Self-review checklist

- [ ] Every sub-circuit has a positive + at least one negative test.
- [ ] Public signal order in main matches orchestration §2.2 exactly.
- [ ] Constraint count committed and under budget (3–5M target, 8M hard cap).
- [ ] `.zkey` hash baseline committed.
- [ ] `Verifier.sol` compiles under `solc 0.8.24` (run `forge build` from contracts package sanity).
- [ ] No circuit uses `<--` without a matching `===` constraint (no unconstrained assignments).
