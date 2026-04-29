# QIE Phase 2 — Sprint 0 Circuits Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four Phase-1 circuit-side deviations before any QIE-core work starts — RSA variant, unified single-proof ECDSA, nullifier primitive, local ceremony ×2, R2 upload. Every downstream package depends on the 14-signal public layout that lands here.

**Architecture:** Two new main circuits (`QKBPresentationRsa.circom`, `QKBPresentationEcdsa.circom`) replace the Phase-1 leaf-only `QKBPresentationEcdsaLeaf`. Both share the nullifier sub-template. Both run full local ceremonies. Stubs land first for downstream integration.

**Tech Stack:** Circom 2.1.9, snarkjs, circomlib, `@zk-email/circuits`, `circom-ecdsa-p256`. Node 20. Local 48+ GB host. Cloudflare R2.

Spec reference: `docs/superpowers/specs/2026-04-17-qie-phase2-design.md` §14.

Worktree: `/data/Develop/qie-wt/circuits` (lead creates). Branch: `feat/qie-circuits`.

---

## File structure

```
packages/circuits/
  circuits/
    QKBPresentationEcdsa.circom      # NEW — unified leaf+chain, 14 signals
    QKBPresentationRsa.circom        # NEW — RSA variant, 14 signals
    QKBPresentationEcdsaStub.circom  # NEW — stub sibling matching new layout
    QKBPresentationRsaStub.circom    # NEW — stub sibling matching new layout
    primitives/
      NullifierDerive.circom         # NEW — secret = Poseidon(subject_serial, issuer_hash)
                                     #       nullifier = Poseidon(secret, ctxHash)
      X509SubjectSerial.circom       # NEW — extract subject.serialNumber from leaf DER
  ceremony/
    QKBGroth16VerifierEcdsa.sol      # output of ECDSA ceremony (committed)
    QKBGroth16VerifierRsa.sol        # output of RSA ceremony (committed)
    verification_key_ecdsa.json      # committed
    verification_key_rsa.json        # committed
    urls.json                        # NEW schema — keyed by variant (ecdsa | rsa)
    zkey.sha256                      # committed, both variants
  test/
    primitives/nullifier.test.ts     # NEW — Poseidon-based KAT
    primitives/x509-subject-serial.test.ts  # NEW — fixture-driven parse test
    integration/qkb-ecdsa-unified.test.ts   # NEW — E2E vs real Diia fixture
    integration/qkb-rsa.test.ts             # NEW — E2E vs synthetic RSA chain
    integration/nullifier-e2e.test.ts       # NEW — ctxHash → nullifier determinism
```

---

## Task 1: Nullifier primitive (pure circuit)

**Files:**
- Create: `circuits/primitives/NullifierDerive.circom`
- Create: `test/primitives/nullifier.test.ts`

- [ ] **Step 1: Failing test for `NullifierDerive`.** Fixture: known
  `subject_serial = [0x1234567890abcdef, 0, 0, 0]`, known
  `issuer_cert_hash = 0xdead...`, known `ctxHash`. Expected nullifier = computed off-circuit via `circomlibjs.poseidon([poseidon([serial...], issuer_hash), ctxHash])`. Assert circuit output matches.

- [ ] **Step 2: Implement `NullifierDerive`.**

```circom
pragma circom 2.1.9;
include "circomlib/circuits/poseidon.circom";

template NullifierDerive() {
    signal input subjectSerialLimbs[4];  // 4 × uint64 LE (matches pk encoding)
    signal input issuerCertHash;          // Poseidon of intermediate cert DER
    signal input ctxHash;                 // binding context
    signal output secret;
    signal output nullifier;

    component h1 = Poseidon(5);
    h1.inputs[0] <== subjectSerialLimbs[0];
    h1.inputs[1] <== subjectSerialLimbs[1];
    h1.inputs[2] <== subjectSerialLimbs[2];
    h1.inputs[3] <== subjectSerialLimbs[3];
    h1.inputs[4] <== issuerCertHash;
    secret <== h1.out;

    component h2 = Poseidon(2);
    h2.inputs[0] <== secret;
    h2.inputs[1] <== ctxHash;
    nullifier <== h2.out;
}
```

- [ ] **Step 3: Run, commit.**
```bash
pnpm -F @qkb/circuits test --run nullifier
git commit -m "feat(circuits): S0.1 NullifierDerive sub-circuit + KAT"
```

---

## Task 2: X509SubjectSerial extractor

**Files:**
- Create: `circuits/primitives/X509SubjectSerial.circom`
- Create: `test/primitives/x509-subject-serial.test.ts`
- Create: `fixtures/x509-samples/subject-serial-diia.fixture.json` (lead provides the raw cert DER)

- [ ] **Step 1: Failing test.** Given a leaf cert DER + offset into the subject sequence where `serialNumber` (OID `2.5.4.5`) attribute begins, extracts the value bytes. Vary across 3 fixtures: Diia (UA РНОКПП), Szafir (PL PESEL), EE-Test (EE Personal Code). Assert byte-array equality.

- [ ] **Step 2: Implement.** Analogous to Phase-1 `BindingParseFull` — use `Multiplexer` over the cert bytes with `selector = subjectSerialValueOffset`, length fixed at 10–20 bytes (all EU PII IDs fit in 20). Output: `subjectSerialLimbs[4]` packed as 4×64-bit LE (zero-padded if <32 bytes).

- [ ] **Step 3: Run, commit.**
```bash
pnpm -F @qkb/circuits test --run x509-subject-serial
git commit -m "feat(circuits): S0.2 X509SubjectSerial extractor + 3-country fixtures"
```

---

## Task 3: Stub circuits with 14-signal layout

**Files:**
- Create: `circuits/QKBPresentationEcdsaStub.circom`
- Create: `circuits/QKBPresentationRsaStub.circom`
- Create: `ceremony/scripts/stub-ceremony.sh` (extend to both variants)

- [ ] **Step 1: Implement both stubs.** Identical public-signal layout, trivial constraint (`linear combination of all inputs`). `component main {public [pkX, pkY, ctxHash, rTL, declHash, timestamp, algorithmTag, nullifier]}`. 14 signals total.

- [ ] **Step 2: Stub ceremony runs both variants.** Extend `stub-ceremony.sh`:
  ```bash
  for variant in ecdsa rsa; do
      circom QKBPresentation${variant^}Stub.circom --r1cs --wasm --sym ...
      snarkjs groth16 setup ...
      snarkjs zkey contribute ...
      snarkjs zkey export solidityverifier ...
      sed -i "s/contract Groth16Verifier/contract QKBGroth16VerifierStub${variant^}/" out/...
  done
  ```

- [ ] **Step 3: Commit both stub verifiers.** Downstream (contracts, web) needs these to unblock their Sprint 0 work before the real ceremony finishes.
```bash
git commit -m "feat(circuits): S0.3 dual-variant stub ceremony (14-signal layout)"
```

---

## Task 4: Unified ECDSA circuit `QKBPresentationEcdsa.circom`

**Files:**
- Create: `circuits/QKBPresentationEcdsa.circom`
- Create: `test/integration/qkb-ecdsa-unified.test.ts`

- [ ] **Step 1: Failing E2E test.** Reuse Phase-1 real Diia admin fixture. Witness now includes intermediate cert DER + its Merkle path under rTL + chain signature. Assert `circuit.calculateWitness(input, true)` + `checkConstraints` both pass.

- [ ] **Step 2: Implement unified circuit.** Combines Phase-1's
  `QKBPresentationEcdsaLeaf` + the never-shipped `QKBPresentationEcdsaChain`:
  1. BindingParseFull → extract (pk, scheme, ctx, decl, timestamp).
  2. Secp256k1PkMatch on (pk, pkX, pkY).
  3. sha256(Bcanon) → messageDigest slot of signedAttrs[mdOffsetInSA..+32].
  4. sha256(signedAttrs) → leafDigest.
  5. EcdsaP256Verify(leafDigest, leafSigR, leafSigS, leafSpkiXY) — **leaf**.
  6. sha256(leafTBS) → leafTbsDigest.
  7. EcdsaP256Verify(leafTbsDigest, intSigR, intSigS, intSpkiXY) — **chain**.
  8. PoseidonChunkHashVar(intDER, intDERLen) → intCertHash.
  9. MerkleProofPoseidon(intCertHash, path, rTL) — trusted-list membership.
  10. DeclarationWhitelist(declHash).
  11. PoseidonChunkHashVar(ctxBytes, ctxLen) → ctxHashOut, check == ctxHash.
  12. X509SubjectSerial(leafDER, offset, len) → subjectSerialLimbs.
  13. NullifierDerive(subjectSerialLimbs, intCertHash, ctxHash) → nullifier.

  Constraint budget estimate: ~10.5 M. Fits `performance-12x` (48 GB).

- [ ] **Step 3: Public signals (exactly the spec §14.3 layout).**
```circom
component main {public [pkX, pkY, ctxHash, rTL, declHash, timestamp, algorithmTag, nullifier]}
    = QKBPresentationEcdsa();
```
With `algorithmTag` pinned to `1` (ECDSA) as a constant constraint inside the template.

- [ ] **Step 4: Run, commit.**
```bash
pnpm -F @qkb/circuits test --run qkb-ecdsa-unified
git commit -m "feat(circuits): S0.4 unified ECDSA circuit — 14 signals, ~10.5M constraints"
```

---

## Task 5: RSA circuit `QKBPresentationRsa.circom`

**Files:**
- Create: `circuits/QKBPresentationRsa.circom`
- Create: `test/integration/qkb-rsa.test.ts`
- Create: `scripts/build-rsa-fixture.ts` (produces a synthetic RSA chain per `build-synth-rsa-fixture.ts` precedent)

- [ ] **Step 1: Failing E2E test** against synthetic RSA fixture (pkijs-generated 2048-bit modulus chain signing a binding with the same Bcanon shape as Diia).

- [ ] **Step 2: Implement RSA circuit.** Same structure as ECDSA but substitutes `RsaPkcs1V15Verify` (from `@zk-email/circuits`) for the leaf + chain verify steps. Uses `RsaSpkiExtract2048` from Phase 1. `algorithmTag = 0` constant.

  Constraint budget estimate: ~6.5 M (RSA-2048 verify is cheaper than ECDSA-P256; two of them + chain Merkle ≈ 6.5 M). Fits a 40 GB host comfortably.

- [ ] **Step 3: Public signals match §14.3.** `algorithmTag = 0`.

- [ ] **Step 4: Run, commit.**
```bash
pnpm -F @qkb/circuits test --run qkb-rsa
git commit -m "feat(circuits): S0.5 RSA variant — 14 signals, ~6.5M constraints"
```

---

## Task 6: Local ceremony — ECDSA variant

- [ ] **Step 1: Extend `ceremony/scripts/setup.sh`** (or add a sibling
  `setup-variant.sh`) to take a variant argument (`ecdsa` | `rsa`) and
  target the matching `.r1cs`.

- [ ] **Step 2: Run ceremony.** Local 48+ GB host:
  1. `fetch-ptau.sh` to pull ptau 2^24 (~18 GB).
  2. `snarkjs groth16 setup` under tmux. `NODE_OPTIONS='--max-old-space-size=45056'`.
  3. `snarkjs zkey contribute` (dev contribution; the production contribution ceremony with external participants is Phase 3).
  4. `snarkjs zkey export verificationkey + solidityverifier`.
  5. `sha256sum qkb.zkey > zkey_ecdsa.sha256`.

- [ ] **Step 3: Local round-trip.** `snarkjs groth16 fullprove` against the
  real Diia fixture input.json, `groth16 verify` locally. Must print `OK!`.

- [ ] **Step 4: Upload to R2.** Bucket `proving-1`, keys
  `QKBPresentationEcdsa.wasm` + `qkb_ecdsa.zkey`. Domain
  `prove.identityescrow.org` already bound.

- [ ] **Step 5: Commit.**
```bash
git commit -m "feat(circuits): S0.6 real ECDSA unified ceremony — local host, zkey on R2"
```

---

## Task 7: Local ceremony — RSA variant

Same as Task 6 but for the RSA circuit. Smaller; 40 GB is enough.

- [ ] **Commit.** `feat(circuits): S0.7 real RSA ceremony — local host, zkey on R2`.

---

## Task 8: Update `ceremony/urls.json` schema

**Files:**
- Modify: `packages/circuits/ceremony/urls.json`
- Modify: `packages/circuits/ceremony/zkey.sha256`

- [ ] **Step 1:** Schema becomes:
```json
{
  "ecdsa": { "wasmUrl": "...", "zkeyUrl": "...", "wasmSha256": "...", "zkeySha256": "...", "wasmBytes": ..., "zkeyBytes": ..., "ceremony": { ... } },
  "rsa":   { "wasmUrl": "...", "zkeyUrl": "...", "wasmSha256": "...", "zkeySha256": "...", "wasmBytes": ..., "zkeyBytes": ..., "ceremony": { ... } }
}
```

- [ ] **Step 2: Commit.**
```bash
git commit -m "feat(circuits): S0.8 urls.json schema — per-variant ceremony artifacts"
```

---

## Task 9: CLAUDE.md update

- [ ] **Step 1:** Extend `packages/circuits/CLAUDE.md` with §§:
  - Sprint-0 amendment summary (what changed, why).
  - Two-variant ceremony procedure (run both or one).
  - Local ceremony procedure documented as canonical.
  - Nullifier primitive explainer + privacy implications.

- [ ] **Step 2: Commit.** `docs(circuits): S0.9 CLAUDE.md — variants + local ceremony + nullifier`.

---

## Self-review checklist (worker runs before requesting final review)

- [ ] All 14 public signals exposed in the order specified in spec §14.3.
- [ ] `algorithmTag` is a CONSTANT in each variant's main template, not a witness-supplied value (prevents a malicious prover from swapping).
- [ ] `nullifier` is covered by at least one KAT + one E2E test that asserts determinism across two different context values.
- [ ] Both ceremonies ran on the local 48+ GB host and local-verify passes.
- [ ] Both `.zkey` + `.wasm` on R2 and `urls.json` sha256 matches on-disk sha256.
- [ ] No committed `.zkey` files (>100 MB blob rejected by GitHub).
- [ ] `ceremony/QKBGroth16Verifier{Ecdsa,Rsa}.sol` forge-compile clean.
