# V5 Architecture Design

**Status:** Brainstorming complete · Spec review pass 5 applied (envelope reconcile + mobile-feasibility update + frontend hosting lean) · Awaiting user spec review
**Date:** 2026-04-29
**Predecessor:** [V4 Sepolia deployment](../../../fixtures/contracts/sepolia.json) — to be deprecated.
**Sub-project of:** Path A (Pragmatic full ship of identity-escrow to production).
**Revision history:**
- v1 (2026-04-29): initial brainstorm output.
- v2 (2026-04-29): incorporated external review pass 1 — five findings (trust-list binding, CAdES digest separation, nullifier-uniqueness, policy root enforcement, multi-limb public encoding for 256-bit hashes).
- v3 (2026-04-29): incorporated external review pass 2 — three findings (policy leaf field-reduction undefined, `declHash` vs `policyLeafHash` regression to legacy binding model, mixed SPKI hash semantics between circuit limb-Poseidon and contract byte-Poseidon). All three fix wire-format ambiguity.
- v4 (2026-04-29): incorporated external review pass 3 — two findings (policyLeafHash construction was specified over raw declaration text, not the QKB/2.0 structured `JCS(policyLeafObject)`; stale `Poseidon(intSpki)` references in calldata description, contract field comment, and migration prose conflicted with the canonical `SpkiCommit(intSpki)` defined elsewhere in the same spec). Both fixes close consistency drift; the on-the-wire data-model now matches the QKB/2.0 policy-root spec exactly.
- v4.1 (2026-04-29): doc-only cleanup from external review pass 4. The summary diagram + "Key shift" prose still showed a 3-gate model with "intermediateCert in trustedListRoot" wording; updated to the 5-gate model already implemented in §Data flow with explicit `SpkiCommit(intSpki)` and `policyLeafHash` Merkle gates. `BindingParseV2Core` component description updated to reference the QKB/2.0 `policy.leafHash` field instead of legacy `decl`. No semantic changes; closes summary-vs-detail drift.
- v5 (2026-04-29): post-implementation reconciliation. Three sub-sections (`§Estimated zkey size`, `§Acceptance criteria`, `§Risks`) carried stale numbers from the original ~1.1M-constraint projection; §Circuit body had already been amended to the empirical ~4.0M / 4.5M-cap envelope across `b8e0f74` (1.85M→3M) and `77ed00d` (3M→4.5M), but the consequent zkey/prove-time/acceptance numbers were never propagated to the dependent sections. Pass 5 reconciles: zkey size 250-350 MB → 2.0-2.4 GB; acceptance ≤1.5M / ≤500 MB → ≤4.5M / ≤2.5 GB; "Constraint estimate overshoot" risk marked **MATERIALIZED + closed** with empirical analysis. **Mobile-browser is now a hard acceptance gate**, narrowed to flagship 2024+ phones (Pixel 9, iPhone 15) with `navigator.storage.persist()` granted; below-the-bar devices (mid-range Android, iOS WebView, <8 GB RAM, older browsers) must be detected by the frontend and rerouted to a "use desktop" page BEFORE zkey download. Path B (TEE-delegated) remains the post-A1 expansion for out-of-gate devices. Frontend hosting decided: **GitHub Pages**, with a documented Cross-Origin-Isolation caveat for multithreaded snarkjs proving (service-worker COOP/COEP shim available; single-threaded fallback acceptable). Phase 2 ceremony hardware updated for ~4M-constraint footprint. No semantic changes to the design — number-truth reconciliation + one explicit gate-tightening (mobile gated, not just validated).

---

## Summary

Shrink the QKB ZK proof from 6.54M constraints to ~1M by moving ECDSA-P256 verification from inside the circuit to a contract-side EIP-7212 precompile call. Collapse the existing two-circuit split (`QKBPresentationEcdsaLeaf` + `QKBPresentationEcdsaChain`) into a single circuit. Drop RSA scaffolding. Target Base mainnet exclusively. The result: ~250-350 MB zkey, sub-30s mobile prove time, browser-feasible proving without a native app.

This is **A1** in the broader Path A delivery: A1 (this spec) → A2 (mobile/browser frontend) → A3 (audit + Base mainnet deploy) → A4 (operational launch).

## Goal

Enable Ukrainian users to mint a verified-citizen ERC-721 certificate using only a web browser (desktop or mobile), without installing a CLI or native app, while preserving the privacy and soundness guarantees of the V4 architecture.

Non-goals:
- RSA QES support (deferred — no real test material, no EU QTSP partner today).
- Multi-chain deploy (Base only for V1).
- Mobile native app (skipped because shrunken circuit + EIP-7212 makes browser proving feasible).
- Server-assisted / TEE-delegated proving (the Path B fallback — not needed if A1 ships).

## Architecture

Three-layer trust composition. Each layer has independent verification; all three must pass for `register()` to succeed.

```
┌─────────────────────────┐
│ User: Diia QES (.p7s)   │  Off-chain: cert + sig
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Browser/CLI prover       │  Generate ZK proof + collect calldata
│  • Canonicalize binding  │
│  • Build witness         │
│  • snarkjs prove         │
└────────────┬────────────┘
             │
             ▼ register() tx
┌─────────────────────────┐
│ Smart contract (Base)    │  Five-gate verification:
│  ① Groth16Verifier        │   • ZK proof: binding parse + nullifier + commits
│  ② EIP-7212 (P-256) ×2   │   • ECDSA: leaf signed signedAttrs
│                          │   • ECDSA: intermediate signed leafTBS
│  ③ MerkleVerify (trust)   │   • SpkiCommit(intSpki) ∈ trustedListRoot
│  ④ MerkleVerify (policy)  │   • policyLeafHash ∈ policyRoot
│  ⑤ replay + timing        │   • nullifier ∉ registrantOf, age ≤ MAX_BINDING_AGE
│  → store nullifierOf      │
└─────────────────────────┘
```

**Key shift from V4:** the proof is no longer the sole verification gate. Five independent gates, all must pass:

1. **ZK proof (small)** — proves the user knows canonical-form binding bytes whose hash and signed-attrs digest the proof commits to, derived nullifier is correct, SPKIs hash to commits, signedAttrs.messageDigest equals bindingHash.
2. **EIP-7212 native ECDSA verification** — contract checks signature math directly (~3500 gas/call, two calls per register: leaf-over-signedAttrs and intermediate-over-leafTBS).
3. **Trust-list MerkleVerify** — contract checks `SpkiCommit(intSpki)` is a leaf in `trustedListRoot` (i.e., the verifying intermediate's signing key is from an authorized QTSP).
4. **Policy MerkleVerify** — contract checks `policyLeafHash` is a leaf in `policyRoot` (the binding's declared QKB/2.0 policy is one this registry accepts).
5. **Replay + timing** — both `nullifierOf[msg.sender] == 0` AND `registrantOf[nullifier] == address(0)`; binding `timestamp` within `MAX_BINDING_AGE`.

## Components

### Retained (existing, edits)

- `IQKBRegistry.sol` — ABI-stable interface across V4 and V5. Third-party SDK consumers (the `Verified` modifier in `@qkb/contracts-sdk`, etc.) work unchanged.
- `IdentityEscrowNFT.sol` — unchanged. Reads `nullifierOf` via `IQKBRegistry`. New deploy points at V5 instead of V4.
- `@qkb/contracts-sdk` — unchanged interface.
- `@qkb/sdk` (browser/CLI prover) — significant rewrite for V5 ABI and prove flow, but same overall purpose.
- `@qkb/cli` — updated to V5 prove + register flow.

### New

- `QKBRegistryV5.sol` — new contract; ABI-stable for `IQKBRegistry`, but `register()` ABI completely new (takes ECDSA inputs for EIP-7212).
- `QKBPresentationV5.circom` — single new circuit (replaces leaf + chain).
- `Groth16VerifierV5.sol` — auto-generated by snarkjs after the new ceremony.
- `lib/P256Verify.sol` — wraps EIP-7212 P-256 precompile + DER-SPKI parsing.
- `lib/PoseidonMerkle.sol` — Poseidon-based Merkle verification (vendored from iden3 or rolled).

### Retired

- `QKBPresentationEcdsaChain.circom` — collapsed into single V5 circuit.
- `QKBPresentationRsaStub.circom` + RSA verifier slots in registry — cut entirely.
- The 4.2 GB V4 zkey — replaced by ~250-350 MB V5 zkey.
- V4 leaf + chain Solidity verifiers — replaced by V5 verifier.

## Data flow — `register()` step by step

### 1. Off-chain (browser/CLI)

User signs Diia QES. Resulting artifacts: `.p7s` containing leaf cert, intermediate cert, signedAttrs, ECDSA-P256 signature. Browser/CLI also has a current Merkle proof for the intermediate cert from `trustedListRoot` (fetched from R2 or self-built).

The prover builds:

```
Public signals (committed by ZK proof, 14 field elements):

  Identity / context (3 signals — each fits in a single BN254 field):
    - msgSender                          (≤160 bits, packed in 1 field)
    - timestamp                          (1 field, ≤64 bits)
    - nullifier                          (1 field — Poseidon output)

  256-bit hashes split into hi/lo 128-bit limbs (4 hashes × 2 = 8 signals):
    - ctxHashHi, ctxHashLo               (2 — binding context)
    - bindingHashHi, bindingHashLo       (2 — SHA-256 of canonical binding bytes)
    - signedAttrsHashHi, signedAttrsHashLo (2 — SHA-256 of CAdES signedAttrs)
    - leafTbsHashHi, leafTbsHashLo       (2 — SHA-256 of leaf cert TBS)

  Field-domain values (already in BN254, 1 signal):
    - policyLeafHash                     (1 — uint256(sha256(JCS(policyLeafObject))) mod p,
                                              per QKB/2.0 policy-root spec; commits to the
                                              structured object {policyId, policyVersion,
                                              bindingSchema, contentHash, metadataHash}, NOT
                                              raw declaration text)

  SPKI commitments (Poseidon over X/Y limbs, 2 signals):
    - leafSpkiCommit                     (= SpkiCommit(leafSpki); see definition below)
    - intSpkiCommit                      (= SpkiCommit(intSpki))

Circuit-internal soundness constraints (not exposed):
  - signedAttrs.messageDigest_field == bindingHash
    (Parser walks DER-encoded signedAttrs, locates `messageDigest` SignedAttribute,
     equality-checks against bindingHash. CAdES requires this binding.)

Calldata-only inputs (NOT in proof; contract verifies them directly):
  - leafSpki          (raw 91-byte SubjectPublicKeyInfo DER from leaf cert)
  - intSpki           (raw 91-byte SubjectPublicKeyInfo DER from intermediate)
  - signedAttrs       (DER-encoded bytes leaf cert signed)
  - leafSig           (r, s — leaf ECDSA signature over SHA-256(signedAttrs))
  - intSig            (r, s — intermediate ECDSA signature over leafTbsHash)
  - merklePath        (16 sibling hashes from SpkiCommit(intSpki) to trustedListRoot)
  - merklePathBits    (which side at each level)
  - policyPath        (16 sibling hashes from policyLeafHash leaf to policyRoot)
  - policyPathBits    (which side at each level)
```

**`leafTbs` (raw bytes) is NOT in calldata.** It stays in the witness. The circuit computes `leafTbsHash = sha256(leafTbs)` and commits to it (as hi/lo limbs). Contract uses the committed hash directly with EIP-7212. This preserves V4's privacy property: nothing on-chain identifies the user beyond the nullifier.

**`intCertHash` is NOT used.** Trust-list leaves are `SpkiCommit(intSpki)` (canonical SPKI commit, defined below) — i.e., the trust assertion is "this signing key is from an authorized QTSP." This binds the Merkle gate to the same `intSpki` that EIP-7212 verifies AND to the same value the circuit commits to in `intSpkiCommit`, closing the soundness gap that would otherwise let an attacker pair a self-controlled signing key with an unrelated trusted-list entry.

**Two distinct SHA-256 digests, not one.** Per CAdES (RFC 5652 / EN 319 122):
- The user's leaf cert signs `SHA-256(DER-encoded signedAttrs)` → `signedAttrsHash`.
- Inside `signedAttrs`, the `messageDigest` SignedAttribute equals `SHA-256(binding)` → `bindingHash`.
- Circuit constrains `messageDigest_field == bindingHash`. Contract verifies EIP-7212 with `signedAttrsHash` (NOT `bindingHash`).

**Canonical SPKI commit function — `SpkiCommit(spki)`.** A single function used uniformly by circuit, contract, and flattener:

```
SpkiCommit(spki) := Poseidon₂(
    Poseidon₆( spki.X_as_6×43bit_LE_limbs ),
    Poseidon₆( spki.Y_as_6×43bit_LE_limbs )
)
```

where `spki.X` and `spki.Y` are the 32-byte coordinates of the P-256 public key extracted from the DER-encoded SubjectPublicKeyInfo, decomposed as `Bytes32ToLimbs643` (the M11-hardened limb encoding with explicit `<p` constraints).

- The **circuit** computes `leafSpkiCommit` and `intSpkiCommit` from the witness X/Y limbs as outputs.
- The **contract** uses `P256Verify.spkiCommit(spki)` (parses DER, decomposes to limbs, runs Poseidon) and compares against the proof's commits.
- The **flattener** (`packages/lotl-flattener`) populates the trust-list Merkle tree by computing `SpkiCommit(intSpki)` for each authorized intermediate's public key.

This binds the trust-list Merkle gate, the proof-binding check (gate 2a), and EIP-7212 to the **same canonical commitment of the same key**. No "two flavors of `poseidon(spki)`."

**Policy leaf is field-domain, not hi/lo.** Per the [QKB/2.0 policy-root spec](2026-04-23-qkb-binding-v2-policy-root.md), policy Merkle leaves are `uint256(sha256(JCS(policyLeafObject))) mod p` — already a single BN254 field element. The `policyLeafObject` is a structured JSON object with `{policyId, policyVersion, bindingSchema, contentHash, metadataHash}` (per §3 of the QKB/2.0 spec), JCS-canonicalized before hashing. The circuit exposes `policyLeafHash` as a 1-field-element public signal (matching the existing parser's output, which is `policyLeafHash`, not `declHash`). No hi/lo limb split for this value — it crosses the BN254 boundary cleanly because the field reduction was done at construction time.

**The flattener / policy-list builder must compute leaves identically.** Bytes-equivalent JCS canonicalization of the structured object, then SHA-256, then `mod p` reduction. A divergence at any of these three steps produces a different leaf value and the proof's `policyLeafHash` won't match any leaf in `policyRoot`. Foundry / E2E tests must verify round-trip parity between the off-chain policy-list builder and the circuit's parser output.

### 2. On-chain — `QKBRegistryV5.register()`

```solidity
function register(
    Groth16Proof calldata proof,
    PublicSignals calldata sig,             // 14 public signals
    bytes calldata leafSpki,
    bytes calldata intSpki,
    bytes calldata signedAttrs,
    bytes32[2] calldata leafSig,            // (r, s)
    bytes32[2] calldata intSig,
    bytes32[16] calldata merklePath,        // for trustedListRoot
    uint256 merklePathBits,
    bytes32[16] calldata policyPath,        // for policyRoot
    uint256 policyPathBits
) external {
    // Gate 1: ZK proof.
    require(groth16Verifier.verifyProof(proof, sig.toArray()), "BAD_PROOF");

    // Gate 2a: bind proof commits to provided calldata.
    // SHA-256 of signedAttrs split into hi/lo, equality-checked against public signals.
    bytes32 saHash = sha256(signedAttrs);
    require(uint256(saHash) >> 128              == sig.signedAttrsHashHi, "BAD_SA_HI");
    require(uint256(saHash) & type(uint128).max == sig.signedAttrsHashLo, "BAD_SA_LO");

    // Canonical SpkiCommit — see §Data flow for definition. Reused for trust-list gate.
    uint256 leafSpkiCommitVal = P256Verify.spkiCommit(leafSpki);
    uint256 intSpkiCommitVal  = P256Verify.spkiCommit(intSpki);
    require(leafSpkiCommitVal == sig.leafSpkiCommit, "BAD_LEAF_SPKI");
    require(intSpkiCommitVal  == sig.intSpkiCommit,  "BAD_INT_SPKI");

    // Gate 2b: ECDSA via EIP-7212 P256VERIFY precompile.
    // Leaf signed signedAttrs (CAdES binding-sig); contract uses signedAttrsHash, NOT bindingHash.
    require(P256Verify.verifyWithSpki(
        leafSpki,
        _packHash(sig.signedAttrsHashHi, sig.signedAttrsHashLo),
        leafSig
    ), "BAD_LEAF_SIG");
    // Intermediate signed leafTbs; leafTbsHash is from public signals (leafTbs never on-chain).
    require(P256Verify.verifyWithSpki(
        intSpki,
        _packHash(sig.leafTbsHashHi, sig.leafTbsHashLo),
        intSig
    ), "BAD_INT_SIG");

    // Gate 3: trust list membership. Merkle leaves = SpkiCommit(intSpki); reuse the value.
    require(PoseidonMerkle.verify(
        bytes32(intSpkiCommitVal), merklePath, merklePathBits, trustedListRoot
    ), "BAD_TRUST_LIST");

    // Gate 4: policy acceptance — policyLeafHash already field-reduced (single signal).
    require(PoseidonMerkle.verify(
        bytes32(sig.policyLeafHash), policyPath, policyPathBits, policyRoot
    ), "BAD_POLICY");

    // Gate 5: timing + sender + replay (both directions).
    require(sig.timestamp >= block.timestamp - MAX_BINDING_AGE, "STALE_BINDING");
    require(sig.msgSender == uint256(uint160(msg.sender)),     "BAD_SENDER");
    require(nullifierOf[msg.sender]      == 0,                  "ALREADY_REGISTERED");
    require(registrantOf[sig.nullifier]  == address(0),         "NULLIFIER_USED");

    // Commit.
    nullifierOf[msg.sender] = sig.nullifier;
    registrantOf[sig.nullifier] = msg.sender;
    emit Registered(msg.sender, sig.nullifier, block.timestamp);
}

/// @dev pack 128-bit hi + 128-bit lo public-signal pair into a bytes32.
function _packHash(uint256 hi, uint256 lo) internal pure returns (bytes32) {
    return bytes32((hi << 128) | (lo & type(uint128).max));
}
```

### 3. Calldata + gas budget

| Component | Bytes |
|-----------|-------|
| Groth16 proof | 256 |
| 14 public signals (32 bytes each) | 448 |
| leafSpki + intSpki (~91 bytes each) | ~200 |
| signedAttrs | ~100-200 |
| 2× ECDSA sigs | 128 |
| trust list merklePath + bits | 520 |
| policy merklePath + bits | 520 |
| **Total calldata** | **~2.2-2.4 KB** |

Estimated gas (Base mainnet):

- Groth16 verify: ~250K
- 2× p256Verify (EIP-7212): ~7K total
- 1× sha256(signedAttrs): ~5K
- 2× spkiCommit (Poseidon₆ ×2 + Poseidon₂ per call): ~60K total. Reused for trust-list Merkle leaf — no double cost.
- 2× 16-deep Poseidon Merkle (trust + policy): ~60K
- Storage writes (`nullifierOf` + `registrantOf`): ~44K
- Misc ops: ~15K
- **Total: ~440-490K gas** ≈ $0.20-0.45 USD on Base. Higher than v2 estimate because `spkiCommit` is full Poseidon-on-EVM, not a cheap byte-hash. Acceptance budget bumps from 500K to 600K.

## Circuit — `QKBPresentationV5.circom`

### Components retained (essential for soundness)

| Component | Constraints | Job |
|-----------|-------------|-----|
| `BindingParseV2CoreFast` | ~1.05M | Walks canonical QKB/2.0 binding bytes (single-pass Decoder amortization, MAX_BCANON=1024); locates `@context`, `timestamp`, `ctx`, and the `policy.leafHash` field (the field-domain `policyLeafHash` per QKB/2.0 §3); exposes them as constrained signals |
| `Sha256Var(MAX_BCANON)` + `Sha256CanonPad` | ~880K | Produces `bindingHash` (= SHA-256 of canonical binding bytes); 16 SHA blocks at 1024 B + per-byte block-index mux for variable-length |
| `Sha256Var(MAX_SA)` + `Sha256CanonPad` | ~1.28M | Produces `signedAttrsHash` (= SHA-256 of CAdES signedAttrs DER); 24 SHA blocks at 1536 B (real Diia 1388 B); largest single SHA in the circuit |
| `Sha256Var(MAX_LEAF_TBS)` + `Sha256CanonPad` | ~880K | Produces `leafTbsHash` (= SHA-256 of leaf cert TBSCertificate); 16 SHA blocks at 1024 B |
| `Sha256Var(MAX_CTX)` + `Sha256CanonPad` | ~280K | Produces public-domain `ctxHash` (= SHA-256 of ctxBytes for hi/lo public signals; nullifier path uses Poseidon-domain ctxHash separately via NullifierDerive); 4 SHA blocks at 256 B |
| `SignedAttrsParser(MAX_SA)` | ~180K | Walks signedAttrs DER, locates `messageDigest` SignedAttribute, equality-constrains it to `bindingHash` (closes the CAdES binding); O(MAX_SA) byte-window scan |
| `X509SubjectSerial(MAX_CERT)` | ~100K | Locates OID 2.5.4.5; extracts `PNOUA-…` identifier |
| `NullifierDerive` | ~5K | Poseidon₅ + Poseidon₂ |
| Poseidon SPKI commits ×4 | ~8K | `Poseidon(6)` over X/Y limbs + `Poseidon(2)` to combine, for both certs |
| `Bytes32ToHiLo` ×4 | ~4K | Decomposes each 256-bit SHA-256 hash output (ctxHash, bindingHash, signedAttrsHash, leafTbsHash) into 2 × 128-bit field elements (M11-hardened with `<p` checks). `policyLeafHash` is already field-domain — no decomposition needed. |
| `Secp256k1PkMatch` + `Keccak256(uncompressedPk)` | ~150K | Binds proof to `msg.sender`. `Secp256k1PkMatch` packs `parser.pkBytes ↔ pkX/pkY` 4×64-bit LE limbs (~50K); `Keccak256` over the 64-byte uncompressed pk produces a 32-byte digest whose low 160 bits are equality-constrained to the `msgSender` public signal (~100K, vendored from `@zk-email/keccak256-circom`). Without the keccak link, a stolen `.p7s` could be replayed under any wallet — `msgSender` would be unconstrained vs. the binding's `pkBytes`. |
| `leafTbs ↔ leafCert` byte-consistency | ~100-300K | Asserts the leafCert bytes used by `X509SubjectSerial` match the leafTbs bytes hashed by `Sha256Var(MAX_LEAF_TBS)` |
| Slack / glue | ~50K | |
| **Total** | **~4.0M** (cap **4.5M**) | |

**Constraint count delta vs. v1 spec:** +200K from signedAttrs hashing + parser + extra hi/lo decompositions, then +550K from raising `MAX_SA` 256→1536 once real Diia signedAttrs was measured at 1388 B (the pre-measurement assumption "50-150 bytes" treated CAdES-BES as canonical; the CAdES-X-L profile Diia actually emits is ~10× larger), then +700K from raising `MAX_BCANON` 768→1024 and the V2Core implementation reality (V2CoreLegacy measured 2.62M; V2CoreFast single-pass Decoder amortization brought it back to ~1.05M, a 2.49× shrink — see circuits-eng §6.0a), then +1.4M from correcting the per-`Sha256Var` cost estimate from the original ~250K-per-chain to the empirical ~880K-per-chain at MAX≈1024 B (variable-length wrapper plus per-byte block-index mux scales near-linearly in MAX), then +100K from §6.8 vendoring `@zk-email/keccak256-circom` inline (closes the `msg.sender` soundness gap V4's `Secp256k1PkMatch` left open — `msgSender` was otherwise unconstrained vs. `parser.pkBytes`, allowing `.p7s` replay under any wallet; the ~50K original budget for `Secp256k1PkMatch` alone assumed a binding scheme that didn't materialize). Empirical post-§6.7 measurement is **3.57M** (circuits-eng `snarkjs r1cs info`); §6.8 + §6.9 + §6.10 close-out projects the final at **~3.8-4.0M**. The circuit budget envelope is set at **4.5M constraints** with ~12-25% headroom. Final zkey targets ~2.0-2.4 GB. Browser proving remains feasible (V4 chain proof was already ~600 MB and demonstrably ran in-browser; modern Chrome handles ~4 GB memory pressure for snarkjs Web Worker proving); prove time projects to 8-12 s. **Future optimization (V5.1 candidate, NOT in A1 scope):** moving any of the three large in-circuit SHA chains (binding / signedAttrs / leafTbs) off-circuit and replacing the public commitment with `PoseidonChunkHashVar` over the bytes saves ~880K-1.28M per chain at the cost of an ABI-level public-signal layout change, a new Solidity Poseidon-over-bytes primitive, and additional audit surface; deferred to a post-A1 sub-project once the V5 baseline ships and any browser-UX complaints actually materialize.

### Components removed

- `EcdsaP256Verify` — was 4-5M, now in EIP-7212.
- `MerkleProofPoseidon(depth=16)` — was 50-100K, now in `PoseidonMerkle.sol`.
- `DobExtractor` — was 200-500K. Identity proof and age proof split: `QKBPresentationAgeV4.circom` keeps DOB extractor for the age claim only.

### MAX bound retightening

- `MAX_BCANON`: 1024 (real Diia QKB/2.0 admin-ecdsa binding measured 849 B post-impl; the pre-measurement estimate "200-400 byte typical" was wrong because it assumed a smaller QKB/1.0-style schema. 1024 leaves ~21% headroom).
- `MAX_CERT`: 2048 (real Diia leaf cert ~1.2-1.6 KB).
- `MAX_SA`: 1536 (real Diia admin-ecdsa signedAttrs measured 1388 B post-impl: ETSI EN 319 122 CAdES with `id-aa-ets-signerLocation` + `id-aa-signing-certificateV2` attributes mandates ~1300 B; the pre-measurement estimate "50-150 bytes" was wrong because it implicitly assumed CAdES-BES rather than the CAdES-X-L profile Diia actually emits. 1536 leaves ~10% headroom).
- `MAX_LEAF_TBS`: 1024 (real Diia leaf TBS ~700-900 bytes).

### Public signal layout (14 field elements)

```circom
component main {public [
    msgSender,
    timestamp,
    nullifier,
    ctxHashHi, ctxHashLo,
    bindingHashHi, bindingHashLo,
    signedAttrsHashHi, signedAttrsHashLo,
    leafTbsHashHi, leafTbsHashLo,
    policyLeafHash,
    leafSpkiCommit,
    intSpkiCommit
]}
```

Two encoding regimes coexist:

- **256-bit SHA-256 digests** (`ctxHash`, `bindingHash`, `signedAttrsHash`, `leafTbsHash`) are exposed as two 128-bit limbs (`hi` = bits[0..127], `lo` = bits[128..255]). The contract reconstructs `bytes32` via `(hi << 128) | lo` before passing to EIP-7212 / equality-checking against `sha256(calldata)`.
- **Field-domain values** (`policyLeafHash`, `leafSpkiCommit`, `intSpkiCommit`, `nullifier`) are exposed as a single field element. They are constructed in the field domain at the source: `policyLeafHash = uint256(sha256(...)) mod p` per QKB/2.0; `leafSpkiCommit`/`intSpkiCommit` are `SpkiCommit(spki)` Poseidon outputs; `nullifier` is `Poseidon₂` output. No hi/lo split.

(Final ordering may shift to match snarkjs ABI conventions; settled in implementation plan. The encoding regime per signal is fixed.)

### Estimated zkey size

**~2.0-2.4 GB**, down from 4.2 GB (V4). Drives a different mobile/desktop split than the original 250-350 MB projection assumed:

- **Desktop browser (Chromium / Firefox / Safari):** loadable in a Web Worker. Linear memory stays under the WASM-32 4 GB cap. Tab-level cache via OPFS or IndexedDB available with `navigator.storage.persist()`. V4's ~600 MB chain proof already ran in-browser; the V5 zkey is ~3-4× larger but still within desktop budget. **Primary V1 user flow.**
- **Mobile browser — flagship-phones only, gated.** Pixel 9 / Galaxy S24 / iPhone 15 with iOS 17+ and `navigator.storage.persist()` granted have the disk quota (Chrome Android: ~60% of free disk when persisted; Safari iOS 17+: ~20% of disk per origin) and the WASM Web Worker memory budget (16+ GB RAM phones) to host a 2.4 GB zkey. **Below the bar — mid-range Android (50-200 MB quotas) and iOS in-app WebViews (1 GB cap) — fail by design.** Frontend MUST detect the device class up-front, prompt for `persist()`, and route below-the-bar users to a "use desktop" message rather than letting them start a download that will OOM their browser.
- **Out-of-bar fallback:** WalletConnect from a desktop-proven session is the V1 path for non-flagship phones. Path B (TEE-delegated rapidsnark prover) is the post-A1 expansion — adds a trust delta, but unlocks every phone.

Compared to V4 (4.2 GB), the V5 zkey is 40-50% smaller, browser-feasible on desktop without OPFS streaming workarounds, and downloadable on a normal home connection in 1-3 minutes. Future optimization (V5.1) — moving any of the three large in-circuit SHA chains off-circuit — is flagged in §Circuit but explicitly out of A1 scope.

## Contracts

### `QKBRegistryV5.sol`

```solidity
contract QKBRegistryV5 {
    IGroth16Verifier public immutable groth16Verifier;
    address public admin;
    bytes32 public trustedListRoot;          // Merkle root over SpkiCommit(intSpki) leaves
    bytes32 public policyRoot;               // Merkle root over accepted policyLeafHash leaves
    uint256 public constant MAX_BINDING_AGE = 1 hours;

    // Two-direction replay protection.
    mapping(address => bytes32) public nullifierOf;       // wallet → nullifier
    mapping(bytes32 => address) public registrantOf;      // nullifier → wallet

    event Registered(address indexed holder, bytes32 indexed nullifier, uint256 timestamp);
    event TrustedListRootRotated(bytes32 indexed previous, bytes32 indexed current, address admin);
    event PolicyRootRotated(bytes32 indexed previous, bytes32 indexed current, address admin);

    function register(...) external { /* see Data flow §2 */ }

    function isVerified(address holder) external view returns (bool) {
        return nullifierOf[holder] != bytes32(0);
    }

    function setTrustedListRoot(bytes32 newRoot) external onlyAdmin {
        emit TrustedListRootRotated(trustedListRoot, newRoot, msg.sender);
        trustedListRoot = newRoot;
    }

    function setPolicyRoot(bytes32 newRoot) external onlyAdmin {
        emit PolicyRootRotated(policyRoot, newRoot, msg.sender);
        policyRoot = newRoot;
    }
}
```

### `lib/P256Verify.sol`

Wraps EIP-7212 precompile (address `0x0000000000000000000000000000000000000100` on Base). Input layout per EIP-7212: 160 bytes = `hash(32) || r(32) || s(32) || x(32) || y(32)`. Returns true if signature valid.

Three exported functions:

- `parseSpki(bytes calldata spki) → (bytes32 x, bytes32 y)` — DER walker for 91-byte P-256 SPKI. Fails loudly on unexpected DER variants (e.g. non-named-curve, wrong AlgorithmIdentifier).
- `spkiCommit(bytes calldata spki) → uint256` — computes the canonical SPKI commitment exactly the way the circuit and the flattener do. Internally: `parseSpki`, then decompose X and Y into 6×43-bit LE limbs, then `Poseidon₂(Poseidon₆(X_limbs), Poseidon₆(Y_limbs))`. Used for both gate 2a binding and gate 3 trust-list Merkle leaf.
- `verifyWithSpki(bytes calldata spki, bytes32 messageHash, bytes32[2] calldata sig) → bool` — convenience: `parseSpki` then call EIP-7212.

The `spkiCommit` function is the canonical bridge between calldata SPKI bytes and the field-domain commitment exposed by the proof. It must be byte-equivalent to the circuit's `Poseidon₂(Poseidon₆(leafXLimbs), Poseidon₆(leafYLimbs))` (per `packages/circuits/circuits/QKBPresentationEcdsaLeaf.circom:290-299`). Foundry tests must cover round-trip: a real Diia leaf SPKI fed through `spkiCommit` produces the same value the circuit produces from the same SPKI's witness limbs.

### `lib/PoseidonMerkle.sol`

Vendored or rolled Poseidon₂ Solidity implementation. Verifies a 16-deep Merkle proof against a stored root. Hash function must match the flattener's off-chain Merkle construction exactly.

### `IdentityEscrowNFT.sol`

**Unchanged.** Constructor parameter swaps from V4 registry → V5 registry, otherwise same code.

### `IQKBRegistry.sol`

**Unchanged.** ABI-stable across versions for third-party SDK consumers.

## Trusted setup ceremony

### Phase 1 (universal)

**Reuse `powersOfTau28_hez_final_23.ptau`** (Powers of Tau Phase 1, ~1.2 GB). Supports circuits up to 2^23 = 8,388,608 constraints; our ~4.0M-constraint V5 circuit fits with ~110% headroom against the 4.5M envelope cap. Already public + audited (Hermez ceremony). No new Phase 1 needed.

**Why pot23 instead of pot22 or pot28**: pot22 (~600 MB, 4.19M cap) was the original right-sized choice when V5 was projected at 2.6M, but the §6.4 empirical measurement raised the projection to ~4.0M, which would leave only ~5% headroom under pot22 and would need an upgrade if any further constraint creep emerges. pot23 doubles the ceiling to 8.4M, costs only +600 MB of one-time coordinator download, and keeps zero risk of mid-development ptau swaps. Still 7.5× smaller than the maximum-size pot28 (9.1 GB), so the original "smaller-than-pot28" simplification largely stands. (Phase 2 zkey size — what 20-30 contributors download/upload — is determined by the circuit, not by ptau capacity.)

### Phase 2 (circuit-specific)

**Hardware: local execution feasible; remote optional.** At the empirical ~4.0M-constraint envelope, Phase 2 setup needs ~16-24 GB peak RAM and ~30-45 min wallclock. Manageable on a 32 GB dev box; comfortable on a Fly.io perf-10x (40 GB) one-shot machine. No multi-node infrastructure required — every contributor's `snarkjs zkey contribute` step is single-machine and bounded by their own RAM.

zkey download/upload between contributors is ~2.0-2.4 GB per round trip. R2 bucket recommended over GitHub Releases (size limit) or per-contributor S3 spinups.

**Contributor count: 20-30.** Mix of admin + ZK community contacts (PSE, 0xPARC, Mopro, ETH Kyiv) + ~5 public contributions. Sequential workflow: each contributor downloads previous zkey, runs `snarkjs zkey contribute` with their own entropy, uploads. Coordinator (admin) verifies each contribution via `snarkjs zkey verify`.

Optionally start with 5-10 trusted core contributors first, extend with community contributions after the core chain is established (community drops don't break chain).

### Beacon

After last individual contribution, apply a public beacon (future Ethereum block hash) as the final contribution. Binds setup to a public timestamp.

### Transparency artifacts (committed to repo)

```
packages/circuits/ceremony/v5/
  ptau.sha256                  # reference to Hermez Phase 1
  contribution-log.md          # every contributor + their attestation hash
  contribution-XXXX.json       # snarkjs verify output for each contrib
  beacon-attestation.md        # which Ethereum block, which hash
  Groth16VerifierV5.sol        # the deployed verifier
  verification_key.json        # the public verification key
  zkey.sha256                  # final zkey hash for download verification
  urls.json                    # R2 URLs for zkey + .wasm
```

### Optional: deterministic-rerun verification

A public party other than admin re-runs the setup phase from the same ptau, attests that the intermediate zkey matches. Adds 1 day, increases trust. **Recommended.**

## Migration & deployment

### Existing deployments

**Ethereum Sepolia V4 — DEPRECATED, leave standing.** Don't redeploy V5 there (chain target is Base). Mark `fixtures/contracts/sepolia.json` as deprecated; new fixture `fixtures/contracts/base-sepolia.json` for V5 testnet, eventual `fixtures/contracts/base.json` for mainnet.

Existing nullifiers + admin's M27 registration become archival. No mint ever happened on V4 NFT (we held back), so nothing to migrate.

### Phase 1 — Implementation (parallel where possible)

| Track | Scope | Estimated weeks |
|-------|-------|----------------|
| Circuit shrink | New `QKBPresentationV5.circom` | 3-5 |
| Contracts | `QKBRegistryV5` + libs + verifier wiring | 2-3 (parallel) |
| SDK / CLI | Update register flow + V5 ABI | 1-2 (after circuit + contracts converge) |
| Frontend | Rebuild for V5 + EIP-7212-aware register | 1-2 (after SDK ready) |
| Ceremony | Local Phase 2 with 20-30 contributors | 1-2 (after circuit final) |

**Total: ~5-7 weeks** with circuit on critical path.

### Phase 2 — Base Sepolia E2E (testnet validation)

Hard gate before Base mainnet.

1. Deploy `Groth16VerifierV5` + `QKBRegistryV5` + `IdentityEscrowNFT` to Base Sepolia.
2. Pump deployment addresses to `fixtures/contracts/base-sepolia.json`.
3. Repoint SDK + CLI + frontend at Base Sepolia.
4. Founder dry-run: admin signs fresh Diia QES on `QKB/2.0` binding, generates V5 proof, registers, mints NFT №1.
5. Capture: register tx hash, mint tx hash, decoded `tokenURI(1)` SVG, gas costs.
6. Cross-platform smoke: same dry-run from a different device/wallet.
7. **Browser-only smoke** — biggest validation: prove + register + mint entirely in a Chromium tab. Validates the V1 user flow.

### Phase 3 — Base mainnet (production)

Hard-gated on user explicit go-ahead.

Pre-flight:
- Audit complete (A3 sub-project, parallel to A1).
- Base Sepolia phase 2 stable for ≥ 1 week.
- Funded mainnet admin wallet.
- All ceremony transparency artifacts public.

Deploy:
1. Deploy V5 contracts to Base mainnet via signed Foundry script.
2. Pump addresses to `fixtures/contracts/base.json`.
3. Verify on Base block explorer.
4. Frontend repointed at Base mainnet.
5. Founder mint #1 from admin wallet (real on mainnet — the launch).
6. Public announcement.

### Frontend hosting

**GitHub Pages.** Rationale: source-of-truth already lives on GitHub, deploy is `actions/deploy-pages` integrated with CI, custom domain (`identityescrow.org`) supported with auto-issued Let's Encrypt cert, no separate hosting account / dashboard / billing. Pure static SPA — fits the Pages model exactly. 100 GB/month soft bandwidth cap covers expected V1 traffic with significant headroom.

**One technical caveat — Cross-Origin Isolation for multithreaded proving.** snarkjs's WASM prover uses `SharedArrayBuffer` for parallel MSM, which requires the page to be cross-origin-isolated via `Cross-Origin-Opener-Policy: same-origin` + `Cross-Origin-Embedder-Policy: require-corp` HTTP headers. GitHub Pages does **not** let users configure custom response headers. Two paths forward:

- **Single-threaded prove (default).** Works without COOP/COEP. Spec-projected ~8-12 s on a 2024 desktop scales to ~30-90 s single-threaded; acceptable for V1 desktop-browser flow per acceptance criteria.
- **Service-worker COOP/COEP shim** (e.g., `coi-serviceworker` by gzuidhof — small, MIT-licensed, well-known pattern). Service worker intercepts subsequent fetches and synthesizes the headers, enabling `SharedArrayBuffer`. First page load is single-origin; second load onwards is cross-origin-isolated. Adds ~5 KB to the bundle and a small first-load reload pattern. Use only if single-threaded prove time turns out painful.

Validate single-threaded prove time on the real V5 zkey before committing to either path.

**Alternatives if GitHub Pages turns out to have a hard limit (e.g., bandwidth caps hit, COI shim too brittle):** Cloudflare Pages (DNS already on CF, fully header-configurable), Vercel, Netlify, IPFS via gateway, self-hosted VPS. None are blockers.

**Migration path from current Fly setup:** the existing Fly app (currently scaled-to-0) can stay as a fallback during transition. DNS swap is two A/AAAA records on Cloudflare (which still owns the DNS zone, even with Pages serving content); rollback in seconds if needed.

### Trust list rotation

EU LOTL signers rotate every 1-3 months. Flattener (`packages/lotl-flattener`) produces fresh `trustedListRoot` on demand. Today: manual `setTrustedListRoot` by admin.

**Flattener leaf format change.** V4 emitted Merkle leaves over a hash of the full intermediate certificate DER. V5 changes the leaf format to `SpkiCommit(intSpki)` (canonical SPKI commit, defined in §Data flow) — the trust assertion is now "this signing public key is from an authorized QTSP." This binds the on-chain Merkle gate to the same value that the circuit commits to as `intSpkiCommit` and that the contract recomputes via `P256Verify.spkiCommit(intSpki)`, closing the soundness gap that would otherwise let an attacker pair a self-controlled signing key with an unrelated trusted-list entry.

The flattener change is technically out of A1's package scope (`packages/lotl-flattener`) but A1 freezes the leaf-format contract; flattener's plan must align before V5 deploys.

Keep manual rotation for V1. Document runbook at `docs/operations/trust-list-rotation.md`. Daily-cron automation is post-V1 nice-to-have.

## Risks

### Constraint estimate overshoot — **MATERIALIZED. Risk closed.**

Original estimate was 1.1M; empirical projection (per circuits-eng §6.4 measurements) is **~4.0M with a 4.5M envelope cap** (~12% headroom). Drivers:

- Per-`Sha256Var` cost is ~880K at MAX≈1024 B, not the originally-assumed ~250K. Variable-length wrapper plus per-byte block-index mux scales near-linearly in MAX.
- `MAX_SA` raised 256 → 1536 once real Diia signedAttrs measured at 1388 B (CAdES-X-L profile, not CAdES-BES). +550K constraints.
- `MAX_BCANON` raised 768 → 1024 (real Diia binding 849 B; original 200-400 B estimate assumed QKB/1.0 schema). +700K combined with V2Core implementation reality.
- V2Core implementation: V2CoreLegacy measured 2.62M alone; V2CoreFast (single-pass Decoder amortization) brought it back to ~1.05M, a 2.49× shrink. Without this saving the circuit would not fit any reasonable envelope.

Result documented across spec amendments `b8e0f74` (1.85M→3M) and `77ed00d` (3M→4.5M). ptau switched from pot22 (~600 MB, 4.19M cap) to **pot23** (~1.2 GB, 8.4M cap) for safer headroom. zkey impact: ~2.0-2.4 GB (vs original 250-350 MB target). Browser-on-desktop remains feasible; browser-on-mobile reframed (see next risk). Risk closed; no further mitigation required for A1.

### SPKI parsing in Solidity

DER-encoded P-256 SubjectPublicKeyInfo has fixed standard layout (~91 bytes) but variants exist. Mitigation: hardcode expected DER prefix, fail loudly on unexpected encodings, cover edge cases in Foundry tests with real Diia leaf certs.

### EIP-7212 precompile gas + behavior

Address `0x100` on Base. Spec says ~3,500 gas/call, returns 32-byte true/false. Mitigation: verify with a tiny standalone test contract on Base Sepolia early — call the precompile with a known-good signature, confirm gas + return value, before integrating.

### Ceremony coordination

20-30 contributor ceremony spans 1-2 weeks. Drop-outs mid-chain require resuming from last verified contribution. Mitigation: trusted core contributors first, community extensions after.

### Browser proving on mobile — narrow-gated to flagships

At the empirical ~2.0-2.4 GB zkey size, mobile-browser is gated to flagship 2024+ phones with persisted storage. Below that bar is known-broken and explicitly out-of-gate.

**Hardware bar:**
- Pixel 9 / Galaxy S24-class Android with Android 14+, Chrome 120+, ≥8 GB RAM, `navigator.storage.persist()` granted (Chrome Android allots ~60% of free disk to persisted origins; comfortably fits 2.4 GB).
- iPhone 15 / 15 Pro / 16-series with iOS 17+, Safari (NOT in-app WebView). iOS 17+ allots ~20% of disk per origin (~25 GB on a 128 GB phone).
- Modern iPad with Safari (effectively desktop-class).

**Below-the-bar (out-of-gate, must reroute via UX):**
- Mid-range Android (50-200 MB quotas without persist; quota approval heuristic varies by manufacturer)
- iOS in-app WebViews (Telegram, Instagram, Twitter, etc. — historically capped at 1 GB regardless of OS)
- Phones with <8 GB RAM (Web Worker memory pressure during prove)
- Older browser versions (Chrome <120, Safari <17)

**UX requirement (gate-enforcing):**

The frontend MUST detect device class before triggering zkey download. Concretely:

1. On `/ua/cli` (or wherever the V5 prove flow starts), feature-detect: `'storage' in navigator && 'persist' in navigator.storage && 'estimate' in navigator.storage`. If missing → out-of-gate.
2. Call `navigator.storage.estimate()` and check `quota >= 3 GB`. Below → out-of-gate.
3. Call `navigator.storage.persist()` and check the return value. Denied → out-of-gate.
4. If all three pass → proceed with download + prove.
5. If any fail → render a clear "Use desktop or wait for the mobile-app version" page, with a `qkb.org/desktop` deeplink and an opt-in to the post-A1 mailing list.

**Validation gate (acceptance criterion):** full prove + register + mint on Pixel 9 (real device or BrowserStack) AND iPhone 15 (real device or BrowserStack) with `persist()` granted. Both must pass. Out-of-gate devices need only confirm the rerouting UX kicks in correctly.

**Prove time on flagships:** projected 30-90 s single-threaded WASM (vs ~30 s on desktop). With the `coi-serviceworker` shim enabling `SharedArrayBuffer`-backed multithreading, projected 15-30 s on a 6-8 core mobile SoC. Acceptable. Tablets behave like desktop.

**Path B (TEE-delegated) is the post-A1 expansion** for users below the gate. Adds a trust delta, requires explicit UX disclosure. Not blocking A1.

### signedAttrs reproducibility

PKCS#7 signedAttrs from Diia must be deterministically extractable. Mitigation: use the same parsing path the existing CLI uses (already proven against real Diia .p7s in M27). New circuit must consume the same bytes the existing CLI extracts.

### Cert chain depth

Architecture assumes 2-deep chains (root CA → intermediate → leaf). Mitigation: confirm against current Diia QES; document assumption explicitly. If Diia goes 3-deep, add another EIP-7212 call layer.

### RIP-7212 stability on Base

Verified on Base today, but precompile addresses can theoretically change in future hard forks. Mitigation: pin precompile address as a constant overridable via admin function (cheap escape hatch). Audit reviews this.

## Open design questions for plan/implementation phase

These resolve in the implementation plan, not here:

1. Exact public-signal ordering (snarkjs ABI conventions may force a specific layout).
2. PoseidonMerkle library: vendor iden3's `PoseidonT3.sol` or roll our own? (Vendoring is faster, more battle-tested.)
3. Witness builder rewrite: how much of existing `@qkb/sdk` witness code reuses vs. rewrites for V5?
4. SDK API for new register flow: keep `qkbRegistry.encodeRegisterCalldata(witness)` as today, or expose a higher-level `qkbRegistry.register(witness, signer)` that handles the whole tx?

## Acceptance criteria

A1 sub-project is complete when:

- [ ] `QKBPresentationV5.circom` compiles to ≤4.5M constraints (envelope cap; empirical projection ~4.0M).
- [ ] V5 zkey is ≤2.5 GB after Phase 2 ceremony (empirical projection ~2.0-2.4 GB).
- [ ] **Desktop-browser** prove of the V5 circuit succeeds on Chromium / Firefox / Safari in ≤3 min on a 2024-era laptop (Web Worker, OPFS-cached zkey).
- [ ] **Mobile-browser end-to-end gated on flagship phones with persisted storage:**
  - [ ] Full prove + register + mint succeeds on Pixel 9 (Android 14+, Chrome 120+) with `navigator.storage.persist()` granted.
  - [ ] Full prove + register + mint succeeds on iPhone 15 (iOS 17+, Safari, NOT in-app WebView) with persisted storage.
  - [ ] Frontend correctly detects out-of-gate devices (mid-range Android, iOS WebView, <8 GB RAM phones, older browsers) BEFORE triggering zkey download, and reroutes them to a "use desktop" page.
  - [ ] iOS in-app WebView (Telegram / Instagram / X) explicitly returns the rerouting UX, never the prove flow.
- [ ] `QKBRegistryV5.register()` succeeds end-to-end on Base Sepolia for the founder address with a real Diia .p7s, executed from a desktop browser.
- [ ] `IdentityEscrowNFT.mint()` succeeds for the founder address; `tokenURI(1)` decodes to a civic-monumental certificate SVG.
- [ ] Total `register()` gas on Base Sepolia ≤ 600K (raised from 500K → 600K because `spkiCommit` is full Poseidon-on-EVM, not byte-Poseidon).
- [ ] Ceremony transparency artifacts committed to repo.
- [ ] Desktop-browser end-to-end (no CLI used) validated for at least one full register + mint.
- [ ] Soundness regression tests pass:
  - [ ] Self-controlled `intSpki` paired with a trusted-list entry → BAD_TRUST_LIST (the contract's `spkiCommit(intSpki)` won't match any leaf in the Merkle).
  - [ ] Same nullifier registered to two wallets → second tx reverts NULLIFIER_USED.
  - [ ] Binding with `policyLeafHash` not in `policyRoot` → BAD_POLICY.
  - [ ] Mismatched `signedAttrs.messageDigest` vs binding → circuit fails to satisfy.
  - [ ] Public-signal hash hi/lo limbs that don't match the calldata SHA → BAD_*_HI / BAD_*_LO.
  - [ ] Mismatched `spkiCommit` semantics: a leaf SPKI fed through the contract's `spkiCommit` produces the same value as the circuit's witness-side computation for the same key (round-trip parity test, real Diia leaf cert as fixture).

## Out of scope (handled by other A-track sub-projects)

- **A2** — frontend UX rebuild for V5 (covered separately when A1 is plan-stable).
- **A3** — contract security audit + Base mainnet deploy.
- **A4** — operational launch (announcement, founder mint #1 on mainnet, post-launch monitoring).

---

**Spec self-review checklist:**

- [x] No "TBD" / placeholders (frontend hosting decision flagged as explicitly post-A1).
- [x] Internal consistency: data flow ↔ circuit components ↔ contract gates align.
- [x] Scope: A1 only. A2/A3/A4 cross-references are pointers, not creep.
- [x] Ambiguity: every component has a single clear responsibility; calldata vs. witness split is explicit.
- [x] Privacy regression caught + corrected (leafTbs in witness only, not calldata).

**v2 corrections from external review (incorporated):**

- [x] Trust-list leaf bound to verifying intSpki — Merkle leaf format is `SpkiCommit(intSpki)` (not opaque cert hash); flattener change documented in §Migration.
- [x] CAdES digest separation — circuit exposes `signedAttrsHash` AND `bindingHash` as distinct public signals; circuit-internal constraint `signedAttrs.messageDigest_field == bindingHash` closes the binding; contract uses `signedAttrsHash` for EIP-7212 (NOT `bindingHash`).
- [x] Nullifier-uniqueness preserved — `register()` checks both `nullifierOf[msg.sender] == 0` AND `registrantOf[nullifier] == address(0)`, writes both maps; matches V4 semantics.
- [x] Policy gate restored — calldata carries `policyPath`+`policyPathBits`; contract verifies `MerkleVerify(policyLeafHash, …, policyRoot)`; `setPolicyRoot` admin function added.
- [x] Multi-limb public encoding — every 256-bit SHA-256 digest crosses the BN254 boundary as a `(hi, lo)` 128-bit pair.

**v3 corrections from external review pass 2 (incorporated):**

- [x] Policy leaf domain made explicit — `policyLeafHash` is a 1-field-element public signal already in BN254 domain. (Construction further refined in v4 to match QKB/2.0 structured object exactly.)
- [x] `declHash` → `policyLeafHash` — name realigned with QKB/2.0 binding model and existing parser output. No more "QKB/2.0 spec but legacy declaration-prose surface" drift.
- [x] SPKI hash semantics unified — single canonical function `SpkiCommit(spki)` defined in §Data flow and exported by `P256Verify.sol`. Circuit, contract, and flattener all use the same Poseidon-over-X/Y-limbs construction. No more "two flavors of `poseidon(spki)`."
- [x] Public signal count moved 15 → 14 (consolidated `declHashHi`+`declHashLo` into single `policyLeafHash` per fix above).
- [x] Gas estimate revised upward (~440-490K, was ~400-450K) because `spkiCommit` is real Poseidon-on-EVM, not a cheap byte-hash. Acceptance budget bumped from 500K → 600K.

**v4 corrections from external review pass 3 (incorporated):**

- [x] `policyLeafHash` construction refined to match QKB/2.0 §3 exactly: `uint256(sha256(JCS(policyLeafObject))) mod p`, where `policyLeafObject = {policyId, policyVersion, bindingSchema, contentHash, metadataHash}`. Earlier prose said "raw declaration text" which would have dropped the four structured fields beyond the declaration body. Flattener / policy-list builder responsibility for byte-equivalent JCS canonicalization is now flagged explicitly.
- [x] All three stale `Poseidon(intSpki)` references swept (calldata description, registry contract field comment, migration-section flattener-format-change paragraph). Canonical leaf format is everywhere `SpkiCommit(intSpki)`. Same value the circuit commits as `intSpkiCommit` and the contract recomputes via `P256Verify.spkiCommit(intSpki)`.

**v5 corrections from review pass 5 (incorporated, post-implementation reconciliation):**

- [x] §Estimated zkey size: 250-350 MB → 2.0-2.4 GB. Sub-section now articulates the desktop-feasible-/-mobile-questionable split explicitly, instead of the original "fits IndexedDB on mid-range Android" claim that the empirical envelope no longer supports.
- [x] §Acceptance criteria: ≤1.5M constraints / ≤500 MB zkey → ≤4.5M / ≤2.5 GB. **Mobile-browser is now a hard gate, narrowed to flagship 2024+ phones with persisted storage:** Pixel 9 + iPhone 15 (Safari) must both pass full prove + register + mint; below-the-bar devices (mid-range Android, iOS WebView, <8 GB RAM phones, older browsers) must be detected and rerouted by the frontend BEFORE zkey download.
- [x] §Risks "Constraint estimate overshoot" — marked **MATERIALIZED + closed** with the empirical drivers (per-`Sha256Var` cost, MAX_SA/MAX_BCANON raises, V2Core implementation reality, ptau switch from pot22 to pot23). No further mitigation needed for A1.
- [x] §Risks "Browser proving on mobile" — reframed from "likely failure" to **"narrow-gated to flagships."** Hardware bar, out-of-gate device list, frontend rerouting UX requirement (`storage.estimate` quota check + `storage.persist` grant check before download), and validation gate all spelled out. Path B remains the post-A1 expansion for below-the-bar devices.
- [x] §Trusted setup ceremony Phase 2 hardware: 4-8 GB / 5-10 min → 16-24 GB / 30-45 min for the larger envelope. R2 bucket recommended for ~2.4 GB zkey rounds vs. GitHub Releases.
- [x] §Frontend hosting: open decision → **GitHub Pages**. Rationale tied to source-of-truth co-location with the repo + CI integration + auto-cert. One real technical caveat called out: GitHub Pages can't set custom HTTP response headers, so multithreaded snarkjs proving via `SharedArrayBuffer` requires either a service-worker COOP/COEP shim or accepting single-threaded prove time. Validation gate before committing to single- vs multi-threaded path.
