# Qualified Identity Escrow — Phase 2 Design

**Status:** Draft for team-of-agents execution
**Date:** 2026-04-17
**Depends on:** `2026-04-17-qkb-phase1-design.md` (Phase 1 QKB must ship first)
**License:** GPLv3 (inherits from Phase 1)

## 0. Scope

Phase 2 delivers **Qualified Identity Escrow (QIE)** as an overlay on the Phase 1 QKB. Holders who already hold a Phase 1 QKB `(B, σ_QES, cert_QES)` for a `pk` may additionally escrow *identity-recovery material* across a threshold of QTSP custodians. Release yields the raw recovery material — no QEAA, no qualified-seal issuance — so QTSPs act as dumb custodians; recipients verify reconstructed artifacts against Phase 1's chain.

Phase 2 also **closes four gaps inherited from Phase 1** (amendments §14 of this spec):

1. **RSA-PKCS#1 v1.5 variant** of the presentation proof. Phase 1 shipped ECDSA-P256 only (Diia). Phase 2 adds RSA-2048 so Polish Szafir, Estonian SK, and other RSA-issuing QTSPs work.
2. **Unified single-proof circuit.** Phase 1's §5.4 split-proof fallback (leaf-only + deferred chain) is collapsed back into one proof that carries `rTL` + `algorithmTag` in its public signals, matching the original `R_QKB` specification. The 28 GB peak memory that forced the split in Phase 1 is comfortably accommodated by `performance-12x` Fly machines (48 GB); ceremony happens there as standard operating procedure.
3. **Flyctl-based ceremony** documented as the canonical production path — covers setup, contribute, export, R2 upload. Local dev boxes are for development-stub circuits only.
4. **Nullifier primitive for deduplication** — one new public signal, one new on-chain mapping, enables Sybil-resistance per context, revocation-readiness, and escrow-link-on-release (§14.4).

Out of scope: key-recovery escrow (`sk` is never escrowed), threshold decryption, QTSP-issued QEAAs, real-LOTL QIE service-type URI integration (Phase 2 ships with a synthetic LOTL extension), Feldman VSS (Phase 3), threshold ML-KEM (no mature library yet).

## 1. Terms

- **Recovery material `R`** — JCS-canonical bytes of `{B, σ_QES, cert_QES}` from the Holder's Phase 1 QKB.
- **Escrow configuration `E`** — JCS-canonical document declaring agents, threshold, arbitrator, recipient, expiry (§3).
- **`escrowId`** — `SHA-256(E)`; also the on-chain commitment.
- **Agent** — a QTSP running the `qie-agent` HTTP service, holding one Shamir share of `k_esc` wrapped under its hybrid KEM public key.
- **Arbitrator** — a Solidity contract that emits `Unlock(escrowId, recipient)` when its predicate fires.
- **Unlock predicate** — the disjunction `OnChainEvent(arbitrator, escrowId) ∨ QESCountersig(Holder, {escrowId, "unlock", recipient_pk})`.

## 2. Cryptographic construction

### 2.1 Recovery-material envelope

1. `k_esc ← $ {0,1}^256`
2. `encR = AES-256-GCM(k_esc, iv=$, aad=escrowId) || tag` over `R`
3. Shamir split `k_esc` over `GF(2^256)` with threshold `t` into `(s_1, …, s_N)` (information-theoretic; PQ-safe at this layer by construction)
4. Per agent `i`: hybrid-KEM-encapsulate to `agent_pk_i`, yielding `(kem_ct_i, ss_i)` where `ss_i = HKDF-SHA256(X25519_ss || MLKEM_ss, "QIE/hybrid/v1")`; then `wrap_i = AES-256-GCM(ss_i, iv=$, aad=escrowId || agent_id_i) || tag` over `s_i`; the agent-facing ciphertext is `ct_i = {kem_ct_i, wrap_i}`.

### 2.2 Hybrid KEM

- Classical: X25519 (RFC 7748) via `@noble/curves`.
- Post-quantum: ML-KEM-768 (FIPS 203) via `@noble/post-quantum`.
- Combiner: `ss = HKDF-SHA256(salt="QIE/hybrid/v1", ikm = X25519_ss || MLKEM_ss, info = "shared-secret", L=32)`.
- Agent public key encoding: JCS field `hybrid_pk = {x25519: 0x…(32B), mlkem: 0x…(1184B)}`.
- Wire-format for `kem_ct_i`: `{x25519_ct: 0x…(32B), mlkem_ct: 0x…(1088B)}`.

### 2.3 Shamir scheme

- Field: `GF(2^256)` with irreducible `x^256 + x^10 + x^5 + x^2 + 1`.
- Share encoding: `(index: u8, value: 32 bytes)`, 33 B per share.
- Threshold `1 ≤ t ≤ N ≤ 16` (MVP bound).
- Reconstruction: Lagrange interpolation at `x=0`.

## 3. Escrow Configuration `E`

Canonical JCS (RFC 8785) document:

```json
{
  "version": "QIE/1.0",
  "pk": "0x04...",
  "agents": [
    { "agent_id": "ua-qtsp-demo-0", "hybrid_pk": { "x25519": "0x...", "mlkem": "0x..." }, "endpoint": "https://..." },
    { "agent_id": "ua-qtsp-demo-1", "hybrid_pk": { ... }, "endpoint": "https://..." },
    { "agent_id": "ua-qtsp-demo-2", "hybrid_pk": { ... }, "endpoint": "https://..." }
  ],
  "threshold": 2,
  "recipient_hybrid_pk": { "x25519": "0x...", "mlkem": "0x..." },
  "arbitrator": { "chain_id": 11155111, "address": "0x...", "kind": "authority|timelock" },
  "expiry": 1900000000,
  "jurisdiction": "UA",
  "unlock_predicate": "A_OR_C"
}
```

`escrowId = SHA-256(JCS(E))`. The configuration is **not** signed into `E` itself; legal binding comes from the Holder's on-chain `registerEscrow` call (which is implicitly authorized by the Phase 1 QKB chain).

## 4. Data flow

### 4.1 Setup

Holder already has `(B, σ_QES, cert_QES)` from Phase 1.

1. Holder fetches `qie-agents.json` (Merkle set rooted at `r_QIE`), picks `N` agents, verifies each `hybrid_pk` is under `r_QIE`.
2. Holder builds `E` (JCS), computes `escrowId`.
3. Builds `R = JCS({B, σ_QES, cert_QES})`.
4. Generates `k_esc`; computes `encR` per §2.1 step 2.
5. Shamir-splits `k_esc` → `{s_i}` per §2.3.
6. For each agent `i`, computes `ct_i` per §2.1 step 4.
7. `POST /escrow` to each agent with `{escrowId, E, ct_i, encR}`. Agent validates: `escrowId == SHA-256(JCS(E))`, self-identity in `E.agents`, `encR` size ≤ 64 KiB; persists; returns `{ack_sig}` — an Ed25519 signature over `{escrowId, agent_id, "stored"}` under the agent's long-term ack key.
8. Holder collects `N` acks, then calls `QKBRegistry.registerEscrow(pk, escrowId, arbitratorAddr, expiry)`. Contract emits `EscrowRegistered(pk, escrowId, arbitratorAddr, expiry)`.

If any agent fails to ack, Holder either retries or rolls back by calling each successful agent's `DELETE /escrow/:id` (idempotent) and restarting with a fresh `escrowId`.

### 4.2 Release

Recipient holds the hybrid sk matching `E.recipient_hybrid_pk` and knows `escrowId`.

1. Recipient fetches `E` from any agent's `GET /escrow/:id/config`; verifies `SHA-256(JCS(E_fetched)) == escrowId` and `escrowId == QKBRegistry.escrowCommitment(pk)`. Mismatch → `QIE_CONFIG_MISMATCH`.
2. Recipient assembles predicate evidence:
   - **A-path:** block number + tx hash + log index referencing an `Unlock(escrowId, recipient_hybrid_pk)` emitted by `E.arbitrator.address`.
   - **C-path:** Holder's QES countersignature (full CAdES-BES detached) over canonical message `{escrowId, "unlock", recipient_hybrid_pk}`.
3. `POST /escrow/:id/release` to each agent with `{evidence, recipient_nonce}`. Agent validates predicate, replay window (24 h on `(escrowId, recipient_nonce)`), expiry, and revocation; on success returns `{ct_i, encR}`.
4. Recipient hybrid-KEM-decapsulates each `ct_i` → `s_i`; reconstructs `k_esc` via Shamir once `≥ t` good shares collected.
5. Decrypts `encR` with AES-256-GCM → `R`.
6. Recipient independently verifies `R`: parses `{B, σ_QES, cert_QES}`, checks `B.pk == pk`, runs Phase 1 QES verification against `r_TL` (Merkle proof for `cert_QES`), confirms `cert_QES` validity window covers `B.timestamp`. Optional: check OCSP/CRL for current revocation status.

### 4.3 Revocation

Holder calls `QKBRegistry.revokeEscrow(pk, reason)` authenticated by Phase 1 Groth16 proof π over the same relation `R_QKB` (same witness, same verifier). Agents watch this event and tombstone the escrow: ciphertexts overwritten with random bytes, metadata retained for audit for 1 year.

## 5. Arbitrators

Two reference implementations shipped; Holders may also point `arbitrator.address` at any contract emitting the canonical `Unlock(bytes32 escrowId, bytes recipientHybridPk)` event.

### 5.1 `AuthorityArbitrator`

Constructor: `(address authority)`.
State: `mapping(bytes32 => bool) evidenceHashUsed`.
Entry: `requestUnlock(bytes32 escrowId, bytes recipientHybridPk, bytes32 evidenceHash, bytes authoritySig)`.
Verification: `ecrecover(hash({escrowId, recipientHybridPk, evidenceHash}), authoritySig) == authority`; `!evidenceHashUsed[evidenceHash]`; marks used; emits `Unlock`.

### 5.2 `TimelockArbitrator`

Constructor: `(address holderPing, uint256 timeoutSeconds)`.
State: `uint256 lastPing`.
Entries:
- `ping()` — only `holderPing`; resets `lastPing`.
- `requestUnlock(bytes32 escrowId, bytes recipientHybridPk)` — anyone; requires `block.timestamp >= lastPing + timeoutSeconds`; emits `Unlock` once per `escrowId`.

## 6. Agent HTTP API

All request/response bodies JCS-canonical JSON. All errors return `{error: { code, message, details? }}` with 4xx/5xx status and one of the codes from §7.

- `POST /escrow` — body `{escrowId, E, ct_i, encR}`; response `{ack_sig}`.
- `GET /escrow/:id/config` — response `{E}`.
- `GET /escrow/:id/status` — response `{status: "active"|"expired"|"revoked"|"unknown"}`.
- `POST /escrow/:id/release` — body `{evidence, recipient_nonce}`; response `{ct_i, encR}`.
- `DELETE /escrow/:id` — idempotent setup-rollback; body `{holder_sig}` (Phase 1 QES countersig over `{escrowId, "delete"}`); response `{deleted: true}`.
- `GET /.well-known/qie-agent.json` — response `{agent_id, hybrid_pk, ack_pk, lotl_inclusion_proof}`; recipient uses this to verify the agent matches `r_QIE`.

Rate limits: per-IP 60 req/min on release; 10 req/min on setup.

## 7. Error taxonomy

Extends Phase 1 codes (orchestration §2.5). All under `QIE_*` namespace:

- `QIE_AGENT_UNREACHABLE`
- `QIE_PREDICATE_UNSATISFIED` (subcodes: `EVIDENCE_SIG_INVALID`, `EVIDENCE_EVENT_NOT_FOUND`, `EVIDENCE_ARBITRATOR_MISMATCH`, `EVIDENCE_EXPIRED`)
- `QIE_ESCROW_EXPIRED`
- `QIE_ESCROW_REVOKED`
- `QIE_ESCROW_NOT_FOUND`
- `QIE_CONFIG_MISMATCH`
- `QIE_SHARE_DECRYPT_FAILED`
- `QIE_RECONSTRUCTION_FAILED`
- `QIE_LOTL_AGENT_UNKNOWN`
- `QIE_REPLAY_DETECTED`
- `QIE_RATE_LIMITED`

## 8. Package structure

- **`packages/qie-core`** — pure-TS lib. Exports: `buildEscrowConfig`, `splitShares`, `reconstructShares`, `hybridEncapsulate`, `hybridDecapsulate`, `wrapShare`, `unwrapShare`, `encryptRecovery`, `decryptRecovery`, `evaluatePredicate`. Zero I/O. Runs in browser + Node. Dependencies: `@noble/curves`, `@noble/post-quantum`, `@noble/hashes`, JCS lib already vendored in web.
- **`packages/qie-agent`** — Node 20 HTTP server (Fastify). Storage adapters: `fs` (default, for mock docker), `postgres` (stub). Chain watcher via `viem`. Config via env. Binary: `qie-agent serve`.
- **`packages/qie-cli`** — operator CLI (`commander`). Subcommands: `setup`, `release`, `reconstruct`, `revoke`, `agent:rotate-keys`, `agent:list`.
- **`packages/contracts`** (extension) — `Arbitrator.sol` interface, `AuthorityArbitrator.sol`, `TimelockArbitrator.sol`, `QKBRegistry.sol` extended with `registerEscrow`/`revokeEscrow`/`escrowCommitment`/`isEscrowActive`.
- **`packages/lotl-flattener`** (extension) — emit `qie-agents.json` with `r_QIE`. MVP synthesizes 3 mock-QTSP entries; real-LOTL path documented.
- **`packages/web`** (extension) — routes `/escrow/setup` and `/escrow/recover`; reuses Phase 1 styling + i18n (EN + UK).
- **`deploy/mock-qtsps`** — `docker-compose.yml` with 3 agents + anvil + fixture arbitrator deployment. Used by CI.

## 9. Team allocation

Five workers for Phase 2:

- **qie-eng** (new) — `qie-core`, `qie-agent`, `qie-cli`, `deploy/mock-qtsps`. Heaviest track.
- **contracts-eng** — `QKBRegistry` extension, `AuthorityArbitrator`, `TimelockArbitrator`, Sepolia deployment.
- **flattener-eng** — `qie-agents.json` emission, synthetic-LOTL extension, real-LOTL migration doc.
- **web-eng** — escrow setup wizard + recovery flow routes, i18n strings, Playwright E2E integration with `deploy/mock-qtsps`.
- **lead (you)** — orchestration, interface locks (§2–§7 here are the contract), CLAUDE.md synthesis, cross-worker artifact pumping, final merge.

## 10. Testing

### 10.1 `qie-core`

- Shamir round-trip property test: `∀ (N∈[1,16], t∈[1,N], k_esc random)` reconstruct works with any `t`-subset, fails for `t-1` (statistical test across 1000 trials).
- Hybrid KEM KATs: NIST ML-KEM FIPS 203 vectors + X25519 RFC 7748 vectors + combined-KDF vectors frozen in `fixtures/qie/hybrid-kat.json`.
- AES-256-GCM envelope: tag tamper → fails; iv reuse detected; length-extension rejected.
- Predicate evaluator: A-path with mocked RPC fixtures; C-path with Phase 1 QES fixtures reused from `fixtures/qes/`.

### 10.2 `qie-agent`

In-process harness spawns real Fastify server on ephemeral port. Cases: enroll, release both paths, expiry tombstone, revocation tombstone, replay rejection, wrong-arbitrator evidence, storage crash recovery (kill mid-write, restart, verify consistency), DELETE rollback idempotency.

### 10.3 `contracts` (Foundry)

- `AuthorityArbitrator`: valid sig → `Unlock`; wrong signer → revert; replayed evidence hash → revert.
- `TimelockArbitrator`: ping resets; early unlock → revert; late unlock → `Unlock`; double-unlock → revert.
- `QKBRegistry`: `registerEscrow` writes + emits; `revokeEscrow` tombstones; double-register → revert; `isEscrowActive` truth table over `{active, expired, revoked}`.

### 10.4 E2E via `deploy/mock-qtsps`

`docker-compose up` → 3 agents + anvil + deployed arbitrators + registry. Playwright CI:

1. Load `/escrow/setup`, fixture Phase 1 QKB pre-loaded, configure 2-of-3 with `AuthorityArbitrator`, submit → 3 acks + `EscrowRegistered`.
2. Authority signs unlock. `qie-cli recover` as recipient → `R` reconstructed → Phase 1 verification passes → assert `B` byte-equal to fixture.
3. `TimelockArbitrator` path: `evm_increaseTime` past timeout → unlock → reconstruct → verify.
4. Negative: `t-1` agents shut down → `QIE_AGENT_UNREACHABLE` with partial-share report.
5. Negative: Holder revokes → `QIE_ESCROW_REVOKED` on next release attempt.

Coverage gate: ≥ 90% lines on `qie-core`; 100% branch on security-critical paths (predicate eval, storage writes, replay window).

## 11. Security considerations

- **Harvest-now-decrypt-later**: mitigated by hybrid KEM on every share wrap. Under standard assumptions, breaking both X25519 and ML-KEM-768 is required to recover a share.
- **Malicious shares**: MVP reconstruction is brute-force subset-try on `C(N,t)` combinations on failure. Phase 2b adds Feldman VSS to pin bad shares to a specific agent.
- **Agent collusion**: `t-1` colluding agents learn nothing about `k_esc` (information-theoretic). `t` colluding agents can reconstruct without evidence — trust anchor is the QTSP supervisory regime, not cryptography.
- **Chain-watcher integrity**: agents independently verify `Unlock` events against their own RPC. A single malicious RPC returning a forged event compromises only that agent; recipient still needs `t` honest agents.
- **Replay**: `(escrowId, recipient_nonce)` pair recorded for 24 h; release always uses a fresh nonce.
- **Evidence-hash reuse in AuthorityArbitrator**: prevented by on-chain `evidenceHashUsed` map.
- **Synthetic LOTL MVP gap**: documented as a temporary measure; production requires real QIE service-type URI in the EU trusted list and a real QTSP offering the service.

## 12. Non-goals (defer to Phase 3)

- QEAA issuance on release.
- Threshold ML-KEM (no mature library).
- Verifiable Secret Sharing.
- Real QTSP partnership + trusted-list QIE service-type URI.
- Cross-agent share-migration (if a QTSP goes out of business).
- Recipient-side formal legal framework for accepting reconstructed `R` as evidence in court.

## 13. Open questions for implementation plans

- Chunk size for `encR` (64 KiB cap is arbitrary; revisit based on max cert chain size).
- Whether `qie-agent` should expose a gRPC surface alongside REST. MVP: REST only.
- Whether setup wizard should optionally re-bind (emit a new Phase 1 binding with `escrow_commitment = escrowId`) vs. using pure on-chain linkage. MVP: on-chain linkage only; document rebind as a Holder-driven flow reusing Phase 1 tooling.

---

## 14. Phase-1 debt amendments (decided 2026-04-17)

Phase 1 shipped with four known deviations from the original `R_QKB`
specification, driven by a 22 GB compile-memory ceiling on the lead's
dev box and by the need to unblock downstream integration before the
ceremony completed. Phase 2 closes all four in a single pass before
touching any QIE-specific work, because every QIE primitive (the
`registerEscrow` dispatch, the agent predicate evaluator, the recovery
flow) reads the Phase-1 public signals and would break on a second
layout change downstream.

### 14.1 RSA-PKCS#1 v1.5 variant (`QKBPresentationRsa.circom`)

- Scope: RSA-2048 signatures over CAdES-BES `signedAttrs`, matching the
  modulus layout used by Polish Szafir + Estonian SK (4×512-bit limbs,
  `@zk-email/circuits` `RsaPkcs1V15Verify` sub-template).
- Reuses Phase-1 sub-circuits: `BindingParseFull`, `Sha256Var`,
  `PoseidonChunkHashVar`, `DeclarationWhitelist`, `Secp256k1PkMatch`
  (unchanged — the bound key is still secp256k1 regardless of the QES
  algorithm; `algorithmTag` refers to the QES signature, not the bound
  key).
- Public-signal layout identical to ECDSA variant (§14.3) — the
  `algorithmTag` distinguishes them on-chain.
- Ceremony: separate `.zkey` + verifier per variant, each at its own
  R2 URL in `urls.json`. The web runtime picks the prover variant from
  the detected QES cert's SignatureAlgorithm OID.
- Registry dispatch: `QKBRegistry.register` receives `algorithmTag` in
  the proof and routes to `rsaVerifier` or `ecdsaVerifier` — the
  dual-verifier registry pattern that was removed in Phase 1 T10
  returns.

### 14.2 Unified single-proof circuit

- The Phase-1 `QKBPresentationEcdsaLeaf` + the never-shipped
  `QKBPresentationEcdsaChain` collapse into one
  `QKBPresentationEcdsa.circom` that inlines all six constraints
  (R_QKB.{1,2,3,4,5,6}): the leaf QES verify, the intermediate-signs-
  leaf verify, the Merkle inclusion of the intermediate under `rTL`,
  `B.pk` match, context + declaration + timestamp binds.
- Estimated constraint budget: ~10–11 M (leaf ECDSA 7.6 M + chain ECDSA
  2.5 M + Merkle 0.4 M). Budget covered by `performance-12x` Fly
  machines with 48 GB, which we already validated tolerate ≥28 GB setup
  peaks comfortably.
- `leafSpkiCommit` is removed from the public signals — it only existed
  to glue the split proofs together, and the single-proof circuit has
  no glue. The contract's `QKBVerifier.Inputs` struct loses the field.

### 14.3 Public-signal layout (Phase 2 final — 14 signals)

```
[0..3]   pkX limbs (4 × uint64 LE)
[4..7]   pkY limbs (4 × uint64 LE)
[8]      ctxHash
[9]      rTL                 ← restored from Phase-1 drop
[10]     declHash            (sha256(decl) mod BN254.p)
[11]     timestamp
[12]     algorithmTag        ← restored from Phase-1 drop (0=RSA, 1=ECDSA)
[13]     nullifier           ← new, §14.4
```

Registry-side changes:
- `IGroth16Verifier.verifyProof` input array: `uint[14]`.
- `QKBVerifier.Inputs` gains `rTL`, `algorithmTag`, `nullifier`; loses
  `leafSpkiCommit`.
- `QKBRegistry` regains the `rTL == trustedListRoot` check dropped in
  Phase-1 T10, and gains the nullifier-uniqueness mapping in §14.4.

### 14.4 Nullifier primitive — amended 2026-04-18

> Superseded by `docs/superpowers/specs/2026-04-18-person-nullifier-amendment.md`. The prior `Poseidon(subject_serial_limbs, issuer_cert_hash)` construction bound to a specific certificate, not to a person — every QES renewal produced a fresh nullifier, breaking Sybil resistance at the DAO/regulated-entity layer. Replaced with the construction below.

Construction:
```
rnokppBytes  = subject.serialNumber attribute content (OID 2.5.4.5)
rnokppLen    = byte length of that content (1..16)
rnokppPadded = rnokppBytes ∥ 0x00 × (16 - rnokppLen)

secret       = Poseidon(Poseidon(rnokppPadded), rnokppLen)
nullifier    = Poseidon(secret, ctxHash)
```

- `rnokppBytes` — the raw PrintableString bytes of the subject
  `serialNumber` attribute (OID 2.5.4.5), present in every
  ETSI-EN-319-412-1-compliant eIDAS QES in the format
  `<TYPE><CC>-<national-id>` (e.g. `PNOUA-3456789012`, `PNODE-12345678`,
  `TINPL-1234567890`, `PASDE-C01X00T47`). The circuit never outputs it.
  Stable across cert renewals (the national identifier does not change
  when the QES rotates), which is the property that makes the nullifier
  person-scoped rather than cert-scoped.
- `rnokppLen` — hashed alongside the inner digest to prevent
  padding-collision attacks between identifiers of different natural
  lengths (8-byte EDRPOU vs 10-byte РНОКПП vs 12-byte passport).
- `ctxHash` — the Phase 1 binding's existing context field. Reused
  unchanged. An empty context (`ctxHash = 0`) yields a global
  nullifier suitable for KYC; a per-dApp `ctxHash` yields a
  Sybil-resistance nullifier suitable for DAO voting, airdrops, etc.

Properties (per the 2026-04-17 lead ↔ Alik conversation):

- **Uniqueness per context.** Two registrations attempting the same
  `(secret, ctxHash)` pair produce the same `nullifier`. On-chain
  `mapping(bytes32 nullifier => bool used)` enforces one-Holder-one-
  registration per context.
- **Unlinkability across contexts.** Different `ctxHash` yields
  different `nullifier`; the observer of two contexts' nullifier sets
  cannot cross-link Holders (unless Poseidon is broken or secret
  leaked via side-channel).
- **Revocation-ready.** Same primitive as Sedelmeir's DB-CRL: publish
  a revoked `nullifier` and any registry that observes the publication
  treats the corresponding binding as expired.
- **Escrow-ready.** The `secret` is the same value the QIE recovery
  flow would re-derive from `R` on release — so the recipient can
  independently verify `nullifier == Poseidon(Poseidon(subject_serial,
  issuer_hash), ctxHash)` from the reconstructed recovery material.
  This links an on-chain nullifier back to a decrypted QES identity
  through the threshold of custodians, and only through them.

On-chain:
- `QKBRegistry` gains `mapping(bytes32 => bool) usedNullifiers` and
  `error NullifierUsed()`. `register` reverts on duplicate.
- `QKBRegistry` also gains `mapping(bytes32 => address) nullifierToPk`
  for the Sedelmeir-style revocation publication pattern: a revoked
  `nullifier` implies the mapped `pkAddr` is no longer authoritative
  regardless of its `bindings[pkAddr].status`.

Ceremony impact:
- Circuit constraint count up ~40 k (two Poseidon hashes). Negligible
  vs. the ~10 M base cost.
- Public-signal count 14 (from 13 in original design, 12 in Phase-1
  shipped variant).

### 14.5 Flyctl ceremony as standard procedure

The Phase-1 precedent (`packages/circuits/ceremony/scripts/fly-setup-remote.sh`)
becomes the documented production path:

1. `fly apps create qkb-ceremony-<handle>` + `fly volumes create
   ceremony_data --size 40 --region fra`.
2. `fly machine run node:20-bookworm --vm-size performance-12x
   --vm-memory 49152 --volume ceremony_data:/data sleep infinity`
   (48 GB RAM covers unified-proof setup with comfortable headroom).
3. SFTP-upload compressed `.r1cs.zst` (2×SHA256Var + 2×ECDSA + Merkle
   = ~10 M constraints compresses ~25× with zstd — under 100 MB
   transfer).
4. On-machine: `curl` ptau 2^24 from googleapis CDN (~18 GB — larger
   circuit needs a larger ceremony).
5. `snarkjs groth16 setup → zkey contribute → export` in a detached
   tmux session. `NODE_OPTIONS='--max-old-space-size=45056'`.
6. Compress + SFTP-pull the `.zkey` back. Local sha256 verify against
   on-machine hash.
7. `aws s3 cp` (R2-compatible) upload of `.zkey` + `.wasm` to the R2
   bucket `proving-1` under `prove.identityescrow.org`.
8. `fly machine destroy && fly volumes destroy && fly apps destroy` —
   ephemeral infra, ceremony cost ≈ $1–2 total.

Per-variant artifacts (RSA + ECDSA) → two parallel ceremonies, two
entries in `urls.json`. Consumers key by `algorithmTag`.

Local dev boxes continue to run the **stub** circuit flow
(`circuits/QKBPresentationEcdsaLeafStub.circom` + Phase-2 sibling for
RSA) for contract + web integration tests. Stubs ship with a dev
verifier that has the 14-signal layout but no real constraints.

### 14.6 Sequencing inside Phase 2

These amendments land **before any QIE-core code** because every QIE
primitive reads the Phase 1 public signals:

1. Write `QKBPresentationRsa.circom` + stub sibling. Ship RSA stub to
   contracts + web so they can test dispatch.
2. Write `QKBPresentationEcdsa.circom` (unified) + stub sibling. Ship
   ECDSA stub to contracts + web with the 14-signal layout.
3. Extend `QKBVerifier.sol` + `QKBRegistry.sol`: dual verifier
   addresses back, `nullifier` check, `rTL` check, `algorithmTag`
   dispatch.
4. Update `packages/web` witness builder for 14 signals + nullifier
   computation.
5. Run real unified-proof ceremonies (×2 variants) on Fly.
6. Swap stub verifiers for real in the Sepolia deploy.
7. **Then** begin QIE-core, qie-agent, QIE routes.

This sequencing is explicit in the per-worker Phase-2 plans
(`qie-{contracts,web,qie,flattener}.md`).
