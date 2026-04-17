# Qualified Identity Escrow — Phase 2 Design

**Status:** Draft for team-of-agents execution
**Date:** 2026-04-17
**Depends on:** `2026-04-17-qkb-phase1-design.md` (Phase 1 QKB must ship first)
**License:** GPLv3 (inherits from Phase 1)

## 0. Scope

Phase 2 delivers **Qualified Identity Escrow (QIE)** as an overlay on the Phase 1 QKB. Holders who already hold a Phase 1 QKB `(B, σ_QES, cert_QES)` for a `pk` may additionally escrow *identity-recovery material* across a threshold of QTSP custodians. Release yields the raw recovery material — no QEAA, no qualified-seal issuance — so QTSPs act as dumb custodians; recipients verify reconstructed artifacts against Phase 1's chain.

Out of scope: key-recovery escrow (`sk` is never escrowed), threshold decryption, QTSP-issued QEAAs, real-LOTL QIE service-type URI integration (Phase 2 ships with a synthetic LOTL extension).

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
