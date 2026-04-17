# `@qkb/qie-agent` — Fastify QIE agent

Orientation for future contributors (human or agent) working inside
`packages/qie-agent/`. Prescriptive; follow the patterns unless you
have a reason and a green test suite.

## 1. Package purpose

The QIE agent is the HTTP surface a Holder's or heir's client talks to
when depositing or recovering an escrow share. It is a Fastify app,
backed by a filesystem store (`FsStorage`), with two event watchers
(revocation + unlock/evidence) that reconcile on-chain state with the
local record.

Routes:

| Method | Path | Purpose |
|---|---|---|
| POST | `/escrow` | Deposit a wrapped share + config; verify `escrowId == hash(config)` and the agent is named in `config.agents`. |
| GET  | `/escrow/:id/config`   | Return the stored config. `no-store`. |
| GET  | `/escrow/:id/status`   | Return `active \| expired \| revoked \| released \| unknown`. |
| POST | `/escrow/:id/release`  | Release the share to the recipient after predicate evaluation (A-path or C-path) and state gate. |
| DELETE | `/escrow/:id`        | Holder-signed erasure via CAdES. |
| GET  | `/.well-known/qie-agent.json` | Discovery metadata. |

## 2. Security invariants

- **`escrowId == computeEscrowId(config)`** — enforced on POST /escrow.
- **Replay guard** — `recipient_nonce` must be fresh per escrow.
- **Cache-Control: no-store** on sensitive endpoints (see `server.ts`).
- **`Unlock` is authoritative** — evidence envelopes (`UnlockEvidence`)
  are provenance-only.
- **No plaintext `R`** — the agent never sees plaintext; hybrid-KEM
  ciphertext is returned as-is.

## 3. State machine (MVP refinement §0.3)

Registry state per escrow:

```
NONE → ACTIVE → RELEASE_PENDING → RELEASED
           ↘ REVOKED                ↑
              (terminal)            ↳ cancellation returns to ACTIVE
```

Agent enforcement (Q3):
- `POST /escrow/:id/release` calls `ctx.escrowStateReader(id)` when
  wired, and rejects with **409 `QIE_ESCROW_WRONG_STATE`** unless the
  on-chain state is `RELEASE_PENDING` or `RELEASED`.
- The watcher (`startUnlockWatcher`) observes `UnlockEvidence` then
  `Unlock`; on `Unlock` it flips the local record to `released` and
  attaches the evidence envelope (if any).
- `EscrowRevoked` from the registry still flips local state to
  `revoked` via `startRevocationWatcher`.
- When `escrowStateReader` is absent, the gate is **not** enforced —
  this is the legacy Phase 1 behavior and is the default for local
  dev. Production deploys MUST wire a real reader (e.g. a viem
  `readContract` call against `QKBRegistry.escrows(pkAddr).state`).

## 4. Notary-assisted recovery (MVP refinement §0.4)

`POST /escrow/:id/release` accepts an optional `on_behalf_of` field:

```jsonc
{
  "recipient_pk": "0x<heir_hybrid_pk>",          // required when on_behalf_of present
  "evidence": { ... },                           // A or C path, existing
  "recipient_nonce": "0x...",
  "on_behalf_of": {
    "recipient_pk": "0x<same as top-level>",
    "notary_cert":  "0x<DER cert>",
    "notary_sig":   "0x<CAdES sig>"
  }
}
```

When present, the agent:

1. Verifies `on_behalf_of.recipient_pk === recipient_pk`
   (else **400 `QIE_NOTARY_MISMATCH`**).
2. Builds the attestation payload
   `JCS({domain:"qie-notary-recover/v1",escrowId,recipient_pk})`.
3. Calls `ctx.notaryVerify(notary_sig, notary_cert, payload)` —
   pluggable hook that reuses the LOTL-backed CAdES chain-validation
   path already used for Holder QES. Errors:
   - `chain === "untrusted"` → **403 `QIE_NOTARY_CHAIN_UNTRUSTED`**.
   - `sigValid === false` → **403 `QIE_NOTARY_SIG_BAD`**.
4. If no `notaryVerify` is wired, the attestation is rejected as
   `QIE_NOTARY_CHAIN_UNTRUSTED` (safe default).

Absence of `on_behalf_of` means self-recovery — the existing
predicate-only path is used.

## 5. Watchers (MVP refinement §0.2)

- `startRevocationWatcher` — subscribes to registry `EscrowRevoked`,
  flips record state to `revoked`.
- `startUnlockWatcher` — subscribes to arbitrator `UnlockEvidence` AND
  `Unlock`. Buffers evidence envelopes keyed by `escrowId`; on
  `Unlock`, calls `storage.setEvidence(...)` (if evidence buffered)
  and `storage.markReleased(escrowId, recipientHybridPk)`.

Evidence field names mirror the **frozen** `AuthorityArbitrator` ABI:
`kindHash`, `referenceHash` (NOT `reference`), `evidenceHash`,
`issuedAt`. Do not rename; contracts-eng has confirmed the name is
`referenceHash` in the on-chain event.

## 6. Error codes (canonical, `@qkb/qie-core` `QIE_ERRORS`)

Existing: `QIE_AGENT_UNREACHABLE`, `QIE_PREDICATE_UNSATISFIED`,
`QIE_ESCROW_EXPIRED`, `QIE_ESCROW_REVOKED`, `QIE_ESCROW_NOT_FOUND`,
`QIE_CONFIG_MISMATCH`, `QIE_SHARE_DECRYPT_FAILED`,
`QIE_RECONSTRUCTION_FAILED`, `QIE_LOTL_AGENT_UNKNOWN`,
`QIE_REPLAY_DETECTED`, `QIE_RATE_LIMITED`.

MVP refinement §0.5:
- `QIE_NOTARY_CHAIN_UNTRUSTED` (403) — notary cert not in LOTL.
- `QIE_NOTARY_SIG_BAD` (403) — notary CAdES signature invalid.
- `QIE_NOTARY_MISMATCH` (400) — `on_behalf_of.recipient_pk` differs
  from top-level `recipient_pk`, or `recipient_pk` missing.
- `QIE_ESCROW_WRONG_STATE` (409) — on-chain state is not
  `RELEASE_PENDING` or `RELEASED`.

## 7. Tests

- `test/server.test.ts` — route-level E2E with Fastify `inject`.
- `test/watcher.test.ts` — revocation watcher.
- `test/watcher.evidence.test.ts` — unlock/evidence watcher (Q1).
- `test/recover.notary.test.ts` — `on_behalf_of` paths (Q2).
- `test/recover.state.test.ts` — registry-state gate (Q3).
- `test/storage-fs.test.ts` — FsStorage adapter contract.
- `test/replay.test.ts` / `test/ack.test.ts` — nonce + Ed25519 ack.

Run:

```
pnpm -F @qkb/qie-agent test
pnpm -F @qkb/qie-agent typecheck
```

Tests consume the built `@qkb/qie-core` dist — if you change
`packages/qie-core/src/**`, run `pnpm -F @qkb/qie-core build` before
re-running agent tests.

## 8. What NOT to do

- Don't add a per-package schema to Fastify routes — the reply shape
  is plain JSON and serializer-free by design.
- Don't bypass the state gate or the replay guard for "convenience".
- Don't persist plaintext `R`, recovery secrets, or notary cert PII
  to logs.
- Don't rename event field types in `EvidenceEnvelope` — they mirror
  the frozen Solidity ABI.
- Don't replace `FsStorage` with in-memory in production; durability
  is load-bearing for post-mortem audit.
