# QIE MVP Refinement — Tier 1 Wedge

**Status:** Amendment to `2026-04-17-qie-phase2-design.md`
**Date:** 2026-04-17
**Supersedes:** scoping assumptions in Phase 2 design §0, §6.1, §6.2

## 0. Why this amendment

The Phase 2 spec defines QIE as a general-purpose identity-recovery escrow with
dual-variant prover, authority + timelock arbitrators, sybil-nullifier tooling,
and a standalone recipient UX. Brainstorming on 2026-04-17 sharpened the
**target market** and the **product framing**, which in turn sharpens which
pieces of Phase 2 are load-bearing for MVP and which are speculative.

This amendment records that framing and the scope deltas that fall out of it.
It does not replace the Phase 2 spec — circuits, contracts, and core protocol
constructions are unchanged. It narrows the MVP surface and adds three new
sections (Legal Instruments, Evidence Envelope, Operational Model).

## 1. Primitive framing

**QKB** is a *sybil-resistance credential*: one Groth16 proof that a real
EU-qualified human controls a wallet. Read-mostly, standalone product,
integrations are one `QKBRegistry` read + optional nullifier check.

**QIE** is a *recovery protocol*: a threshold of QTSP custodians hold
encrypted shares of the QKB witness; release is gated by an arbitrator
contract. Stateful, multi-party, legally anchored.

The coupling is deliberate: QIE's recovered artifact `R` is a QKB binding,
so reconstruction produces a *re-bindable credential*, not a raw secret.
This is QIE's unique property versus Shamir-as-a-service.

## 2. Target market (Tier 1 wedge)

QIE's real demand comes from three segments where *legal-grade* custody
matters more than permissionless UX:

1. **Inheritance / estate planning** — notary-as-arbitrator, death-cert as
   release trigger, heir re-binds to a new wallet. Replaces "seed phrase
   in a will."
2. **Regulated entities holding crypto** — DAOs with legal wrappers, funds,
   treasuries. Board + outside counsel + audit firm as 2-of-3 custodians.
   Addresses personnel-change continuity that single-custodian products
   (Fireblocks) concentrate and that social recovery can't handle legally.
3. **KYC-recovery in regulated DeFi** — escrow the QKB; on key loss,
   reconstruct and re-bind under the *same nullifier*, preserving the
   holder's KYC'd status at the protocol without re-verification.

Out of MVP scope (Tier 2/3): individual social-recovery competition,
whistleblower conditional-disclosure, identity-portability demos.

## 3. Scope deltas vs. Phase 2 design

### 3.1 Keep (unchanged from Phase 2 spec)

- Dual-variant prover (RSA-PSS + ECDSA). Verified against ETSI TS 119 312
  v1.5.1: both are valid QES algorithms; D-Trust citizen cards are
  RSA-PSS, Diia ships both, Polish/French QTSPs split. Dropping either
  loses roughly half the citizen market.
- `R = QKB binding` as escrowed material.
- On-chain `registerEscrow` / `revokeEscrow` / `escrowCommitment` /
  `isEscrowActive`.
- Hybrid KEM (X25519 + ML-KEM-768), `GF(2^256)` Shamir.
- QTSP agents as HTTP services with Ed25519 ack signatures.
- `Arbitrator` interface abstraction.

### 3.2 Cut from MVP (defer or drop)

- **`TimelockArbitrator`** — deferred. Tier 1 release triggers are all
  authority-based (notary, death cert, board resolution); timelock serves
  Tier 2 "lost device" and Tier 3 whistleblower, both post-MVP. Ship the
  interface, don't ship the implementation. ~200 lines of contract +
  tests removed from critical path.
- **Standalone sybil-nullifier tooling** — the circuit primitive and
  on-chain `mapping(bytes32 => bool)` stay (essentially free once the
  circuit's there), but no CLI / docs / integration examples in MVP.
- **Standalone recipient UX** — the Phase 2 recover flow assumes the
  recipient runs the QIE web app or CLI. Inheritance heirs cannot do
  this. Replace with *notary-assisted recovery* (§3.3 below).

### 3.3 Add to MVP

- **§15 Legal Instruments** — template outlines for:
  - *Inheritance rider* that references `escrowId`, names the
    arbitrator address, and specifies death-certificate hash as the
    evidence trigger.
  - *Custody agreement* between a regulated entity, its N QTSPs, and
    the arbitrator-holder (typically outside counsel). Spells out
    liability, SLA, fee schedule.
  - Non-normative — for pilot partners to adapt with their counsel.
- **`EvidenceEnvelope` schema** — structured payload an
  `AuthorityArbitrator` accepts alongside its release call:
  ```jsonc
  {
    "kind": "death_certificate" | "court_order" | "board_resolution" | "custom",
    "reference": "<human-readable id, e.g., UK-GRO-DC-2026-000123>",
    "hash": "0x<sha256 of evidence document>",
    "issuerSig": "0x<signature by arbitrator's whitelisted authority>",
    "issuedAt": "<unix ts>"
  }
  ```
  Emitted in the `Unlock` event. Agents MAY gate share release on
  receiving the envelope; recipients MAY display it in recovery UX.
- **§16 Operational Model** —
  - Annual fee per escrow, Holder-paid, agent-denominated.
  - Agent SLA: 99.5% availability, 24 h recovery response, ciphertext
    durability (geo-replicated).
  - Agent liability: limited to ciphertext-loss remediation (re-sharing
    from remaining agents); agents never learn `R` so no plaintext
    exposure liability.
  - Pricing, SLA, liability are per-agent contracts, not protocol
    enforcement. Protocol only enforces the threshold and revocation.
- **Notary-assisted heir UX** — a new flow where the notary
  authenticates as the recipient on behalf of a non-crypto-native heir,
  drives reconstruction via a notary-run web app, and outputs a fresh
  QKB re-binding that the heir's new wallet can import. Requires one
  agent API concession: accept the notary's signed attestation
  (`on_behalf_of: <heir_pk>`) in the share-release call. Detailed flow
  specified in a follow-up plan.
- **Revoke-vs-release state machine** — make explicit in contracts:
  - States: `Active → ReleasePending → Released` (happy path),
    `Active → Revoked` (holder-initiated).
  - Transitions: `ReleasePending` on first agent accepting an unlock
    call; blocks `revokeEscrow` until `Released` or until a timeout
    returns the state to `Active`.
  - Prevents the "Holder revokes mid-reconstruction" race and the
    "Holder comes back from dead" scenario.

## 4. MVP cut summary

Ship QIE v1 with: **dual-variant prover (RSA + ECDSA), `AuthorityArbitrator`
only, one QTSP partner for pilot, one legal template (inheritance),
notary-assisted heir UX, explicit escrow state machine, evidence envelope
in arbitrator releases.**

Defer to post-MVP: `TimelockArbitrator`, sybil-nullifier integrations,
standalone recipient UX, entity-custody legal template (may overlap with
inheritance template enough to ship together; re-evaluate post-pilot).

## 5. Implementation impact on in-flight Phase 2 work

- **contracts-eng** — `TimelockArbitrator.sol` drops from critical path;
  keep the deploy script but don't block Sepolia on it. Add `EvidenceEnvelope`
  to `AuthorityArbitrator` release path. Add state-machine transitions
  to `QKBRegistry.{registerEscrow, revokeEscrow}`.
- **circuits-eng** — unchanged. Dual-variant remains.
- **flattener-eng** — unchanged.
- **qie-eng** — add `on_behalf_of` attestation path to agent share-release.
  Add evidence-envelope pass-through in release responses. Docker/compose
  unchanged.
- **web-eng** — cut standalone recipient playwright spec; replace with
  notary-assisted recovery spec. Setup wizard cuts timelock option from
  the arbitrator picker.

## 6. Open questions (non-blocking)

- Which pilot QTSP first? D-Trust (DE, RSA-PSS citizen cards, notary
  relationships) vs. Diia (UA, familiar, already shipping ECDSA, less
  notary depth). Dispatch decision lives in a GTM doc, not this spec.
- Whether "notary-assisted recovery" is a first-class mode or a thin
  wrapper over the standard flow with relaxed auth. Leaning first-class
  because the UX divergence is large.
- Whether `EvidenceEnvelope.kind` should be an extensible string or an
  enum; proposing extensible string with a reserved set, to avoid
  contract upgrades per new evidence type.

## 7. Non-goals of this amendment

- Does not alter the cryptographic construction (§2 of Phase 2 spec).
- Does not alter the on-chain interfaces beyond adding state-machine
  transitions and the evidence envelope field.
- Does not prescribe the pilot QTSP; that is a GTM decision.
- Does not commit to an inheritance-product launch timeline.
