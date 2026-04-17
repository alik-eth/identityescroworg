# QIE §16 — Operational model

These provisions are **not protocol-enforced**. They are the baseline
contractual expectations we propose QTSPs accept when onboarding as
QIE agents. Deviations are permitted and should be disclosed in the
agent's `/.well-known/qie` document.

## 16.1 Fees

- **Annual fee per escrow**, denominated per-agent.
- **Payment instrument:** off-chain. The Holder settles directly with
  each agent at `registerEscrow` time; agents MUST NOT refuse share
  storage on the basis of pending payment within the current billing
  cycle.
- **Proration:** a Holder revoking mid-cycle forfeits the current
  cycle's fee; no refund. Agents may offer refunds at their discretion.
- **Non-payment penalty:** after a **30-day grace period** past the
  annual renewal date, an agent MAY refuse to participate in a release
  request. The agent MUST NOT destroy the ciphertext during the grace
  period; grace-period-triggered destruction requires a further 90-day
  notice per §16.4.

## 16.2 SLA

- **Availability:** 99.5% measured per calendar month, per agent.
  Measurement window: `GET /escrow/:id/config` and `POST /recover/:id`
  together.
- **Recovery response:** < 24 h from receipt of a well-formed
  `POST /recover/:id` that passes signature and state checks.
  Well-formed means: correct JSON schema, valid on-chain `Unlock`
  event reference, and either a self-auth or a passing `on_behalf_of`
  notary attestation.
- **Durability:** geo-replicated storage with at least two independent
  power/network domains. Agents MUST document their own replication
  topology in a public transparency statement.
- **Incident reporting:** any availability or durability incident that
  affects > 1% of stored escrows MUST be disclosed to affected Holders
  within 72 h of detection.

## 16.3 Liability

- **Ceiling:** the annual fee multiplied by the number of years the
  escrow has been active, capped at a pilot-defined limit.
- **Scope:** ciphertext-loss remediation only. Agents never learn
  plaintext `R` (the share is hybrid-KEM-sealed under the agent's
  public key and the ciphertext is Shamir-split so a single agent
  holds no usable material), so there is no plaintext-exposure
  liability.
- **Force majeure clause:** RECOMMENDED. Specifically excluded should be
  LOTL trust-root changes outside the agent's control and failures of
  the EU trust framework as a whole.
- **Cross-agent coordination:** liability is **not joint-and-several**
  across agents. A Holder whose ciphertext is lost by agent N still
  recovers via the surviving t-of-N threshold; individual agent
  liability is bounded to remediation cost (re-sharing from remaining
  agents + any incidental costs).

## 16.4 Termination

- **Agent-initiated:** 90-day notice to affected Holders. Holders MUST
  re-register with a replacement agent or revoke the escrow. After the
  90-day window, the departing agent MAY destroy the ciphertext.
- **Holder-initiated:** any time via `revokeEscrow` on-chain. Agents
  SHALL tombstone the ciphertext within 24 h of observing the
  `EscrowRevoked` event; ciphertext is overwritten with random bytes,
  metadata retained for 1 year for audit.
- **Regulatory termination:** if a national supervisory body withdraws
  an agent's QTSP status, the agent MUST notify all affected Holders
  within 72 h of receiving the withdrawal notice, and MUST cooperate
  with the Holder's designated replacement agent.

## 16.5 Notary-assisted recovery

For the notary-assisted heir recovery path (plan §0.4 `on_behalf_of`):

- Agents MUST verify the notary certificate chains to the EU LOTL (same
  chain-validation path used for Holder QES at `registerEscrow` time).
- Agents MUST reject attestations where the notary certificate's
  `subject` field does not match the jurisdiction the Holder named in
  their inheritance rider (off-chain cross-reference; agents MAY cache
  this mapping at `registerEscrow` time).
- Agents MUST log (`notary_subject`, `timestamp`, `escrowId`) for each
  accepted notary-driven recovery. Logs are retained per jurisdictional
  audit requirements.

## 16.6 Pricing guidance (non-binding)

Pilot price ranges, indicative only:

- Individual inheritance escrow: **€50–€150 / year / agent** (three
  agents typical → €150–€450 / year total).
- Regulated-entity custody escrow: **€500–€2000 / year / agent**,
  subject to liability ceiling negotiation.

Actual pricing is a per-agent business decision.
