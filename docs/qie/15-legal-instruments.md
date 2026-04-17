# QIE §15 — Legal instrument templates

These templates are **non-normative**. They are provided as starting points
for pilot partners to adapt with their own counsel. They are not legal
advice and have not been reviewed by a licensed attorney in any
jurisdiction.

## 15.1 Inheritance rider (will attachment)

**Purpose:** bind an on-chain `escrowId` to the testator's estate so a
future beneficiary can reconstruct the recovery material `R` under a
formally specified condition (death of the testator, established by a
certified death certificate).

**Required fields:**

- Testator's full legal name, date of birth, jurisdiction of residence.
- `escrowId` (32-byte hex string, exactly as registered on-chain).
- Arbitrator address (EIP-55 checksummed hex, network identifier).
- Evidence trigger:
  - `kindHash = keccak256("death_certificate")`
  - `referenceHash` = sha-256 of the canonical issuing-authority reference
    (e.g. UK GRO registration number, German Sterbeurkunde Nr., Ukrainian
    свідоцтво про смерть номер).
- Beneficiary identification — legal name, two independent contact
  channels (email + phone is the minimum), and a back-up route the notary
  can verify independently.
- Fee schedule — annual escrow fee, denominated per-agent (§16).

**Template clauses (illustrative):**

1. *"I, [testator], hereby irrevocably declare that the digital record
   identified by `escrowId = [id]` on arbitrator contract `[addr]`
   constitutes a component of my estate. On production of a certified
   death certificate matching `referenceHash = [ref]`, my executor is
   authorised to instruct the arbitrator to release the recovery
   material to the beneficiary identified below."*
2. *"The beneficiary, on receipt of the recovery material, shall use it
   only to re-bind the underlying qualified credential to a wallet under
   their own control, and shall not disclose or onward-transfer the
   material to any third party."*
3. *"Revocation of this rider requires notarised revocation of the
   escrow on-chain by the testator during their lifetime via the
   `revokeEscrow` mechanism; revocation after death has no effect."*
4. *"Disputes arising from this rider shall be resolved in the courts of
   [jurisdiction] under the law of [jurisdiction]."*

**Arbitrator-side prerequisites:**

The arbitrator-operator (typically a notary) must hold the private key
corresponding to the `authority` address set in the `AuthorityArbitrator`
constructor. On receipt of the certified death certificate, the notary:

1. Computes `evidenceHash = sha-256(death_cert_pdf_bytes)`.
2. Signs the digest `keccak256(abi.encode(escrowId, recipientHybridPk, evidenceHash, kindHash, referenceHash, issuedAt))`
   with a secp256k1 key matching `authority`.
3. Submits the 7-arg `requestUnlock` call.

## 15.2 Custody agreement (regulated entity)

**Purpose:** govern the relationship between the entity holding the QKB
(the *Principal*), the QTSPs acting as agents (the *Custodians*), and
the holder of the arbitrator key (the *Arbitrator-Operator*, typically
outside counsel or a board resolution signer).

**Required sections:**

- Parties — legal names, seats, regulatory registrations.
- Scope — reference to the specific `escrowId` and the on-chain
  arbitrator address.
- Operational SLA — cross-reference to `docs/qie/16-operational-model.md`
  §16.2.
- Liability limit — per-escrow annual cap; see §16.3.
- Termination and re-provisioning — the procedure by which a departing
  Custodian is replaced (revoke + re-register against a new agent set).
- Evidence policy — what the Arbitrator-Operator will accept as a
  release trigger (e.g. a dated board resolution signed by a quorum of
  directors; a court order; a regulator notice). Enumerate specifically.
- Governing law and dispute resolution.

**Template status:** outline only. A full template is deferred until the
first regulated-entity pilot conversation clarifies which jurisdiction's
corporate-governance law applies.

## 15.3 Evidence-envelope provenance

Every `AuthorityArbitrator.requestUnlock` call emits an
`UnlockEvidence(bytes32 escrowId, bytes32 kindHash, bytes32 referenceHash, bytes32 evidenceHash, uint64 issuedAt)`
event immediately before the `Unlock` event. Relying parties — agents,
recipients, courts — may use the envelope to audit *why* a release was
authorised. The envelope is intentionally minimal: four 32-byte hashes
plus a timestamp. The underlying documents stay off-chain under the
custody of the Arbitrator-Operator subject to their retention policy.

**Recommended retention:** the Arbitrator-Operator retains the canonical
`referenceHash`-preimage document and the `evidenceHash`-preimage PDF
for the statute-of-limitations period applicable in their jurisdiction
(typically 7–10 years).
