# identityescroworg

**Qualified Key Binding (QKB)** and **Qualified Identity Escrow (QIE)** — pseudonymous cryptographic identity with state-grade legal weight, built on [Regulation (EU) 2024/1183 (eIDAS 2.0)](https://eur-lex.europa.eu/eli/reg/2024/1183/oj) primitives.

A Holder produces a self-generated keypair, signs a declaration binding that public key to their legal identity using any Qualified Electronic Signature (QES) issued by an EU-trusted QTSP, and then proves the binding under a zero-knowledge proof — revealing nothing about the QES, the certificate, or the QTSP, only that *some* qualified signature exists behind the key. An on-chain registry records the binding. A future escrow layer (Phase 2) adds threshold-held, post-quantum-encrypted recovery material so the binding can be deanonymized under formally-specified conditions.

## Status

- **Phase 1 — QKB:** in active development (see `docs/superpowers/plans/`). Real-QES validation passes against Ukrainian Diia QES (ECDSA-P256). Sepolia deployment + `identityescrow.org` Fly.io hosting pending the final ceremony.
- **Phase 2 — QIE:** design frozen (`docs/superpowers/specs/2026-04-17-qie-phase2-design.md`) and amended for the MVP wedge (`docs/superpowers/specs/2026-04-17-qie-mvp-refinement.md`). MVP scope targets three Tier 1 segments — **inheritance / estate planning**, **regulated-entity crypto custody**, and **KYC-recovery in regulated DeFi** — shipping with `AuthorityArbitrator` only, dual-variant prover (RSA-PSS + ECDSA), an explicit escrow state machine, a notary-assisted heir recovery flow, and evidence envelopes on arbitrator releases. `TimelockArbitrator` and standalone recipient UX deferred post-pilot. Dispatch of the MVP amendment is in flight; full Phase 2 tag gated on Phase 1 deploy.

## Documents

- **Design specs:** [`docs/superpowers/specs/`](docs/superpowers/specs/)
  - [Phase 1 QKB design](docs/superpowers/specs/2026-04-17-qkb-phase1-design.md)
  - [Phase 2 QIE design](docs/superpowers/specs/2026-04-17-qie-phase2-design.md)
  - [Phase 2 QIE MVP refinement](docs/superpowers/specs/2026-04-17-qie-mvp-refinement.md) — Tier 1 wedge scope deltas.
- **Implementation plans:** [`docs/superpowers/plans/`](docs/superpowers/plans/) — per-phase orchestration + per-package plans, plus cross-worker amendments.
- **QIE operational docs:** [`docs/qie/`](docs/qie/) — §15 legal instrument templates, §16 operational model (agent fees, SLA, liability).
- **Ceremony:** [`docs/ceremony/`](docs/ceremony/) — trusted-setup transcript, artifact hashes.

## Architecture

### Phase 1 — QKB

```
Holder                  Circuits (Groth16)         On-chain
------                  ------------------         --------
1. generate (sk, pk)    R_QKB witness:             QKBRegistry.register(pk, π)
2. build binding B           B, σ_QES, cert,
   { pk, declaration,        Merkle path to r_TL      ↓
     timestamp, nonce }                             verifies π via
3. sign B with QES →                                RSA- or ECDSA-verifier
   σ_QES (detached                                  (library contract)
   CAdES-BES)                ↓
4. prove R_QKB →        Groth16 proof π           EscrowRegistered (Phase 2)
   public pk, r_TL      ───────────────────────→
```

The `R_QKB` relation asserts in-circuit: QES verify, certificate Merkle inclusion in the EU trusted list, binding → signed-attributes digest chain, binding contains the claimed `pk`, certificate validity window covers `B.timestamp`. Nothing else leaks.

### Phase 2 — QIE

```
Holder                 QTSP Agents (k-of-n)         Recipient
------                 --------------------          ---------
R = {B, σ_QES, cert}   agent_i holds                release predicate
  ↓ AES-256-GCM         wrapped_share_i             (on-chain Unlock event
  with k_esc                (hybrid X25519 +         OR Holder QES countersig)
  ↓ Shamir split         ML-KEM-768 KEM)
  {s_1…s_n} over         → acks                     fetch ≥ t shares
  GF(2^256)              →                          ────────────────→
                                                     reconstruct k_esc → R
QKBRegistry.registerEscrow(pk, hash(E))             Phase 1 verify on R
```

Qualified Trust Service Providers act as dumb custodians. Release yields the raw recovery material; the recipient independently re-verifies against Phase 1's chain. Escrow envelopes are post-quantum-safe by construction (hybrid KEM on every share + information-theoretic Shamir on the key). Release is gated by an on-chain state machine (`ACTIVE → RELEASE_PENDING → RELEASED`, with a 48 h Holder cancellation window) and by a typed evidence envelope the authority submits alongside its signature, so downstream parties can audit *why* a release was authorised.

## Packages

- [`packages/lotl-flattener`](packages/lotl-flattener) — offline CLI; EU LOTL → Poseidon Merkle CA set (`trusted-cas.json`, `root.json`). Phase 2 adds `qie-agents.json`.
- [`packages/circuits`](packages/circuits) — Circom circuits for `R_QKB` (RSA + ECDSA-P256 variants), Groth16 artifacts, generated `Verifier.sol`.
- [`packages/contracts`](packages/contracts) — `QKBVerifier` library + `QKBRegistry` reference contract (Foundry). Phase 2 adds `AuthorityArbitrator` (with evidence-envelope emission) and the escrow state machine (`ACTIVE → RELEASE_PENDING → RELEASED` + Holder cancellation window); `TimelockArbitrator` is stubbed and deferred post-MVP.
- [`packages/web`](packages/web) — TanStack Router static SPA; binding generator, in-browser snarkjs prover, registry client. EN + UK. Phase 2 adds `/escrow/setup` and the notary-assisted `/escrow/notary` recovery flow (standalone self-recovery remains reachable via `?mode=self`).
- [`packages/qie-core`](packages/qie-core) *(Phase 2)* — hybrid KEM, Shamir, envelope codec, predicate evaluator. Pure TS, browser + Node.
- [`packages/qie-agent`](packages/qie-agent) *(Phase 2)* — Fastify HTTP custodian reference implementation.
- [`packages/qie-cli`](packages/qie-cli) *(Phase 2)* — operator/holder/recipient CLI.
- [`deploy/mock-qtsps`](deploy/mock-qtsps) *(Phase 2)* — docker-compose harness: 3 mock QTSP agents + anvil + arbitrators for E2E testing.

## Prerequisites

- Node 20.11.x (see `.nvmrc`)
- pnpm 9.1.x
- Foundry (`forge`, `cast`, `anvil`)
- circom 2.1.9
- Docker + docker-compose (Phase 2 only)

## Getting started

```bash
pnpm install
pnpm test        # run all package tests
pnpm lint
pnpm build
```

### Produce a binding to sign via a real QES

```bash
pnpm binding:admin                              # writes ./binding.qkb.json
# Take binding.qkb.json to your QES provider (Diia Підпис, etc.)
# Sign it as detached CAdES-BES (SHA-256).
pnpm verify:real-qes binding.qkb.json binding.qkb.json.p7s
```

The verifier expects the signed `.p7s` alongside the public `.json` binding. Detached CAdES `.p7s` files are git-ignored globally — they are bound to a natural person's legal identity and must never be committed.

## Deployment

- **Sepolia** is the primary testnet.
- **`identityescrow.org`** serves the static SPA via Fly.io.
- Admin key at deploy-time lives in root `.env` (git-ignored). Never commit secrets.

## Legal framing

- **QKB** produces pseudonymous identities with legally binding effect — each binding declaration is a signed statement under Art. 25 of eIDAS accepting responsibility for actions cryptographically attributable to the key.
- **QIE** is proposed as a qualified trust service under Art. 3(19) and Art. 47 of Regulation (EU) 2024/1183. Phase 2 ships mock QTSPs; production adoption requires real qualified providers and an ETSI-published service-type URI.

Together, the constructions resolve the tension in eIDAS 2.0 between the unlinkability requirement of Art. 5a(16) and the static-signature assumptions of the current Architecture Reference Framework.

## License

**GPLv3** — see [`COPYING`](COPYING). The entire repository adopts GPLv3 because the ECDSA-P256 circuit vendor ([`privacy-scaling-explorations/circom-ecdsa-p256`](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256)) is GPLv3 and its constraints propagate through the compiled `.zkey` and generated `Verifier.sol`. MIT-licensed upstream sub-components (zk-email RSA circuits, snarkjs, circomlib) remain under their original licenses within their vendor directories — see per-directory `PROVENANCE.md`.

## Acknowledgements

Funding sought from NLNet NGI Zero Commons Fund for Phase 2 QIE implementation. Circuits built on [zk-email](https://github.com/zkemail) (RSA) and [PSE's circom-ecdsa-p256](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256) (ECDSA). The Qualified Key Binding and Qualified Identity Escrow constructions are presented in full in [`docs/superpowers/specs/`](docs/superpowers/specs/).
