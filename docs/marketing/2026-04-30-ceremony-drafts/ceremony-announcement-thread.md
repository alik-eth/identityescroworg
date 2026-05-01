# Ceremony Announcement — X Thread

**Status:** Draft for review. Not for publication.
**Date:** 2026-04-30
**Posting gate.** Only after at least five core contributors have confirmed. Not the launch thread; the launch thread lives at `2026-04-29-launch-drafts/x-thread-launch.md` and goes out at T-day after the ceremony has finalised.
**Audience.** ZK Twitter and Ukrainian crypto. Goal: amplify the ceremony in flight, surface the contributor chain as social proof, invite additional civic participation.
**Branding.** Lead with zk-QES; the ceremony is a protocol-layer artefact, not a project-level announcement.
**Constraint check.** Zero emoji. Zero argot. Each tweet ≤ 280 characters; counted in brackets.

---

## T1 — opening

A multi-party trusted setup is underway for zk-QES, the zero-knowledge protocol that lets an eIDAS qualified electronic signature authorize a wallet on chain.

Phase 1 is the public Hermez Powers of Tau. Phase 2 is the contributor chain we are running now.

[259]

---

## T2 — what zk-QES is, in one breath

The protocol proves possession of a valid qualified signature whose issuing chain anchors in the European Union List of Trusted Lists. Initial jurisdiction is Ukraine; the signing key is sourced from Diia.

The chain learns a nullifier, and nothing else identifying.

[268]

---

## T3 — what a Phase 2 ceremony does

Groth16 needs a structured reference string. The string is generated once, with private randomness; whoever holds that randomness can forge proofs.

A multi-party ceremony randomises it across many independent contributors. One honest contributor is enough.

[265]

---

## T4 — the contributor chain (so far)

Round 0 was seeded by the project's admin. The chain is now extending through {{N}} confirmed contributors, drawn from the ZK ecosystem and the Ukrainian crypto community.

Each contributor's handle and attestation hash is published as their round lands.

[279]

---

## T5 — live status

The status feed updates with each contribution.

`prove.identityescrow.org/ceremony/status.json`

The same data renders at `identityescrow.org/ceremony/status` — every round, every contributor, every attestation hash, polled and verifiable.

[266]

---

## T6 — open call

If you have a 32 GB-RAM PC, twenty minutes, and you would like to attest a derivative round once the core chain finalises, the four commands and the requirements live at:

`identityescrow.org/ceremony/contribute`

[238]

---

## T7 — what we publish

The contributor chain. The beacon block we will pin as final entropy. The verifier contract auto-generated from the final zkey. The verification key. The integrity hash of the final prover key. All of it open, all of it reproducible.

[267]

---

## T8 — closer

The protocol's source is open. The ceremony is open. The verifier will be deployed on Base as soon as the chain finalises and the deterministic-rerun verification clears.

`identityescrow.org/ceremony` for the full picture.

[245]

---

## Founder notes

- **{{N}} placeholder in T4.** Fill at posting time with the number of confirmed contributors at the moment of the post (5+ minimum per Phase A.A4 acceptance).
- **Threading sequence.** T1 is the hook; T2 explains zk-QES for any reader unfamiliar; T3 explains why a ceremony at all; T4 + T5 surface the social proof; T6 is the civic invitation; T7 is the transparency commitment; T8 closes with the link.
- **Open call posture.** T6 invites *derivative-round* attestation, not core-round contribution. The core is recruited personally; derivative rounds are open to anyone with a 32 GB machine. This matches the §11 spec: "community contributions are welcome after the core completes; community drops do not break chain."
- **Link discipline.** T5 surfaces the JSON feed (machine-readable) and the rendered page (human-readable). T6 surfaces the contribute page. T8 surfaces the umbrella. Three different links, three different audiences within the same thread.
