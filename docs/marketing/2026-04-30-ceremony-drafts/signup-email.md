# Ceremony Sign-up Email — Template

**Status:** Draft for review. Not for sending.
**Date:** 2026-04-30
**Audience.** Trusted ZK ecosystem contacts the founder is recruiting personally — PSE, 0xPARC, Mopro, Anon Aadhaar, Polygon ID, Lambdaclass, ETH Kyiv, individual ZK researchers.
**Use.** Founder adapts per contact. Verbatim where the rapport allows; abbreviated where the contact already knows the project.
**Voice.** Civic-monumental restraint. A serious technical request, not a marketing pitch. Naming follows `BRAND.md`: **QKB** is the protocol noun; **zk-QES** appears once in the opening as the descriptor; **Identity Escrow** is the project umbrella named once for context.

---

## Subject lines (pick one)

1. QKB Phase 2 ceremony — would you be a contributor?
2. Trusted-setup contribution request — QKB (zk-QES), ~20 min on a 32 GB PC
3. Phase 2 ceremony for QKB — contributor sign-up

---

## Body

> Hi {{name}},
>
> I am running a Phase 2 trusted-setup ceremony for QKB — a zero-knowledge protocol over qualified electronic signatures (zk-QES) that I have been building for the last several months under the project umbrella Identity Escrow. The protocol lets a holder of an eIDAS QES authorize a wallet on chain, in zero knowledge — initial jurisdiction Ukraine, signing key sourced from Diia, verifier on Base. Source is open: {{repo-url}}. Architecture spec: {{spec-url}}.
>
> The Groth16 circuit is roughly four million constraints and the final zkey will be on the order of 2.2 GB. I would like to recruit you as one of seven to ten trusted contributors for the multi-party Phase 2 of the QKB ceremony. Each contributor downloads the previous intermediate zkey, runs `snarkjs zkey contribute` with their own entropy, verifies, and uploads. So long as one contributor honestly destroys their entropy, the ceremony is sound.
>
> What is involved on your side:
>
> - A machine with 32 GB of RAM, around 5 GB of free disk, Node 20 or later, and snarkjs ≥ 0.7.4.
> - Approximately fifteen to twenty minutes of wall time, including the download and the upload.
> - Four CLI commands; the full instructions live at {{ceremony-contribute-url}}.
> - One contribution round per roughly twenty-four hours, sequential. I will send you a signed upload URL when your slot opens.
>
> If you agree to contribute, I would also ask:
>
> - **Confirmation:** yes or no.
> - **Public name:** the handle you would like attached to your contribution in the public attestation chain. Your real name, a pseudonym, an organisational affiliation — whatever you prefer.
> - **Optional:** a profile or homepage URL to link from the chain.
>
> I am keeping the core round at seven to ten contributors so the chain stays coordinable; community contributions are welcome after the core completes, attesting derivative rounds. There is no honorarium and there is no token. The ceremony output is the verifier that anchors the production deploy.
>
> Quiet acknowledgement is fine. If you would prefer not to, that is also fine; please say so and I will move on without follow-up.
>
> With respect,
>
> Alik.eth

---

## Notes for the founder when adapting

- **Length target.** ≤ 300 words. The version above is 286.
- **Personalisation.** Add one sentence at the top that names the contact's recent ZK work and the reason they specifically came to mind. Two examples: "I have been reading the Mopro mobile-prover work and the trade-offs you settled match the constraints we are gating on for our flagship-mobile tier." / "Anon Aadhaar's framing of state-issued credentials is the closest architectural cousin we have; I would be honoured to have you in the chain."
- **Repo + URLs.** Fill `{{repo-url}}`, `{{spec-url}}`, `{{ceremony-contribute-url}}` per current canonical. Suggested defaults: `github.com/qkb-eth/identityescroworg` (pending repo URL lock), `identityescrow.org/ceremony/contribute`.
- **Tone slider.** If the contact is a personal acquaintance, drop the "With respect" closer and use the contact's usual sign-off register. If the contact is approached cold (introduction via mutual), keep the formal closer.
- **Pseudonym handling.** A non-trivial number of replies will come back with "I'd prefer to attest under a pseudonym only." Pre-decided answer: yes, accepted; the chain treats handle as opaque.
