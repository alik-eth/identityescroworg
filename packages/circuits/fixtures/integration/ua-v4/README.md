# UA leaf V4 synthetic smoke KAT

## What

A round-trip Groth16 proof for the UA leaf V4 circuit (`ZkqesPresentationEcdsaLeafV4_UA.circom`) against the ceremonied artifacts from commit `e1b822f`.

## What this validates

- The UA leaf ceremony is **internally consistent**: the wasm, zkey, and vkey trio produces proofs that verify.
- The 16-signal public-input shape matches between the circuit, the witness-builder, and `LeafVerifierV4_UA.sol`.
- BindingParseV2Core + signedAttrs + ECDSA-P256 + Poseidon Merkle + nullifier derivation + DOB extractor all satisfy every constraint against a hand-built zkqes binding (version "QKB/2.0" frozen; see specs/2026-05-03-zkqes-rename-design.md §3).

## What this does NOT validate

- This is NOT a real Diia QES. The leaf cert is a synthetic byte container — NOT a valid X.509. The signing key is an ephemeral P-256 generated in-memory.
- The binding is synthetic (policy `qkb-smoke/v1`, not the real `qkb-default-ua`). <!-- qkb-default-ua is a frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3 -->
- `dobSupported` is 0 because the synthetic leaf DER has no `2.5.29.9` outer anchor. The Diia-specific DOB extraction path is covered by the DOB unit tests from the circuits task #16, not by this smoke.
- Do NOT use this fixture to assert on-chain registry acceptance on Sepolia — the signals here do not match any real trusted-list root or policy root.

## How to reproduce

```
cd packages/circuits
node scripts/smoke-ua-leaf-v4-synthetic.mjs
```

Requires: ceremony artifacts at `build/ua-leaf/` from the `e1b822f` ceremony commit (zkey SHA `0xd43cc46c…`, wall ~4 min for fullProve on 6.38M constraints).

## Committed outputs

- `leaf-synthetic-zkqes2.proof.json` — Groth16 proof (π_a, π_b, π_c)
- `leaf-synthetic-zkqes2.public.json` — 16 public signals in leaf order

Keys generated at commit time:

```
public[12] nullifier:     19325880876914286994313297572547190914755939137277584459545786287195189852578
public[14] dobCommit:     12583541437132735734108669866114103169564651237895298778035846191048104863326
proof.json sha256 first-8: eecb288f
fullProve wall:            234.1s
```

## Follow-up (task #24)

Once web-eng ships zkqes binding generation (version "QKB/2.0" frozen) in task #14, the real-Diia smoke (task #24) replaces synthetic leaf DER / keys with a live Diia QES signature. That one will exercise `DobExtractorDiiaUA`'s `2.5.29.9 → 1.2.804.2.1.1.1.11.1.4.11.1 → PrintableString` path end-to-end.
