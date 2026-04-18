# Person-Level Nullifier — Spec Amendment

> Amends §14.4 of `2026-04-17-qie-phase2-design.md` and §13.4 of `packages/contracts/CLAUDE.md`. Date: 2026-04-18. Status: authoritative.

## Motivation

The prior Phase-2 nullifier construction was:

```
secret    = Poseidon(subject_serial_limbs, issuer_cert_hash)
nullifier = Poseidon(secret, ctxHash)
```

This binds the nullifier to a specific **certificate**, not to a **person**. Every eIDAS QES is reissued every 1–3 years with a fresh serial and subject public key. Under the prior construction, the same natural person produced a different nullifier after each renewal — defeating Sybil resistance at the DAO / airdrop / regulated-entity layer, where "one human per context" is the whole point.

## New construction

```
rnokppBytes  = subject.serialNumber attribute content (OID 2.5.4.5, PrintableString)
rnokppLen    = byte length of that content (1..16)
rnokppPadded = rnokppBytes ∥ 0x00 × (16 - rnokppLen)

secret       = Poseidon(Poseidon(rnokppPadded), rnokppLen)
nullifier    = Poseidon(secret, ctxHash)
```

`rnokppPadded` is a fixed-size 16-byte array; `Poseidon(rnokppPadded)` is a 16-input Poseidon over byte field elements. Hashing `rnokppLen` alongside the inner digest prevents padding-collision between identifiers of different natural lengths (e.g. an 8-byte EDRPOU vs a 10-byte РНОКПП vs a 12-byte passport number).

## eIDAS scope

ETSI EN 319 412-1 §5.1.3 — mandatory for every eIDAS QES — requires the subject `serialNumber` (OID 2.5.4.5) to carry a **semantics identifier** in the format:

```
<3-letter-type><2-letter-country>-<national-unique-id>
```

where `<3-letter-type>` ∈ `{PAS, IDC, PNO, TAX, …}` per ETSI TS 119 412-1 Annex A. Examples:

| Value                 | Country | Scheme                    |
|-----------------------|---------|---------------------------|
| `PNOUA-3456789012`    | UA      | РНОКПП (natural person)   |
| `PNODE-12345678`      | DE      | Steuer-ID                 |
| `PNOFR-1850799123456` | FR      | NIR                       |
| `PNOPL-89030303030`   | PL      | PESEL                     |
| `TINPL-1234567890`    | PL      | Tax identification number |
| `PASDE-C01X00T47`     | DE      | Passport number           |

The circuit hashes the raw PrintableString content bytes. It does NOT parse the semantics prefix. Consequently:

- **Pan-eIDAS coverage**: any ETSI-compliant QES works without circuit changes. The primitive generalizes beyond Ukraine.
- **Identifier-scheme-scoped**: a person who holds both `PNODE-…` and `PASDE-…` certs from the same QTSP produces two distinct nullifiers — one per identifier scheme. This is intentional; normalizing across schemes would introduce gaming (pick whichever cert yields a fresh nullifier). Applications that want strict one-human-ever should pin a single identifier-type prefix off-chain.
- **Non-ETSI QES**: certs without OID 2.5.4.5 fail witness generation with `witness.rnokppMissing`. The web SPA surfaces this as "This flow currently requires an ETSI EN 319 412-1 compliant eIDAS QES."

## On-chain / interface compatibility

- `QKBVerifier.Inputs.nullifier` (bytes32) — unchanged.
- Public-signal index 13 — unchanged.
- `QKBRegistry.usedNullifiers` / `nullifierToPk` / `revokedNullifiers` — unchanged.
- `revokeNullifier(bytes32, bytes32)` — unchanged.

Contracts require no rebuild. The change is circuit-internal (new witness inputs, new Poseidon sub-circuit) plus witness-builder (new offset + padded-bytes fields).

## Backwards compatibility

**None required.** The Phase-1 Sepolia deployment at `0x7F36aF783538Ae8f981053F2b0E45421a1BF4815` shipped with 13-signal proofs (no nullifier) and remains addressable for existing Phase-1 bindings. The Phase-2 `QKBRegistryV2` at `0xcac30ff7B0566b6E991061cAA5C169c82A4319a4` (deployed 2026-04-18) has `usedNullifiers` empty — no prior production registrations to migrate. This amendment therefore lands transparently; the first registration against the rebuilt circuit writes the first entry.

## Constraint budget

ECDSA leaf+chain: currently 7.63 M constraints; hard cap 8 M. The new sub-circuit adds:

- 16× byte-range check (`LessThan(9)`) — ~16 × 12 = 192 constraints
- 2× length bound check — ~40 constraints
- 16× padding-zero invariant — ~16 × 30 = 480 constraints
- 1× `Asn1ShortTLVCheck` (already present pattern) — ~2 × 12 = 24 constraints
- 16× Multiplexer slice from leafDER — ~16 × MAX_CERT = ~24 k constraints
- 2× `LessEqThan(16)` / `GreaterEqThan(16)` bounds — ~30 constraints
- 1× `Poseidon(16)` — ~3.5 k constraints
- 2× `Poseidon(2)` — ~600 constraints

Total estimate: ~30 k constraints, well under the 80 k ceiling I allowed in the plan. If compile reports > 7.95 M, fall back to a split proof (auxiliary nullifier circuit chained by `leafSpkiCommit` equality).

## Witness-builder contract

The witness builder MUST supply these new fields alongside existing inputs:

| Field | Type | Source |
|---|---|---|
| `rnokppOffset` | uint (absolute offset in `leafDER`) | pkijs-parsed subject RDN walk, located via unique subarray match |
| `rnokppLen` | uint 1..16 | length of the PrintableString content |
| `rnokppPadded[16]` | uint[16] | content bytes zero-padded to 16 |

Public signal `nullifier` is derived off-circuit by `buildPersonSecret` + `buildNullifier` (see `packages/circuits/src/witness/nullifier.ts`) and compared constraint-side.

## Test surface

- `test/nullifier.test.ts` — unit tests for the witness helpers (stable, differs-for-different-input, length-bound, length-hashing).
- `test/PersonNullifier.test.ts` — circuit unit test with KAT vectors.
- `test/QKBPresentationEcdsa.e2e.test.ts` — extended to assert the E2E-produced nullifier matches `fixtures/nullifier-kat.json#admin-ecdsa`.
- `fixtures/nullifier-kat.json` — contains `admin-ecdsa` and `synth-de` entries to prove pan-eIDAS coverage.

## Out of scope

- **RSA variant.** Still deferred until we have non-Diia RSA QES test material. When it lands, the same `PersonNullifier` primitive wires in unchanged — only the leaf-cert DER path differs.
- **Normalization across schemes.** See eIDAS scope note above — explicitly out.
- **Cross-QTSP deduplication.** Two QTSPs issuing certs to the same person produce the same nullifier (both derive from OID 2.5.4.5 which is the state-issued identifier, not a QTSP artefact). This is a property, not a limitation.
