# Shared test fixtures

Fixtures live here so every package can read them without cross-package coupling.

## Contents (populated by team lead before dispatching Task 7/10 of circuits and contracts)

- `qes-certs/ua-diia/` — Ukrainian test QES material: `leaf.pem`, `int.pem`, `root.pem`, `signed.p7s`, `binding.qkb.json`. Sourced from KICRF test infra or generated offline with a test CA matching the same DN/algorithm profile.
- `qes-certs/ee-sk/` — Estonia SK-issued test QES material, same layout.
- `lotl/2026-04-17-lotl.xml` — pinned EU LOTL snapshot. Obtained from `https://ec.europa.eu/tools/lotl/eu-lotl.xml` on the date.
- `lotl/ms-tls/` — per-MS TL XML fragments referenced by the pinned LOTL.
- `declarations/en.txt`, `declarations/uk.txt` — canonical declaration texts, LF line endings, UTF-8, no trailing newline. Their SHA-256 digests are hard-coded in `packages/circuits/circuits/binding/DeclarationWhitelist.circom` and `packages/contracts/src/constants/DeclarationHashes.sol`.
- `integration/ua-diia/` — pre-computed circuit inputs for the positive integration test (produced by `packages/circuits/inputs/fixture-builder.ts`).

## Ground rules

- Fixtures are committed. Regenerating them changes CI expectations — do it intentionally and bump the snapshot date.
- Real QES **private keys** never live here. Only signatures + certs.
- When a fixture changes, cross-reference: flattener baseline, circuit declaration digests, contract `DeclarationHashes`, web i18n declaration strings all agree.
