# `@qkb/lotl-flattener` — Maintainer Notes

## Purpose

Offline Node CLI that turns the EU **List of Trusted Lists** into the
inputs the QKB protocol needs on-chain and in-circuit:

- Walk the LOTL → each Member State Trusted List → every QES-issuing CA
  certificate (`Svctype/CA/QC` + `Svcstatus/granted`).
- Canonicalize each CA's DER, hash it with Poseidon over BN254, place
  every hash as a leaf in a fixed-depth-16 binary Merkle tree.
- Emit `trusted-cas.json`, `root.json`, `layers.json`. The Merkle root
  `rTL` is the public input the circuit and registry both bind to.

This package is **not** part of the trusted computing base of any single
proof. It runs periodically (manually for now), and its outputs are
checked into the repo and pushed on-chain via admin multisig.

## How to run

All commands assume the repo root and pnpm 9.x.

```bash
# Tests (Vitest, ~2 s)
pnpm --filter @qkb/lotl-flattener test

# Type-check + emit JS to dist/
pnpm --filter @qkb/lotl-flattener build

# Run the CLI against the synthetic fixture
pnpm --filter @qkb/lotl-flattener build
node packages/lotl-flattener/dist/index.js \
  --lotl packages/lotl-flattener/fixtures/lotl-mini.xml \
  --out  /tmp/flat-out \
  --lotl-version mini-fixture
```

The CLI takes:

- `--lotl <path>` (required) — local path to the LOTL XML.
- `--out <dir>` (required) — output directory (created if missing).
- `--lotl-version <id>` (default `unknown`) — written verbatim into
  `root.json.lotlVersion`.
- `--tree-depth <n>` (default 16) — must match `TREE_DEPTH` in
  `src/index.ts`; circuits and contracts assume 16 in Phase 1.

`run(opts)` is exported from `src/index.ts` so tests and other tooling
can inject an `msTlLoader` (e.g. read MS TL XML from disk instead of
fetching).

## Pipeline stages

```
LOTL XML ── parseLotl ──▶ pointers ─┐
                                    ▼
              loader(p.location)  msTl XML ── parseMsTl ──▶ RawService[]
                                                          │
                              filterQes (CA/QC + granted) │
                                                          ▼
                              extractCAs (pkijs DER parse) │
                                                          ▼
                              canonicalizeCertHash (Poseidon)
                                                          │
                              buildTree (depth 16)        │
                                                          ▼
                              writeOutput (3 JSON files)
```

| File                              | Stage                              |
|-----------------------------------|------------------------------------|
| `src/fetch/lotl.ts`               | LOTL XML → `LotlPointer[]`         |
| `src/fetch/msTl.ts`               | MS TL XML → `RawService[]`         |
| `src/filter/qesServices.ts`       | Keep `CA/QC` + `granted` services  |
| `src/ca/extract.ts`               | DER → `{certDer, issuerDN, validFrom, validTo}` via pkijs |
| `src/ca/canonicalize.ts`          | DER → `bigint` Poseidon hash       |
| `src/tree/merkle.ts`              | Hashes → `{root, layers}` + inclusion proofs |
| `src/output/writer.ts`            | Writes the three artifact files    |
| `src/index.ts`                    | `run()` + commander CLI            |

## Hard algorithmic locks

These behaviours are pinned in lockstep with `@qkb/circuits`. **Do not
change without coordinated edits to the circom mirror in
`packages/circuits/circuits/`.**

### `canonicalizeCertHash` (`src/ca/canonicalize.ts`)

1. Pack the DER into field elements, **31 bytes per chunk, big-endian**
   within each chunk (first byte = highest-order byte of the field).
   Last chunk may be shorter; do **not** zero-pad inside the integer.
2. Append exactly one extra field element whose value is
   `BigInt(der.length)` — the length-domain separator.
3. Sponge: Poseidon **width 16, rate 15, capacity 1** on BN254. Initial
   state element = 0. Each round consumes the previous state[0] in
   slot 0 plus up to 15 input chunks; pad the trailing window with 0.
4. Output = `state[0]` after the final round, returned as `bigint` in
   `[0, p)` where p is the BN254 scalar field modulus.
5. Library: `circomlibjs.buildPoseidon()`, instance cached at module
   scope.

Snapshot test (`tests/ca/canonicalize.test.ts`) pins the hash for
`fixtures/certs/test-ca.der`:

```
3343320682401079542006381927947751400566902976482490538395564021405243591237
```

If you ever intentionally change the chunking, you MUST also bump the
circuit's mirror, regenerate this snapshot, and notify circuits-eng
before merging.

### Merkle tree (`src/tree/merkle.ts`)

- Binary, **`node = Poseidon(left, right)`** (two-input Poseidon).
- **Fixed depth 16** in Phase 1 (`TREE_DEPTH` in `src/index.ts`,
  `treeDepth` in orchestration §2.1).
- Zero subtrees: `zero[0] = 0`, `zero[i] = Poseidon(zero[i-1], zero[i-1])`.
  Missing siblings at level *L* are the value `zero[L]`, **not** literal 0.
- `proveInclusionAsync(layers, index)` returns `{path, indices}` with
  `indices[L] = 0` if the current node is the left child at level L,
  `1` otherwise.

### Output schemas

The three artifacts conform to **orchestration §2.1**
(`docs/superpowers/plans/2026-04-17-qkb-orchestration.md`). That doc is
the source of truth — when in doubt, read it before editing
`src/output/writer.ts`. Notable invariants:

- `cas[].merkleIndex == position in cas[]` (writer preserves caller
  order; caller MUST order `cas[]` to match the leaves in `layers[0]`).
- BigInts serialize as **lower-case `0x`-prefixed hex, even-length
  payload** (single hex digit values pad to two). Round-trips losslessly
  through `BigInt('0x...')`.
- `layers.json` is an extension of the original spec for web-eng's
  runtime Merkle-path construction. Shape: `{depth, layers: hex[][]}`.

## Fixtures

| Path                                              | Purpose                            |
|---------------------------------------------------|------------------------------------|
| `fixtures/lotl-mini.xml`                          | Synthetic 2-MS LOTL                |
| `fixtures/ms-tl-ee.xml`, `ms-tl-pl.xml`           | Synthetic MS TLs (CA/QC + unspecified, both with the test cert embedded) |
| `fixtures/certs/test-ca.der`                      | Self-signed RSA-2048 test CA       |
| `fixtures/expected/root.json`                     | Pinned `rTL` for the e2e mini run  |
| `fixtures/lotl/2026-04-17-lotl.xml` (TBD)         | Real EU LOTL snapshot — owned by the team lead, not yet committed; required for Task 10 reproducibility |

### Regenerating the test CA

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout /tmp/k.pem -out /tmp/c.pem -days 3650 -nodes \
  -subj "/CN=QKB Test CA/O=QKB/C=EE"
openssl x509 -in /tmp/c.pem -outform DER \
  -out packages/lotl-flattener/fixtures/certs/test-ca.der
```

If you regenerate, the canonicalize snapshot AND the e2e expected
`root.json` will both shift. Update both, and re-embed the new base64
into both `ms-tl-*.xml` fixtures, in a single commit.

### Refreshing the real LOTL snapshot

When the lead drops `fixtures/lotl/<date>-lotl.xml` plus the per-MS TL
XMLs, wire Task 10:

1. Run the CLI against the snapshot, capture `root.json.rTL`.
2. Commit it as `fixtures/expected/root-pinned.json`.
3. Add a vitest in `tests/integration/e2e.test.ts` that re-runs the
   pipeline against the same snapshot and asserts byte-equality with
   the committed expected.

Drift in determinism (Poseidon impl, chunking, library version) will
fail this test and force coordination with circuits-eng.

## CI

Wired in `.github/workflows/ci.yml`, job `test-flattener`:

- Pinned to Node 20.11.1 + pnpm 9.1.0.
- `timeout-minutes: 10`.
- Steps: install (frozen lockfile) → `pnpm --filter @qkb/lotl-flattener
  build` → `pnpm --filter @qkb/lotl-flattener test`.

A nightly reproducibility job is planned (orchestration §7.2): rebuild
the flattener, re-derive the rTL from the pinned LOTL, byte-compare
against the committed `root-pinned.json`. Lands once Task 10 is unblocked.

## Gotchas

- **`circomlibjs` has no types.** Ambient declaration is at
  `src/circomlibjs.d.ts`. Don't `pnpm add @types/circomlibjs` — the
  package doesn't exist on npm.
- **XML namespace prefixes are stripped.** `fast-xml-parser` is
  configured with `removeNSPrefix: true` so element paths stay flat
  (`tsl.SchemeInformation.PointersToOtherTSL.OtherTSLPointer`). ETSI
  TS 119 612 documents always carry an explicit namespace; production
  LOTL parsers strip it the same way.
- **`pnpm-lock.yaml` is gitignored on worker branches.** The root
  `.gitignore` excludes it; do NOT `git add` it. The lead manages the
  root lockfile during merges to `main`.
- **BigInt JSON serialization is one-way through `JSON.stringify`** —
  hence the explicit `toHex()` in `src/output/writer.ts`. Re-reading
  uses `BigInt('0x…')` which is lossless.
- **`merkleIndex` is positional, not sorted.** The writer preserves
  caller order. If you ever reorder `cas[]` post-tree-build, you MUST
  rebuild the tree against the new order or the `layers[0]` indices
  will silently disagree with the JSON.
- **Default loader is filesystem-relative.** `run(opts)` resolves MS
  TL `<TSLLocation>` URIs relative to the LOTL XML's directory. For
  real network fetches, inject your own `msTlLoader`.

## Extending

### Adding a new LOTL source (e.g. UA national TL)

Adding outside the EU LOTL hierarchy means there's no `OtherTSLPointer`
to follow. Either:

1. Pre-merge the source's services into a synthetic LOTL XML that
   `parseLotl` can consume (cheap, no code change), or
2. Add a sibling fetcher in `src/fetch/` and call it from `run()`. Keep
   the downstream `RawService[]` shape identical so `filterQes` and
   `extractCAs` remain unchanged.

### Adding a new output field

If circuits/contracts/web all need it: edit orchestration §2.1 first,
then mirror the schema change in `src/output/writer.ts` and bump the
artifact `version` field. Otherwise leave the artifact alone and expose
the field via a separate file.

### Rotating the Merkle depth

Treat as a coordinated breaking change:

1. Update `TREE_DEPTH` in `src/index.ts` and `treeDepth` in any
   fixture/expected JSON.
2. Notify circuits-eng — `MerkleProofPoseidon.circom` is parameterized
   by depth; the production `.r1cs`/`.zkey`/`.wasm` triple needs a full
   circuit rebuild + new ceremony.
3. Update `QKBRegistry`'s `trustedListRoot` rotation procedure docs;
   the on-chain root storage isn't depth-aware but proofs against the
   new tree won't verify against old verifying keys.

## Phase-1 explicit non-goals

These are deliberately out of scope; reject PRs that try to add them
without an updated spec:

- **Live EU LOTL fetches in CI.** Production refreshes are manual
  ops-flavoured runs by the lead; the package only supports them via
  the swappable `msTlLoader` interface.
- **DSTU-4145 cert parsing.** Ukraine's national curve. Phase 1 covers
  RSA-2048 and ECDSA-P256 only (per orchestration §2.0). Adding DSTU
  requires both a cert-parsing extension here AND a circuit variant.
- **Historical trusted-list-root tracking.** Registry stores only the
  current root; users prove against it. Old roots are not retained.
  Don't add a `previousRoots[]` array to the artifacts.
- **Sorting `cas[]` by `poseidonHash`.** Earlier plan wording suggested
  this; it conflicts with the position-defines-merkleIndex contract.
  Caller orders, writer preserves.
