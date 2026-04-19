# @qkb/cli

Offline Groth16 proving for the QKB split-proof flow.

## Why

The SPA at `identityescrow.org` builds the leaf + chain witnesses in the
browser, but `snarkjs.groth16.fullProve` reliably OOMs browser tabs on the
4.5 GB leaf zkey. This CLI takes the witness bundle the SPA exports and
produces real Groth16 proofs against the committed ceremony zkeys.

## Install

Inside this repo:

```
pnpm install
pnpm --filter @qkb/cli build
```

Then run via pnpm (recommended):

```
pnpm --filter @qkb/cli start -- prove ~/Downloads/witness.json
```

Or directly:

```
NODE_OPTIONS=--max-old-space-size=16384 node packages/qkb-cli/dist/src/cli.js \
  prove ~/Downloads/witness.json
```

The CLI prints a heap-limit warning if Node's V8 heap is under ~12 GB. The
warning matters for `--backend snarkjs` (which actually needs 12–14 GB of
heap or OOMs mid-leaf). For `--backend rapidsnark` it's a false positive —
rapidsnark runs outside V8 and tops out around 4.7 GB RSS regardless of
Node's heap.

## Usage

```
qkb prove <witness-path> \
  [--out <dir>]                 default ./proofs
  [--backend snarkjs|rapidsnark] default snarkjs
  [--rapidsnark-bin <path>]     required if --backend rapidsnark
  [--cache-dir <path>]          default ~/.cache/qkb/
```

### Input: `witness.json`

Exported by the SPA `/upload` screen when "Offline proving" is selected.
Schema `qkb-witness/v1`:

```jsonc
{
  "schema": "qkb-witness/v1",
  "circuitVersion": "QKBPresentationEcdsaLeaf+Chain",
  "algorithmTag": 1,
  "artifacts": { /* urls.json block — drives .wasm/.zkey fetch */ },
  "leaf":  { /* Phase2Witness.leaf */ },
  "chain": { /* Phase2Witness.chain */ }
}
```

### Output: `proof-bundle.json`

Re-import via the SPA `/upload` "Import proof bundle" button. Schema
`qkb-proof-bundle/v1`:

```jsonc
{
  "schema": "qkb-proof-bundle/v1",
  "circuitVersion": "QKBPresentationEcdsaLeaf+Chain",
  "algorithmTag": 1,
  "proofLeaf":   { /* Groth16Proof */ },
  "publicLeaf":  [ /* 13 decimal-string field elements */ ],
  "proofChain":  { /* Groth16Proof */ },
  "publicChain": [ /* 3 decimal-string field elements */ ]
}
```

## Backends

### snarkjs (default)

Pure Node.js. Works out of the box. Runtime on commodity laptop:

- leaf: ~10–15 min
- chain: ~3–5 min

Memory: ~12 GB peak for leaf, ~6 GB for chain.

### rapidsnark (opt-in)

Much faster and far lower RAM, but requires the user to supply the binary:

```
qkb prove witness.json --backend rapidsnark --rapidsnark-bin /usr/local/bin/rapidsnark
```

Binary releases: https://github.com/iden3/rapidsnark/releases
Source builds: https://github.com/iden3/rapidsnark (Linux x86_64 is the
primary target; macOS / arm64 users typically build from source).

#### Measured profile

Against the real Diia `binding.qkb.json.p7s` on a Linux/x86_64 laptop
(2026-04-19, rapidsnark v0.0.8, leaf zkey 4.2 GB + chain zkey 2 GB):

| Phase                | Wall time |
|----------------------|-----------|
| leaf wtns.calculate  | ~18 s     |
| leaf rapidsnark prove| ~108 s    |
| chain wtns.calculate | ~16 s     |
| chain rapidsnark prove| ~98 s    |
| **Total**            | **4:28**  |

- Peak RSS: **4.67 GB** (cgroup `memory.peak`: 4,616 MB).
- User CPU: 455 s across the run (rapidsnark multi-threads; ~1.7× wall).
- Major page faults: 388 — zkeys are `mmap`'d, pages pulled on demand.

Practical sizing: `MemoryMax=6G` is enough; `8G` is comfortable. Don't
need Node's heap raised past the default when running rapidsnark. The
full-process resident set tops out near 5 GB because rapidsnark holds the
active portion of the zkey plus working buffers, not the whole 4.2 GB
file.

Sanity harness:

```
systemd-run --user --scope -p MemoryMax=6G -p MemorySwapMax=0 \
  /usr/bin/time -v \
  qkb prove witness.json --backend rapidsnark --rapidsnark-bin <path>
```

`/usr/bin/time -v` reports `Maximum resident set size`; the cgroup's
`memory.peak` file under `/sys/fs/cgroup/.../<scope>/` agrees within a
few MB.

## Artifact cache

Zkeys are large (4.5 GB leaf, 2 GB chain) and sha256-verified against the
ceremony manifest baked into `witness.json`. The cache lives at:

```
$XDG_CACHE_HOME/qkb/<sha256>/
```

fallback `$HOME/.cache/qkb/<sha256>/`. First run downloads from R2; every
subsequent run hits the local cache. A zkey rotation (new sha256) forces a
fresh download automatically.

## Security

- Output files are written with `0600` perms inside a `0700` directory.
- `witness.json` contains your leaf cert + intermediate cert + CAdES
  signedAttrs — all already public in the `.p7s` you signed, but still
  PII-adjacent. **Do not commit these files or paste them into public
  issues.**
- After `/register` succeeds on-chain, delete the proofs directory:
  ```
  rm -rf ./proofs
  ```

## Troubleshooting

**`WARNING: Node heap limit is ~2048 MB`**
Re-run with `NODE_OPTIONS=--max-old-space-size=16384`.

**`sha256 mismatch for leaf zkey`**
The cached zkey is corrupt or urls.json was updated. Delete
`~/.cache/qkb/<sha>/` and retry.

**`--rapidsnark-bin is required`**
You passed `--backend rapidsnark` without `--rapidsnark-bin`. Either point
to your binary or drop the `--backend` flag to use snarkjs.
