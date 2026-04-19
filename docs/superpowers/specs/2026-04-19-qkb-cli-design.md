# @qkb/cli — offline Groth16 proving CLI design

> **Status:** draft 2026-04-19 — pending review

## Problem

The split-proof SPA (`/upload`) runs `snarkjs.groth16.fullProve` in a Web Worker
for both the leaf (13 pubsignals, ~4.47 GB zkey) and chain (3 pubsignals, ~2.00
GB zkey) proofs. Browser tabs cap around ~4 GB heap; the chain prove reliably
throws `prover.wasmOOM` on commodity laptops. Without a usable local real-prover
path, every on-chain register submit to Sepolia V3 requires an externally-proven
bundle — and today that bundle can only come from a CI ceremony machine.

## Goal

Give the user a local CLI (`qkb`) that takes a witness JSON exported from the
browser, produces real Groth16 proofs against the committed ceremony zkeys, and
hands proof files back to the browser for the /register submit.

Browser keeps owning verify + witness build. CLI owns only prove. Register
continues to be a browser flow.

## Out of scope

- Porting CAdES parse / cert chain / witness build into Node — those already
  work in-browser and duplicating them in two languages is where drift lives.
- Rebuilding the ceremony or re-generating zkeys.
- Shipping a rapidsnark binary. The CLI supports it as a backend but the user
  must provide the binary.
- A GUI. CLI is dev-facing; the browser SPA stays the user-facing surface.

## Architecture

Three units with well-defined interfaces:

```
packages/qkb-cli/
├── cli.ts           # argv parsing, subcommand dispatch
├── artifacts.ts     # download + sha256 verify + cache
├── witness-io.ts    # read + validate Phase2Witness JSON (leaf + chain)
├── backend-snarkjs.ts   # implements IProverBackend via snarkjs Node
└── backend-rapidsnark.ts # implements IProverBackend via snarkjs-wtns + rapidsnark shell-out
```

Interface:

```ts
interface IProverBackend {
  prove(side: 'leaf' | 'chain', input: {
    witness: Record<string, unknown>;
    wasmPath: string;
    zkeyPath: string;
  }): Promise<{ proof: Groth16Proof; publicSignals: string[] }>;
}
```

Both backends produce identical output shape so callers don't branch.

### Subcommands

Only one ships in v1; the `qkb <subcommand>` shape leaves room for more:

- `qkb prove <witness.json> [--out <dir>] [--backend snarkjs|rapidsnark]
  [--rapidsnark-bin <path>] [--cache-dir <path>]`

Input `witness.json` is a single file with shape:

```jsonc
{
  "schema": "qkb-witness/v1",
  "circuitVersion": "QKBPresentationEcdsaLeaf+Chain",
  "algorithmTag": 1,              // 0 = RSA, 1 = ECDSA
  "artifacts": { /* the urls.json block, copied verbatim */ },
  "leaf":  { /* Phase2Witness.leaf  — LeafWitnessInput */ },
  "chain": { /* Phase2Witness.chain — ChainWitnessInput */ }
}
```

Single JSON keeps browser-side export trivial (`Blob([JSON.stringify(...)])` —
no JSZip dep) and CLI-side ingestion trivial (`JSON.parse`).

Output `--out <dir>` (default `./proofs/`):

```
proof-bundle.json
```

Single JSON with shape:

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

Symmetric with the input so browser import is one `JSON.parse` + 4 sessionStorage
writes.

### Artifact cache

- Default cache root: `$XDG_CACHE_HOME/qkb/` (fallback `$HOME/.cache/qkb/`).
- Subdirs keyed by sha256 of the zkey: `<sha256>/qkb-leaf.zkey`, etc.
- First run downloads from `urls.json` URLs, SHA-verifies. Mismatched hash
  refuses to prove — the zkey is load-bearing, silent corruption = invalid
  proofs wasted on-chain gas.
- `--cache-dir` override for sandboxes / CI.

### Backend: snarkjs (default)

Pure Node, imports `snarkjs`, calls `groth16.fullProve`. Process must start with
`NODE_OPTIONS=--max-old-space-size=16384` for the leaf prove; CLI entry injects
this automatically by re-execing if the heap is under 16 GB.

Proves each side serially so peak RAM stays bounded. Runtime: 10–15 min
leaf, 3–5 min chain on commodity laptop.

### Backend: rapidsnark (opt-in)

- Generates `.wtns` via `snarkjs.wtns.calculate(input, wasmPath, outPath)` (Node
  heap is fine for wtns alone).
- Shells out: `<rapidsnark-bin> <zkey> <wtns> <proof.json> <public.json>`.
- Parses the two output files into the `Groth16Proof` + `publicSignals` shape.
- Runtime: ~1–2 min per side. Requires user to install rapidsnark binary; CLI
  emits a pointer to iden3/rapidsnark releases when `--backend rapidsnark` is
  set but `--rapidsnark-bin` is missing.

## Browser handoff

Two new controls on `/upload`:

### Export

After successful verify + witness build, instead of dispatching to the
(OOM-prone) in-browser prover, `/upload` shows:

> **Offline proving required.** Download your witness bundle, run `qkb prove`
> locally, then come back and import the proofs.

Button: **Download witness bundle** → downloads `witness.json` (single file
containing both sides + artifacts block + meta).

A pre-formatted command is shown for copy-paste:

```
npx @qkb/cli prove ~/Downloads/witness.json
```

State: `awaiting-external-proof` — session keeps the witness around so the
Import step can still pair them with the existing `pubkeyUncompressedHex`.

### Import

Button: **Import proof bundle** → accepts `proof-bundle.json`. On load:

- Validates the two public-signals arrays match the session's witness
  (pkX/pkY/leafSpkiCommit/ctxHash checks; aborts on mismatch).
- Writes `proofLeaf`, `publicLeaf`, `proofChain`, `publicChain` into
  sessionStorage.
- Navigates to `/register`.

### Fallback

The existing mock-vs-real toggle is removed. Two buttons above the drop-zone:
"Prove in browser (mock)" for local UI testing, "Offline proving" for real
submit flows. Mock continues to work via the existing MockProver with the
witness-derived publicSignals fix already landed.

## Security

- Witness JSONs carry the user's leaf cert + intermediate cert + CAdES
  signedAttrs. Not secrets per se — they're already public in the `.p7s` the
  user signed — but still PII-adjacent and should not be committed to git or
  pasted into issues.
- CLI output `./proofs/` is written with `0600` file perms; directory created
  with `0700`. `witness.zip` is read-only once unpacked.
- CLI emits a warning after success reminding user to `rm -rf ./proofs/`
  after /register completes. No telemetry, no network except the R2 artifact
  fetch.
- Artifact cache SHA-verify is mandatory — mismatch refuses to run, never
  emits a partial proof. The zkeys sha256s are frozen in
  `packages/web/fixtures/circuits/urls.json` and `fixtures/contracts/sepolia.json`
  (the contract's `ceremony` block) — CLI reads the latter to cross-check the
  former, so a single tampered file can't slip through.

## Testing

- Unit: `witness-io` parser on a synthetic witness bundle.
- Unit: `artifacts` SHA verification with a crafted mismatched fixture.
- Backend smoke: golden-case snarkjs fullProve against a tiny test circuit (not
  the real 4.5 GB zkey — fixture is a circom `a*b=c` multiplier so CI stays
  under a minute).
- Rapidsnark backend: same smoke test, gated on `RAPIDSNARK_BIN` env var so CI
  skips when no binary is present.
- Manual: one end-to-end run against the real Sepolia ceremony zkey, logged
  in the follow-up PR.

## Open questions

None locked — this spec is authoritative for implementation.

## Non-decisions (intentionally deferred)

- **Multiple subcommand scaffold.** v1 ships only `qkb prove`. The dispatcher
  is written such that adding `qkb verify` / `qkb inspect-binding` later is a
  5-line addition.
- **Telemetry.** None. This is a dev-operator tool; no metrics leave the host.
- **Cross-platform rapidsnark.** Linux x86_64 tested only. macOS / arm64 /
  Windows users either wait for someone to build their binary or fall back to
  the snarkjs backend.
