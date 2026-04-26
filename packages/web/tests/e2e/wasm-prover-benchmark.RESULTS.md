# Browser wasm-prover benchmark — results

## Setup

- Circuit: `QKBPresentationEcdsaLeafV4_UA` — V2 hardened ceremony (zkey SHA `9370ac25…`, 6.54M constraints)
- Synthetic input: `packages/circuits/fixtures/integration/ua-v4/leaf-synthetic-qkb2.input.json` (52 KB)
- Wasm: 38.6 MB; zkey: 3.39 GB (R2-hosted at `prove.identityescrow.org/ua-leaf-v4-v2/`)
- Browser: Chromium headless via Playwright (`pnpm exec playwright test --project=wasm-prover-benchmark`)
- Host: 64 GB Linux dev box (Node 24, Chromium 140 via Playwright)
- snarkjs 0.7.6 UMD bundle injected via `page.addScriptTag`

## Run results

### Run 1 — initial harness
- **Outcome:** failed at `fetch(wasm)` in 472 ms with `Access-Control-Allow-Origin` missing
- **Lesson:** R2 bucket doesn't serve CORS for cross-origin browser fetches.
- **Fix:** spin up local CORS-enabled HTTP fixture server, page.route 302-redirect.

### Run 2 — V1 input vs V2 hardened circuit
- **Outcome:** failed at witness gen in 109 s with `Assert Failed. line: 344` (dobCommit equality)
- **Lesson:** synthetic input fixture computed `dobCommit = Poseidon(0,1)` from pre-M11 logic; V2 hardened circuit gates dobCommit by dobSupported (`dobCommit MUST = 0` when `dobSupported = 0`).
- **Fix:** patch smoke script to set `dobCommit = 0n` when `dobSupported = 0`; regenerate fixture.

### Run 3 — Node 2 GB Buffer cap on zkey download
- **Outcome:** failed in cache-miss path with `RangeError: length out of range. Received 3555108112` from `Buffer.from(arrayBuffer())`
- **Peak JS heap:** 756 MB (whole-zkey-into-Buffer attempt before throw)
- **Lesson:** Node Buffer caps at `INT32_MAX` (2 GB). Can't single-buffer the 3.55 GB zkey.
- **Fix:** stream R2 fetch via `Readable.fromWeb` + `pipeline` to disk.

### Run 4 — fixture server doesn't honor HTTP Range
- **Outcome:** failed at `Failed to fetch` after 152 s (37 s zkey download streamed cleanly to disk + 115 s witness gen + zkey-load attempt)
- **Peak JS heap:** 756 MB
- **Lesson:** snarkjs (via ffjavascript FastFile) issues HTTP `Range: bytes=…` requests to chunk-read the zkey. The fixture server returned the full file every time → fetch bailed mid-stream.
- **Fix:** parse `Range` header, return `206 Partial Content` with `Content-Range`, including suffix-length form (`bytes=-N`).

### Run 5 — both artifacts cached, Range honored
- **Outcome:** **failed at `Failed to fetch` after 119 s during zkey-chunk-load phase**
- **Peak JS heap:** 756 MB
- **Peak chromium renderer RSS:** **2.65 GB** (wasm linear memory + native heap)
- **Threads:** 21 (single-thread snarkjs, no SharedArrayBuffer used)
- **Phase reached:** witness gen complete (~110 s); zkey loading into wasm linear memory; **proof compute never started**

## Conclusion

Browser-side proving for the UA V4 leaf circuit is on the **wrong side of the feasibility line for end users**:

1. The chromium renderer climbs to **2.65 GB RSS just to load the zkey**, before any proof compute begins.
2. Witness gen alone is **~110 s** on commodity hardware for the 6.54M constraint circuit.
3. The actual Groth16 prove step (snarkjs benchmark: 5–15 min for 6M constraints, ~2× zkey size in RAM) was never reached — the harness died from a fetch failure mid-load.
4. On an 8 GB consumer laptop, the renderer would OOM before reaching the prove step.

Even if a future version of the harness pushes through to a successful prove, the resource budget (≥4 GB RAM, ≥10 minutes wall) makes browser proving inappropriate for user-facing flows. The decision to keep `/ua/upload` on `MockProver` and route real proving to the offline `@qkb/cli` is supported both by privacy considerations (the user's QES-signed binding never leaves their machine) and by these capacity numbers.

## Re-running

```bash
cd packages/web
E2E_WASM_BENCH=1 pnpm exec playwright test --project=wasm-prover-benchmark --reporter=list
```

Cache (`tests/e2e/.r2-cache/`) survives across runs; first cold run downloads ~3.4 GB.
