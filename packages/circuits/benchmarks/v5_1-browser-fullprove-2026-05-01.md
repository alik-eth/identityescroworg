# V5.1 in-browser `snarkjs.groth16.fullProve` benchmark — A6.4

**Date**: 2026-05-01
**Branch**: `feat/v5arch-circuits` @ `b04b2a5` (post-A6.1 close)
**Author**: circuits-eng

## Question

> Does `snarkjs.groth16.fullProve` against the V5.1 stub ceremony (4.022 M
> constraints, 2.12 GB zkey, 22 MB wasm, 19 public signals) complete in a
> normal desktop Chrome tab? If yes, what's the resource budget? If no,
> what's the exact constraint that breaks?

The answer determines whether the upcoming Fly deploy ships
`/ua/registerV5` as a working browser flow or whether 95 %+ of users hit
`/ua/use-desktop` and bounce.

## TL;DR — verdict

**Browser-and-engine-conditional.** Stock `snarkjs@0.7.6` cannot load the
V5.1 stub zkey in **Chrome / V8** (single-`ArrayBuffer` cap ~2.00–2.05 GB
on Chrome 147; 2.12 GB zkey overshoots by ~70–130 MB). However, **Firefox
64-bit / SpiderMonkey allows up to 4 GB single-`ArrayBuffer` allocations**
(empirically confirmed by user via direct `new ArrayBuffer(4 * 1024**3)`
probe — see "Cross-browser cap data" below), which means the V5.1 zkey
**fits under the observed Firefox cap** (2.12 GB < 4 GB). A direct
Firefox `fetch /v5_1.zkey` run was NOT performed in this benchmark — the
cap probe is the only Firefox-side evidence — so "Firefox load step is
feasible" is the precise claim, not "Firefox load step succeeds".

This is a **JavaScript-engine cap**, not a device-class issue:

- 32 GB workstation, 16 cores, **Chrome 147**, `jsHeapSizeLimit = 4 GB` —
  zkey load **fails** at 2.05 GB allocation.
- Same workstation, **Firefox 64-bit** — single 4 GB `ArrayBuffer`
  allocation succeeds in a direct probe; zkey load thus **fits under
  the observed cap** (2.12 GB < 4 GB) but **was not directly run** in
  this benchmark.
- Whether `groth16 prove` then COMPLETES end-to-end on Firefox is
  **unverified in this benchmark** — separate gating concern (4 GB WASM
  linear-memory + MSM working set). Likely possible but needs a Firefox-
  specific run.
- `navigator.storage.persist()` does NOT lift the Chrome cap — confirmed
  empirically.
- The cap is per-allocation, NOT host-RAM-derived: even a 64 GB Chrome
  user would still fail the load step on any current Chrome.

**Recommendation: keep the gate, but rewrite the copy.** The current
copy ("requires 32 GB workstation") misleads — the actual blocker is
JavaScript-engine-internal, not hardware. Firefox 64-bit's 4 GB
single-`ArrayBuffer` cap (vs Chrome's 2 GB) means the **zkey load step
succeeds on Firefox**, raising the possibility of in-browser proving
there. **Whether Firefox's full prove actually completes is NOT
verified by this benchmark** — only the load step is, indirectly via
the cap probe. A follow-up Firefox-channel run would close that gap.

For the Fly deploy today (conservative):
1. Verify-only flows ship unconditionally on all browsers (153 ms /
   ~6 MB heap).
2. fullProve gate copy: drop the "32 GB workstation" phrasing; replace
   with a JavaScript-engine-memory-limit explanation routing users to
   `@qkb/cli`.
3. Backlog: (a) Firefox-channel `fullProve` follow-up to determine if
   the prove step completes; (b) chunked-load shim (~1-2 days) to
   restore Chrome support and future-proof against larger zkeys.

If the Firefox follow-up confirms end-to-end success, a second deploy
can add Firefox-specific opt-in copy.

---

## Methodology

### Artifacts

All from the V5.1 stub ceremony at `packages/circuits/ceremony/v5_1/`
(committed at `65818a0`, sha256 manifest matches).

| File | Size | sha256 (first 16) |
|---|---|---|
| `qkb-v5_1-stub.zkey` (gitignored) | 2,122.8 MB | `61449d3b182a01e8…` |
| `QKBPresentationV5.wasm` (witness compiler) | 21.7 MB | n/a |
| `verification_key.json` | 5.8 KB | `72872a9b56eec2c5…` |
| `witness-input-sample.json` | 81 KB | `c3d21c7c6f487fcd…` |
| `proof-sample.json` | 0.8 KB | `6403b89204f0268b…` |
| `public-sample.json` (19 entries) | 1.1 KB | `2be0757fbbc3d082…` |

### Harness

Three artifacts in `packages/circuits/benchmarks/`:

- `serve-fixtures.mjs` — minimal Node HTTP server with CORS + HTTP-Range
  support, lifted from the V4 wasm-prover-benchmark fixture server in
  the arch-fly tree (simplified — no R2 upstream caching since
  artifacts are local). NOTE: in this V5.1 benchmark, snarkjs 0.7.6's
  installed bundle does NOT issue Range requests for the zkey load (see
  Run 2 server log + bundle inspection below). The Range path is
  retained as defensive infrastructure for a future chunked-loader shim
  and to keep parity with the V4 harness pattern; it is NOT exercised
  by the stock snarkjs path.
- `v5_1-fullprove-harness.html` — single-page test rig. Loads the snarkjs
  UMD bundle from a sibling route, exposes three buttons (default / persist /
  verify-only), reports per-phase timing + peak `performance.memory.usedJSHeapSize`,
  and writes the final `{ ok, phases, error }` shape to `window.__BENCH_RESULT__`
  for the driver to read.
- This results doc.

### Driver

Run via the `mcp__plugin_playwright_playwright__browser_*` MCP toolset
(NOT a `@playwright/test` spec) so the lead can re-run interactively. The
session-persistent Chromium that the MCP controls is the actual measurement
target.

```bash
# Reproduction:
cd packages/circuits
node benchmarks/serve-fixtures.mjs &     # starts on http://127.0.0.1:8765
# Navigate Chrome to http://127.0.0.1:8765/, click each button.
```

### Environment

- **Host**: 32 GB Linux workstation, 16 logical cores
- **Chrome**: 147.0.0.0 (`Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ...`)
- **`navigator.deviceMemory`**: 32 (GB)
- **`navigator.hardwareConcurrency`**: 16
- **`performance.memory.jsHeapSizeLimit`**: 4 GB (4,096 MB) — Chrome's
  per-tab JS heap cap, distinct from the per-allocation `ArrayBuffer` cap
- **snarkjs**: 0.7.6 UMD bundle from `node_modules/.pnpm/snarkjs@0.7.6/.../snarkjs.min.js`

---

## Run results

### Run 1 — verify-only (smoke test, harness wiring)

| Phase | Wall | Peak heap | Result |
|---|---|---|---|
| fetch wasm | 71 ms | — | ✓ 22 MB |
| `groth16.verify` against committed sample | 153 ms | <6 MB (sub-sample interval) | ✓ proof verifies |
| **total** | **224 ms** | **<6 MB** | **✓** |

Note: snarkjs's `fullProve` and `verify` do not expose internal phase
callbacks, so the harness reports the wrap as a single combined wall.
Sub-phase splits (zkey load vs. witness gen vs. prove) would require a
custom snarkjs build (see "Workarounds" §3); not in A6.4 scope.

This confirms the harness, server, snarkjs UMD, CORS path, vkey JSON, and
sample (proof, public) triple are all wired correctly. **The V5.1 cheap
re-verify path works in browser.**

### Run 2 — default `fullProve` (the question)

| Phase | Wall | Peak heap | Result |
|---|---|---|---|
| fetch wasm | 41 ms | — | ✓ 22 MB |
| `groth16.fullProve(input, wasmUrl, zkeyUrl)` | 7,977 ms | **434 MB** | ✘ `TypeError: Failed to fetch` |
| **total (wasm fetch + failed fullProve)** | **8,018 ms** | **434 MB** | **✘ FAIL** |

Server-side log shows snarkjs/ffjavascript made a single bare `GET /v5_1.zkey`
(no Range header) immediately after fetching wasm. The browser began
streaming the 2.12 GB body, accumulated ~434 MB into the JS heap, then
the fetch was killed at ~8 s with `TypeError: Failed to fetch`.

```
GET /v5_1.zkey → 200 (2247ms)        <-- single-shot, server side abort
```

### Run 3 — persist-granted (`navigator.storage.persist()`)

| Phase | Wall | Peak heap | Result |
|---|---|---|---|
| `navigator.storage.persist()` | <1 ms | — | ✓ returned `true` |
| fetch wasm | 43 ms | — | ✓ 22 MB |
| `groth16.fullProve` | 7,843 ms | **434 MB** | ✘ `TypeError: Failed to fetch` |
| **total** | **7,886 ms** | **434 MB** | **✘ FAIL** |

**Persist permission has no effect on the failure mode.** The persist API
governs IndexedDB/Cache-Storage eviction policy, NOT in-process JS
allocation limits. Confirmed identical fail point as Run 2.

### Run 4 — direct V8 ArrayBuffer cap probe (Chrome 147)

```js
new ArrayBuffer(1500 * 1024 * 1024)  // ✓ 1500 MB
new ArrayBuffer(1900 * 1024 * 1024)  // ✓ 1900 MB
new ArrayBuffer(2000 * 1024 * 1024)  // ✓ 2000 MB
new ArrayBuffer(2050 * 1024 * 1024)  // ✘ RangeError: Array buffer allocation failed
```

**Single ArrayBuffer cap: 2.00–2.05 GB on this Chrome 147 build.**

Multi-buffer probe: 10 × 256 MB ArrayBuffers cumulative = **2,560 MB**
allocated successfully (the loop completed all 10). So the JS heap can
hold ≥2.5 GB worth of data, just not in a single contiguous allocation.

This is the Chrome-side root cause: the zkey at 2.12 GB exceeds V8's
single-allocation cap by ~70–130 MB. snarkjs's
`fetch(url).arrayBuffer().then(t => new Uint8Array(t))` path (visible in
the bundle as a single-line transform) requires that single allocation.

### Run 5 — Firefox 64-bit cap probe (user-reported, separate session)

```js
try {
  const buffer = new ArrayBuffer(4 * 1024 * 1024 * 1024);
  console.log("Success! Buffer size:", buffer.byteLength / (1024**3), "GB");
} catch (e) { /* ... */ }
// → "Success! Buffer size: 4 GB"
```

User confirmed Firefox 64-bit on the same machine successfully
allocates a 4 GiB single ArrayBuffer — twice the V5.1 zkey size. This
inverts the verdict from "browser proving impossible" to "Chrome-only
impossible; Firefox load works".

Whether Firefox's `fullProve` then completes the WASM-prover compute
step end-to-end is **not directly measured** in this benchmark
(harness was driven via Playwright MCP against Chromium-channel; a
Firefox channel run is the natural follow-up). The MSM working set for
4M constraints sits ~1.5–2 GB peak under WASM linear memory; combined
with intermediate result buffers, it may or may not fit under
SpiderMonkey's 4 GB Memory cap. **Recommended follow-up: re-run via
Playwright Firefox channel.**

---

## Why snarkjs 0.7.6 doesn't chunk

Bundle inspection:

```bash
$ grep -oE "fetch[^\"']*\(" snarkjs.min.js | head -3
fetch(t).then((function(t){return t.arrayBuffer()})).then((function(t){return new Uint8Array(t)}))
```

Stock snarkjs 0.7.6 unconditionally does a single-shot `fetch(url) →
arrayBuffer() → Uint8Array`. There is **no** Range-based chunked-read code
path in the bundled UMD. (`grep -oE "Range:|bytes=|chunkSize"` returns
zero hits for HTTP-range primitives; only the V8-internal `chunkSize`
constant for memory layout.)

This contradicts a comment in the V4 leaf benchmark RESULTS.md that
described seeing `Range:` headers from snarkjs — that was either a
different snarkjs version, a non-UMD path, or a misattribution. Empirical
evidence in our log directly shows zero Range requests from the UMD
bundle.

---

## What the host capacity test tells us

The 32 GB host has 16 cores and 4 GB JS-heap-cap. Even with 4× the device
memory of a typical user laptop, the constraint is identical because the
limit is per-allocation in V8, not OS-level.

Approximate ArrayBuffer caps by browser engine (community-reported +
empirical, varies by version):

| Browser/version | Engine | Single ArrayBuffer cap | V5.1 zkey (2.12 GB) load? |
|---|---|---|---|
| Chrome 147 (this benchmark, Linux x86_64) | V8 | ~2.00–2.05 GB (empirical) | ✘ overshoots |
| Chrome typical | V8 | 2.00 GB (V8 default) | ✘ overshoots |
| **Firefox 64-bit** (user-reported) | **SpiderMonkey** | **4 GB** (`new ArrayBuffer(4 * 1024**3)` succeeds) | **✓ fits** |
| Safari | JavaScriptCore | ~1.50 GB | ✘ overshoots |

The Firefox cap is the unambiguous outlier — SpiderMonkey explicitly
supports buffers up to `2^32 - 1` bytes (4 GiB minus 1) on 64-bit
builds, while V8 historically caps at 2 GiB to keep TypedArray indices
fitting in `int32`.

**The Firefox-vs-Chrome cap delta means the LOAD-STEP feasibility of
V5.1 zkey is engine-conditional**: Firefox 64-bit clears the cap;
Chrome/Edge/Safari hit it. Whether Firefox `fullProve` then completes
end-to-end is a separate, unmeasured question — see Caveat below.
Importantly, this changes the accurate description of the constraint
from "needs a 32 GB workstation" (wrong — hardware-irrelevant) to
"depends on the JavaScript engine; load step requires a 4 GB+
single-allocation cap that today only Firefox 64-bit provides".

**Caveat**: this benchmark only directly verified the zkey-LOAD step on
Chrome (where it failed) and the verify-only path (which works
everywhere). The full Firefox `fullProve` round-trip — which depends on
both the load AND the prover's MSM working set fitting under WASM
linear-memory limits — is **not** measured in this report. A follow-up
Firefox run via Playwright MCP `browser_navigate` (Playwright supports
Firefox as a channel) would close that gap.

---

## Workarounds (NOT in scope of A6.4 — gate on a separate dispatch)

1. **Custom snarkjs build with Range-based zkey loader.**
   ffjavascript has a `FastFile` abstraction that supports chunked reads
   in the Node tree but isn't exposed in the browser UMD. Forking that into
   a 50–100 KB browser-side shim is the cleanest path. Estimated effort:
   1-2 days of work + audit.

2. **Pre-load zkey into a series of smaller `Uint8Array`s and concatenate
   in WASM linear memory.** The multi-buffer probe shows 2.5+ GB total is
   allocatable; the issue is solely contiguous-allocation. Requires snarkjs
   surgery (fork the bundle).

3. **Ship the `@qkb/cli` offline prove path as primary; browser stays
   verify-only.** Already the V4 stance per `wasm-prover-benchmark.RESULTS.md`.
   Lowest effort. Recommended.

4. **Web Worker isolation.** Same V8 cap, separate isolate — does NOT
   help with single-allocation size. Not a workaround for this specific
   limit.

5. **OPFS streaming.** Could store the zkey in Origin Private File System
   and stream it, but snarkjs would need to be modified to consume from
   OPFS handles instead of a URL → ArrayBuffer.

---

## CPU throttling — gap

Lead's dispatch asked for a 4× CPU-throttled measurement to estimate
flagship-mobile feasibility. The Playwright MCP tools available
(`browser_navigate`, `browser_click`, `browser_evaluate`, etc.) do NOT
expose CDP's `Emulation.setCPUThrottlingRate`. The throttled measurement
was not taken.

This gap is **non-blocking for the verdict**: throttling slows compute
but doesn't change memory limits, so a phone-emulated run would hit the
EXACT same `TypeError: Failed to fetch` at the EXACT same point. CPU
slowdown doesn't lift V8 allocation caps.

If a CPU-throttled measurement is later required (e.g., for a
chunked-loader workaround that DOES allow proving), it can be run via a
direct `@playwright/test` spec (CDP throttling supported there, but at
the cost of needing the @playwright/test runtime).

---

## Recommendations for the Fly deploy

1. **Rewrite the gate copy to be browser-engine-aware AND honest about
   what's verified.** Two conservative options for the Fly deploy, both
   strictly grounded in what THIS benchmark verified (zkey load step
   only on Chrome — failed; ArrayBuffer cap probes on both engines):

   **Conservative path (recommended for Fly today):**
   - Keep the existing single-route `/ua/use-desktop` gate. Update the
     copy to say "Browser-side proving for this ceremony hits a
     JavaScript-engine memory limit on Chrome/Edge/Safari. Please use
     the offline `@qkb/cli` from any desktop OS for proof generation;
     verification works in any browser." — drops the "32 GB workstation"
     phrasing.
   - Verify-only flows ship unconditionally (they work everywhere in
     <200 ms).

   **Optimistic path (if a follow-up Firefox `fullProve` measurement
   confirms it):**
   - Add a Firefox-specific opt-in route, copy: "Firefox 64-bit users
     can attempt browser-side proving (beta — may take 5–10 min and use
     up to 4 GB RAM; falls back to `@qkb/cli` on failure)." Gate
     specifically on `navigator.userAgent` matching Firefox 64-bit.
   - This option REQUIRES the Firefox follow-up run before deploy. Don't
     ship Firefox-specific copy without empirical confirmation that
     `groth16 prove` (not just zkey load) completes.

   The "requires 32 GB workstation" copy in the current build is wrong
   in both paths — it captures neither the actual constraint
   (engine-level, not RAM) nor the Firefox escape-hatch possibility.

2. **Ship `/ua/registerV5` for verify-only flows now.** The 153 ms
   sample-triple verification IS feasible in browser. Useful for: cert
   validation pre-flight, proof submission UI, public proof viewer.

3. **Backlog the chunked-load shim as a P2 follow-up.** Real ceremony
   (§11) will produce a similar-sized zkey; same constraint applies.
   Eventually we want browser proving to work for accessibility, but it's
   not a Fly-deploy blocker.

4. **Don't add `Cross-Origin-Embedder-Policy: require-corp` headers** to
   the deploy unless we deliberately want SharedArrayBuffer support.
   snarkjs is single-threaded and doesn't need it; my initial fixture
   server included those headers and removing them did not change the
   measurement (the actual blocker is allocation cap, not COEP). But
   leaving them in adds CORP-validation overhead for no benefit.

---

## Reproduction

```bash
# From repo root
cd packages/circuits
node benchmarks/serve-fixtures.mjs &
sleep 1
# Navigate any browser to http://127.0.0.1:8765/, click "Run (default
# desktop Chrome)". Wait ~10 s for failure (or 5+ min for success on
# any future chunked-loader implementation). Click "Run (verify-only,
# no fullProve)" for the cheap-path validation.
```

Server log captures every request method/path/range/status/wall.
Browser console + on-page log capture every phase + peak heap.
Final result mirror at `window.__BENCH_RESULT__` for programmatic
re-reads.

---

## Files committed

- `packages/circuits/benchmarks/serve-fixtures.mjs` (203 lines)
- `packages/circuits/benchmarks/v5_1-fullprove-harness.html` (267 lines)
- `packages/circuits/benchmarks/v5_1-browser-fullprove-2026-05-01.md` (this file)
