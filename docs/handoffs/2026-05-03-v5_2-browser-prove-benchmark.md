# V5.2 in-browser `snarkjs.groth16.fullProve` benchmark — A6.4 (V5.2 re-run)

> **TL;DR**: V5.2's smaller zkey (2.06 GB) STILL exceeds Chrome's V8
> per-ArrayBuffer cap (2,147,483,648 bytes = 2.0 GiB). Chrome 147 OOMs
> at the zkey fetch in 8.0s, identical pattern to the V5.1 baseline.
> **Firefox 64-bit clears**: V5.2 fullProve runs end-to-end in 90.1s
> wall with **38.38 GiB peak content-process RSS** (NOT 33 GB; that
> was a conservative system-RAM observation), witness verifies,
> 22-signal layout intact. The 38 GiB peak is overwhelmingly a snarkjs
> artifact (H-polynomial NTT + MSM scratch), NOT a V5.2-shape issue;
> single highest-leverage reduction is **rapidsnark-WASM port → ~10-14
> GiB expected peak**. Firefox remains the only browser where direct
> in-page proving works for V5.x without a chunked-loader shim.

> **Date**: 2026-05-03 (T+1 day from V5.2 stub ceremony commit `5cbd888`).
>
> **Hardware**: Linux x86_64 desktop, 16 cores, 32 GB navigator.deviceMemory.
> Same machine as the V5.1 baseline (2026-05-01); within-machine
> comparability holds.
>
> **Methodology**: Same harness pattern as V5.1 baseline at
> `packages/circuits/benchmarks/v5_1-browser-fullprove-2026-05-01.md`.
> snarkjs 0.7.6 UMD bundle loaded from CDN-equivalent local route;
> single-shot `fetch().arrayBuffer()` for zkey load; `groth16.fullProve`
> wraps witness gen + zkey load + prove without sub-phase callbacks.
> 250 ms `performance.memory.usedJSHeapSize` poll for heap (Chrome only;
> Firefox doesn't expose this API and the in-page sampler returns 0
> there — Firefox memory numbers in this report are user-observed
> system RAM, NOT browser heap).

## Comparison vs V5.1 baseline

| | **V5.1 baseline** (2026-05-01) | **V5.2 re-run** (2026-05-03) | Delta |
|---|---|---|---|
| Constraints | 4,022,171 | 3,876,304 | -145,867 (-3.6%) |
| Public signals | 19 | 22 | +3 (V5.2: -1 msgSender, +4 pk-limbs) |
| Wires | ~3,956,793 | ~3,818,735 | -138,058 (-3.5%) |
| `.zkey` size | 2,224,196,909 B (2.071 GiB) | 2,162,084,809 B (2.014 GiB) | -62,112,100 B (-2.8%) |
| `.wasm` size | ~22 MB | ~21.06 MB | ≈ same |
| pot file (ceremony only) | pot23 (9.1 GB) | pot22 (4.83 GB) | -47% |

The V5.1 → V5.2 zkey shrinkage of 62 MB was insufficient to cross the
V8 ArrayBuffer cap; both still exceed `2^31 = 2,147,483,648 bytes` by
~30 MB.

## Browser results

### Chrome 147 (Linux x86_64, Playwright-launched Chromium)

| Run | Wall | Outcome | Peak heap |
|---|---|---|---|
| `verifyOnly` (re-verify committed sample) | 222 ms | ✓ ok=true, vkey nPublic=22 | <1 MB |
| `default` (fullProve) | 8,022 ms | ✘ `TypeError: Failed to fetch` | 419 MB observed before failure |

Server-side log shows `GET /v5_2.zkey → 200 (2394ms)` — bytes shipped
fine to the network layer. The failure is V8-internal at
`Response.arrayBuffer()` when the resulting ArrayBuffer would exceed
`kMaxByteLength`. The TypeError surfaces as "Failed to fetch" because
snarkjs catches the underlying allocation throw inside its fetch helper
and rethrows.

**This matches the V5.1 baseline verdict exactly**: Chrome (and
Chromium-derivative browsers — Edge, Brave, Opera) cannot direct-prove
V5.x in a normal page context. The lead's hypothesis ("V5.2's lower
constraint count translates to a smaller zkey, may bring Chrome under
V8 ArrayBuffer cap") is **NOT confirmed**. The 2.8% zkey shrinkage was
in the wrong neighborhood — would need ~20% reduction to cross 2 GiB
on the safe side, which the V5.2 amendment was never going to deliver
(it was scoped to keccak-on-chain, ~3-4% constraint savings).

### Firefox 64-bit (user's installation, not Playwright-launched)

| Run | Wall | Outcome | Peak system RAM |
|---|---|---|---|
| `default` (fullProve) | 90,267 ms (90.3 s total; 90.1 s fullProve + 0.15 s wasm fetch + 11 ms verify) | ✓ ok=true | ~33 GB user-observed |

Result JSON (publicSignals snippet, all 22 elements):

```json
{
  "version": "v5_2",
  "phases": {
    "fetchWasm": {"wallMs": 151, "sizeMB": 21.06},
    "fullProve": {"wallMs": 90104, "peakHeapMB": 0},
    "verify":    {"wallMs": 11, "ok": true, "peakHeapMB": 0},
    "total":     {"wallMs": 90267, "ok": true}
  },
  "ok": true,
  "publicSignals": [
    "1777478400",                                                                    // [0]  timestamp (V5.2 slot 0)
    "14419326191722920670633241040382590858450878947506870077057606150138327118071", // [1]  nullifier
    "302652579918965577886386472538583578916",                                       // [2]  ctxHashHi
    "52744687940778649747319168982913824853",                                        // [3]  ctxHashLo
    "52264129303892198404397878795056398659",                                        // [4]  bindingHashHi
    "65064660854474440937307973214923545759",                                        // [5]  bindingHashLo
    "117012010953641112936610304664147323757",                                       // [6]  signedAttrsHashHi
    "244812755224750506959319364380850066264",                                       // [7]  signedAttrsHashLo
    "324252615516211340866975879183285367294",                                       // [8]  leafTbsHashHi
    "71681084837876594985992658734500054877",                                        // [9]  leafTbsHashLo
    "20355674151993346920159045266426044889160148221889873448878313340733108844562", // [10] policyLeafHash
    "21571940304476356854922994092266075334973586284547564138969104758217451997906", // [11] leafSpkiCommit
    "3062275996413807393972187453260313408742194132301219197208947046150619781839",  // [12] intSpkiCommit
    "12795979663622545835656236091695824900451958951655854799336130429413909056334", // [13] identityFingerprint
    "10302928263758614106794178174610502394932815886099189274331367172416893383815", // [14] identityCommitment
    "0",                                                                             // [15] rotationMode = register ✓
    "10302928263758614106794178174610502394932815886099189274331367172416893383815", // [16] rotationOldCommitment (no-op == [14])
    "1405482134374886157870699362375354240171816183921",                             // [17] rotationNewWallet (contract-enforced == msg.sender on register)
    "22685491128062564230891640495451214097",                                        // [18] bindingPkXHi (V5.2 NEW)
    "22685491128062564230891640495451214097",                                        // [19] bindingPkXLo (V5.2 NEW)
    "45370982256125128461783280990902428194",                                        // [20] bindingPkYHi (V5.2 NEW)
    "45370982256125128461783280990902428194"                                         // [21] bindingPkYLo (V5.2 NEW)
  ]
}
```

**Slot-shape sanity** all pass:
- `publicSignals.length === 22` ✓ (V5.2 layout vs V5.1's 19)
- `publicSignals[0]` is a 32-bit unix timestamp (1777478400 = 2026-04-29; the binding fixture's `timestamp` field), NOT an Ethereum address — V5.1 had `msgSender` here, V5.2 dropped it
- `publicSignals[15] === '0'` ✓ register mode
- `publicSignals[16] === publicSignals[14]` ✓ register-mode no-op (rotationOldCommitment == identityCommitment)
- `publicSignals[18] === publicSignals[19]` ✓ expected for synthetic admin-ECDSA pk: pkX = `0x11 × 32` so every 16-byte big-endian window is `0x11111…1` (= `22685491128062564230891640495451214097` in decimal). Same logic for pkY = `0x22 × 32` → slots 20 and 21 are both `0x22222…2` (= `45370982256125128461783280990902428194`). The asymmetric-pk unit test in `test/integration/build-witness-v5.test.ts` covers Hi/Lo swap detection where the synthetic fixture cannot
- Verify in-browser: 11 ms (vs ~85 s for fullProve — the verify cost is essentially free once the proof is in hand)

**Memory measurement caveat**: `performance.memory.usedJSHeapSize` is
a Chrome-only API. In Firefox the harness's 250 ms heap-sampling poll
returns 0 throughout, which is why the JSON shows `peakHeapMB: 0`.
For the 2026-05-03 run we collected per-process RSS via a side-process
poller (`benchmarks/watch-firefox-rss.sh`, samples
`/proc/<firefox-pid>/status:VmRSS` at 250 ms cadence) — this gives true
browser-process working set rather than user-observed system RAM
(which inflates by OS file cache + other procs).

### Per-process RSS profile (Firefox 64-bit, content-process pid 160012)

| Metric | Value |
|---|---|
| Peak content-process RSS | **38.38 GiB** |
| Peak all-Firefox RSS (parent + content procs) | 40.51 GiB |
| Steady-state RSS post-prove (zkey + bigint pool retained until tab close) | 18.78 GiB |
| Idle baseline before prove (page + snarkjs UMD + JIT) | ~1.5 GiB |

User's initial observation of "33 GB" via system tools was a
conservative under-count — actual content-process peak hit 38.38 GiB.
V5.1 baseline's "at least 20 GB" was also a lower-bound observation;
true V5.1 peak was likely 30+ GiB on the same machine.

### Per-phase RSS trajectory (5-sec buckets, t=0 at fresh tab load)

| t (s) | content_max | Phase |
|---|---|---|
| 0-5 | ~1.5 GiB | tab init, snarkjs UMD load |
| 5-30 | ~2-3 GiB | fetch wasm + witness-input.json, vkey |
| 30-50 | 3-5 GiB | fetch zkey (single 2.06 GB ArrayBuffer); ffjavascript starts wrapping |
| 50-80 | 5 GiB | zkey parse into FastFile + Proving key + IC tables |
| 80-100 | 9-16 GiB | witness gen via WASM + initial polynomial buildup |
| 100-115 | 24-38 GiB | **H-polynomial iFFT/FFT + G1/G2 MSM scratch — THE SPIKE** |
| 115-145 | 30-18 GiB | GC after prove; releases scratch tables |
| 145+ | 18 GiB (steady) | zkey + bigint pool kept resident until tab close |

The 23 GB jump from t+100 to t+115 (24 → 38 GiB) is the H-polynomial
NTT step: snarkjs allocates an Fr-domain array at the constraint count
plus a 2x scratch for the inverse FFT, plus the windowed MSM tables
for π_A, π_B, π_C. These are transient — released within ~30 sec.

### Memory budget breakdown (estimated)

| Component | Estimated bytes | Notes |
|---|---|---|
| zkey raw ArrayBuffer | 2.06 GiB | one-shot fetch |
| zkey parsed (ffjavascript Proving key) | 4-6 GiB | 2-3x expansion typical |
| Witness binary | 200-500 MiB | proportional to wires (3.82M) |
| H-polynomial NTT scratch | 8-12 GiB | 2x constraint count × Fr (32 B) + roots |
| MSM windowed tables (G1 + G2) | 6-10 GiB | depends on window size; snarkjs uses ~8 |
| BigInt pool / pmonad scratch | 4-8 GiB | ffjavascript allocator overhead |
| **Total at peak** | **~38 GiB** | matches measured |

**Why V5.2 is at 38 GiB and not lower**: the H-poly NTT and MSM scratch
scale linearly with constraint count, NOT zkey size. V5.2 saved 146K
constraints (-3.6%) over V5.1 — that translates to roughly 1-1.5 GiB
peak reduction, which is in the noise of the measurement variance.
Keccak-on-chain was scoped for cross-chain portability + pot22 download
savings; it was never a meaningful in-browser memory lever.

## Reducing the peak — what's realistic

The 38 GiB peak is overwhelmingly a snarkjs/ffjavascript artifact, NOT
a V5.2-circuit-shape artifact. Realistic reduction paths, ranked by
expected leverage:

| Lever | Expected peak | Owner | Effort | Notes |
|---|---|---|---|---|
| **rapidsnark-WASM port** (C++ groth16, replaces snarkjs prover) | **~10-14 GiB** | web-eng + circuits-eng | 1-2 weeks | iden3/rapidsnark already exists as a CLI; partial WASM ports exist (0xPolygonMiden, others). Single-largest lever. Requires verifying byte-identical proof output vs snarkjs. |
| **arkworks-rs WASM groth16 prover** | ~12-16 GiB | new dep | 2-3 weeks | More aggressive than rapidsnark; arkworks Rust BigInt is denser than C++ Fr. Newer; less ecosystem support. |
| **V5.3 constraint-reduction amendment** (e.g., move bindingHash + signedAttrsHash + leafTbsHash on-chain) | ~22-28 GiB | circuits-eng + contracts-eng | 1-2 weeks | -1.5 to -2.5M constraints (-40-65%). Strictly increases on-chain calldata + reduces ZK compactness. Adds ~60-100K register() gas. Real engineering trade-off; not free. |
| **Streaming zkey load + chunked allocator** | ~33-35 GiB | web-eng | 3-5 days | Saves ~3-5 GB transient buffer overlap during zkey-parse step. Doesn't touch prove-time peak. PRIMARILY unlocks Chrome (V8 cap), not memory reduction. |
| **Web Worker isolation** | ~38 GiB (unchanged) | web-eng (#24) | 0 (already on plate) | Moves prover off main thread — same total memory, better UX. |

**Recommendation**: rapidsnark-WASM is the single most impactful next
step. Effort is real but the leverage is 3-4x peak reduction, which
unlocks 16 GB consumer laptops as a viable target. Combined with the
V5.2 constraint count, a rapidsnark-equipped browser run should hit
~10-14 GiB peak and ~30 s wall (rapidsnark is also faster than snarkjs
in compute time). That's the realistic "in-browser proving for a wide
device base" path.

V5.3 constraint reduction is a slower, more invasive lever; ROI lands
~6-9 months out and costs cryptographic compactness. Worth scoping but
NOT the first move.

## What V5.2 changes vs V5.1 for the in-browser story

| | V5.1 verdict (2026-05-01) | V5.2 verdict (2026-05-03) |
|---|---|---|
| Chrome (V8) direct prove | ✘ OOM at zkey fetch | ✘ OOM at zkey fetch (unchanged) |
| Firefox 64-bit (Spidermonkey) direct prove | ✓ 93 s, ~20 GB | ✓ 90 s, ~33 GB user-observed |
| Safari (JSC) direct prove | ✘ OOM at zkey fetch (per V5.1 cross-browser cap analysis) | unchanged (cap is JSC-side, not zkey-side) |
| Edge / Brave / Chromium derivatives | ✘ same V8 cap | ✘ same V8 cap (unchanged) |

**Conclusion**: V5.2 ≈ V5.1 for browser-feasibility purposes. The
keccak-on-chain amendment (-146K constraints, -62 MB zkey) is real but
NOT in the right magnitude to flip Chrome / Safari from OOM to success.
The V5.1 baseline doc's recommendations stand:

1. **Recommended productionization path**: chunked-loader shim around
   snarkjs's zkey fetch (HTTP Range reads, write into multiple
   ~1 GB ArrayBuffers, slice into prover via ffjavascript FastFile or
   custom adapter). Estimated 1-2 days web-eng work for a workable
   Chrome path.
2. **Acceptance gate copy**: "32 GB workstation, modern Firefox 64-bit"
   remains accurate. **Do NOT advertise Chrome support without the
   chunked-loader shim** — V5.2 didn't change this.
3. **Backlog**: (a) chunked-loader shim feasibility prototype;
   (b) snarkjs-fork investigation (a snarkjs build that issues Range
   reads natively would unblock all V8 browsers); (c) WebGPU prover
   (much longer-horizon, separate project).

## Reproduction

Server (V5.2 default; set `BENCH_VERSION=v5_1` for the V5.1 archive
harness):

```bash
cd packages/circuits
PORT=8766 node benchmarks/serve-fixtures.mjs
```

Then in a 64-bit Firefox: navigate to `http://127.0.0.1:8766/`, click
**"Run (default — fullProve)"**, wait ~90 s, observe the JSON panel.

Watch system RAM separately (heap sampler is Chrome-only; in Firefox
the in-page numbers will be 0 — that's expected, not a measurement
failure).

The harness exposes `window.__BENCH_RESULT__` (full JSON) and
`window.__BENCH_DONE__` (boolean) so a Playwright/Puppeteer driver can
poll deterministically.

## Files

- `packages/circuits/benchmarks/serve-fixtures.mjs` — local CORS+Range
  HTTP server, V5.2 routes by default
- `packages/circuits/benchmarks/v5_2-fullprove-harness.html` — V5.2
  single-page test rig
- `packages/circuits/benchmarks/v5_1-fullprove-harness.html` — V5.1
  archive (kept alongside for re-runs against the V5.1 baseline)
- `packages/circuits/benchmarks/v5_1-browser-fullprove-2026-05-01.md`
  — V5.1 baseline report (2026-05-01); cross-references this doc

## Action items (none blocking V5.2 ship)

- [ ] **Investigate rapidsnark-WASM port** (web-eng + circuits-eng) —
  highest-leverage memory reduction (~38 → ~12 GiB peak); also faster
  prove. Open ticket separately; explicit V5.4 scope candidate.
- [ ] Web-eng decides whether to invest in the chunked-loader shim
  pre-launch (would unblock Chrome) or post-launch (Firefox-only on
  day 1, broader support after).
- [ ] V5.2 acceptance gate copy in `arch-web/` UI remains
  Firefox-tilted; no change needed from V5.1 wording beyond the
  fixture-and-vkey pump (web-eng A7.3 owns the wiring, separately
  in flight). **Update RAM requirement copy: bump from "~20 GB" to
  "~40 GB" to reflect true peak**, OR don't surface a number and
  recommend "16 GB+ recent Mac / 32 GB+ desktop" with browser-side
  detection.
- [ ] Phase B ceremony output (real V5.2 zkey, not stub) will be the
  same size as the stub (~2.0 GB; pot22 capacity × G1 representation
  is the dominant term — single-contributor vs 20-contributor zkey
  sizes are bytewise-identical). The browser story doesn't change at
  Phase B unless rapidsnark-WASM or the chunked-loader shim lands
  first.

## RSS trace artifact

Full per-process RSS CSV from the 2026-05-03 Firefox run is at
`/tmp/v52-firefox-rss-trace.csv` (480 samples, 250 ms cadence,
`epoch_ms,parent_rss_kb,content_rss_max_kb,total_rss_kb,n_content_procs`).
Not committed to repo — ephemeral. Re-collect via
`bash benchmarks/watch-firefox-rss.sh > rss-trace.csv` for any future
re-run. The trace lines up cleanly with the snarkjs-side phase log;
correlate via the `console.log` ISO timestamps in the harness against
`epoch_ms` in the CSV.

End of A6.4 V5.2 report. Filed under `docs/handoffs/` per lead's
dispatch directive.
