# V5.2 in-browser `snarkjs.groth16.fullProve` benchmark — A6.4 (V5.2 re-run)

> **TL;DR (updated 2026-05-03 with native rapidsnark data)**:
>
> Browser-only direct prove against V5.2 stub: Chrome 147 OOMs at zkey
> fetch (V8 ArrayBuffer cap), Firefox 64-bit succeeds in 90.3 s with
> **38.38 GiB peak content-process RSS**. The 38 GiB is overwhelmingly
> a snarkjs/ffjavascript artifact (H-polynomial NTT + MSM scratch),
> NOT a V5.2-circuit-shape issue.
>
> **Native rapidsnark CLI (v0.0.8) against the SAME V5.2 zkey + witness:
> 13.9 s wall, 3.70 GiB peak — 6.5x faster, ~10x lower memory.** Fits
> 8 GB laptops. This flips the prior "rapidsnark-WASM port (1-3 months,
> uncertain savings)" recommendation entirely: rapidsnark already works
> natively today; we just need a native shell (Tauri desktop or Mopro
> mobile, 1-2 weeks each) instead of a WASM port that doesn't exist.
>
> Pure-browser path remains as a fallback (Firefox 64-bit, 32+ GB RAM)
> but the native-shell path dominates for any production user-facing
> deployment.

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

## Native rapidsnark CLI — measured (2026-05-03 follow-up)

After the initial browser benchmark showed 38 GiB peak, we ran the SAME
V5.2 zkey + witness through the native rapidsnark prover (iden3/rapidsnark
v0.0.8, Linux x86_64) via a new V5.2 prove CLI at
`packages/circuits/scripts/v5_2-prove.mjs`. Same fixture, same machine,
same 250 ms RSS poller (this time at 100 ms over the full process tree
including the spawned `rapidsnark` child).

| Metric | snarkjs browser (Firefox) | snarkjs ceremony (Node CLI) | **rapidsnark CLI (native)** |
|---|---|---|---|
| Wall total | 90.3 s | ~85 s | **13.86 s** |
| Peak process-tree RSS | 38.38 GiB content / 40.51 GiB all-Firefox | ~26 GiB | **3.70 GiB** |
| `wtns.calculate` (snarkjs WASM, Node) | (folded into fullProve) | ~0.5-1 s | 6.90 s |
| `groth16.prove` | (folded) | ~84 s | **6.42 s** |
| `groth16.verify` | 11 ms (Firefox) | <1 s | 0.26 s |
| `verifyOk` | ✓ | ✓ | ✓ |
| Public signals length | 22 ✓ | 22 ✓ | 22 ✓ |

Note: rapidsnark's wtns.calculate is slower than the ceremony script's
because we run it in-process with snarkjs WASM in this CLI; for a
production deploy the C++ `circom-witnesscalc` binary would drop wtns
calc to ~1 s. The 6.9 s here is the snarkjs-WASM witnesscalc cost,
which dominates the rapidsnark-CLI total wall.

### rapidsnark CLI per-second RSS trajectory

| t (s) | RSS | Phase |
|---|---|---|
| 0-1 | 0.35 GiB | Node startup + snarkjs UMD load |
| 1-6 | 0.5-1.05 GiB | `wtns.calculate` (Node + WASM witnesscalc) |
| 6-7 | 1.05 → 2.21 GiB | spawn rapidsnark child + zkey load |
| 7-13 | 2.97 → **3.70 GiB peak** | rapidsnark MSM compute (no NTT explosion — C++ Fr arithmetic + native asm MSM is dramatically denser than ffjavascript BigInt pool) |
| 13+ | drop to 0 | rapidsnark exits, parent exits |

The rapidsnark prove process never exceeds 3.7 GiB, vs snarkjs's 38 GiB
peak. **This is the 10x memory reduction the rapidsnark-WASM hypothesis
was reaching for** — but rapidsnark itself is native, not WASM. The
WASM port was unnecessary; the native binary just works.

### What snarkjs Node-CLI did

Attempted `snarkjs.groth16.prove` in the same `v5_2-prove.mjs` CLI under
the 48 GB cgroup — **OOM-killed at ~57 s**. Confirms snarkjs Node prove
peaks ABOVE 48 GB (higher than the browser content-RSS measurement;
Node V8 + ffjavascript memory layout is even less compact than Firefox
SpiderMonkey). The ceremony script avoids this because it shells out
to the snarkjs CLI as a separate process and gets fresh-process memory
benefits — even so, ceremony peak was ~26 GB for the prove leg, well
under the cap. The Node-hosted snarkjs benchmark was abandoned;
ceremony + browser numbers cover the snarkjs side adequately.

## Reducing the peak — what's realistic

The 38 GiB peak is overwhelmingly a snarkjs/ffjavascript artifact, NOT
a V5.2-circuit-shape artifact. Realistic reduction paths, ranked by
expected leverage:

| Lever | Expected peak | Owner | Effort | Notes |
|---|---|---|---|---|
| **Tauri/Electron desktop app + native rapidsnark** (web frontend, native prover backend, local-IPC) | **3.7 GiB measured** | web-eng + circuits-eng | 1-2 weeks | Ships ~30 MB shell + 1 MB rapidsnark binary. Browser still does witness calc (WASM); shells out to native prover. **Measured against V5.2 stub: 13.9 s wall, 3.7 GiB peak. Single highest-leverage path.** |
| **Mopro on iOS/Android** (native rapidsnark via Swift/Kotlin FFI) | ~3-5 GiB (native, similar to desktop) | mobile-eng (new) | 2-3 weeks | The official mobile-prove path per zkmopro.org. Native app, NOT browser. Same 6-13x speedup as desktop. |
| **rapidsnark-WASM port** (C++ groth16, replaces snarkjs prover) | ~25 GiB best case, uncertain | web-eng + circuits-eng | 1-3 months | NO existing port. Forking rapidsnark + replacing inline asm with portable C++ + Emscripten compile + memory-model work. The 30% asm speedup is platform-specific; lost in WASM. **Earlier "1-2 weeks" estimate was wrong. Native rapidsnark via desktop/mobile shell beats this on every axis.** |
| **arkworks-rs WASM groth16 prover** | uncertain — "doesn't outperform snarkjs in browser" per Mopro/PSE benchmarks | new dep | 2-3 weeks | Tried; no perf advantage demonstrated at scale. Skip. |
| **Server-side delegated proving** | n/a (server-side) | web-eng | 3-5 days | Browser sends witness to server, gets back proof. Privacy trade-off: witness includes `walletSecret` which is the user's keying material. Possibly acceptable with proper TEE / trust scoping; needs threat-model review. |
| **V5.3 constraint-reduction amendment** (move bindingHash + signedAttrsHash + leafTbsHash on-chain) | ~22-28 GiB (browser) | circuits-eng + contracts-eng | 1-2 weeks | -1.5 to -2.5M constraints (-40-65%). Strictly increases on-chain calldata + reduces ZK compactness. Adds ~60-100K register() gas. Real engineering trade-off; not free. Helps browser path; doesn't help if we go native rapidsnark anyway. |
| **Streaming zkey load + chunked allocator** | ~33-35 GiB | web-eng | 3-5 days | Saves ~3-5 GB transient buffer overlap during zkey-parse step. Doesn't touch prove-time peak. PRIMARILY unlocks Chrome (V8 cap), not memory reduction. |
| **Web Worker isolation** | unchanged | web-eng (#24, in flight) | 0 | Moves prover off main thread — same total memory, better UX. |

**Updated recommendation (post-rapidsnark-CLI measurement)**:

The native rapidsnark CLI proves V5.2 in **13.9 s with 3.70 GiB peak**.
That's a 6-7x speedup AND ~10x memory reduction vs snarkjs. The path
forward is **NOT a rapidsnark→WASM port** (which earlier in this report
I overstated as 1-2 weeks; in reality it's 1-3 months with uncertain
savings). The path forward is to **expose rapidsnark via a native shell**:

- **Desktop**: Tauri (or Electron) app — web frontend, native rapidsnark
  embedded as a binary. End-user installs once, then "click button →
  14 s wait → done". Fits ALL consumer laptops including 8 GB. **Effort:
  1-2 weeks for production-quality wrapper.**
- **Mobile**: Mopro (zkmopro/mopro) — native FFI to rapidsnark on
  iOS/Android, ~3-5 GiB peak, similar wall time. Effort 2-3 weeks.
- **Pure-web fallback**: keep the current Firefox 64-bit / 32 GB
  workstation path for users who refuse to install. Document the
  performance gap honestly in the UI.

This entirely supersedes the earlier "rapidsnark-WASM port" recommendation
in this same report. The native shell path is a fraction of the effort
and dramatically better numbers — measured, not estimated.

V5.3 constraint reduction remains a real lever but its ROI gets eaten
by the rapidsnark native shell path: if we're going native anyway,
shaving 1-2M circuit constraints buys mostly proof-time savings (which
are already 6.4 s with rapidsnark) rather than feasibility-unlock.
Defer V5.3 unless we hit an unrelated soundness or feature need.

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
