# zkqes Helper — V5.2 Native Prove Acceleration via On-Demand Local Helper

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **Status:** Draft v0.1 — pending user-review gate.
>
> **Date:** 2026-05-03.
>
> **Predecessor work (load-bearing, READ FIRST):**
> - `docs/handoffs/2026-05-03-v5_2-browser-prove-benchmark.md` — measured browser fullProve at 90.3 s / 38.38 GiB peak content RSS; native rapidsnark at 13.86 s / 3.70 GiB peak.
> - `packages/circuits/scripts/v5_2-prove.mjs` (commit `c1ce6a9`) — V5.2-native prove CLI with snarkjs + rapidsnark backends.
> - `packages/circuits/scripts/v5_2-prove-server.mjs` (uncommitted prototype) — local HTTP prove helper, 12.94 s end-to-end via curl, validated origin pinning + Chrome PNA.
> - `docs/superpowers/specs/2026-05-01-keccak-on-chain-amendment.md` (V5.2 spec v0.5) — frozen public-signal layout (22 signals), stub ceremony at `ceremony/v5_2/`.
>
> **Direction confirmed by lead (2026-05-03):** ship helper, NOT full Tauri app. Reasons: (a) founder's "browser canonical" directive from 2026-04-29 must be preserved; helper augments only the prove step, app inverts the whole flow; (b) trust narrative is product (privacy tool selling "chain doesn't learn who you are"); helper says "runs 14 s, exits"; (c) dual-shell maintenance tax avoided forever; (d) Diia integration model already lives in browser (`.p7s` upload, EOA wallet, on-chain submission), only prove benefits from native acceleration.
>
> **Mobile is out of scope.** Mopro path remains open for a future track but is not addressed here.

## TL;DR

Ship a small Node-based **zkqes Helper** binary, signed and notarized for macOS / Windows / Linux, that runs **on demand** via a `qkb://` URL scheme deep-link. When invoked, the helper binds `127.0.0.1:9080`, accepts a single witness JSON via origin-pinned HTTPS POST, runs the iden3 rapidsnark prover natively, returns the proof, and auto-quits after 5 minutes idle. Browser at `/v5/registerV5` detects the helper before the prove step; if reachable, offloads to it (13 s vs 90 s, 3.7 GiB vs 38 GiB); if not, falls back to in-browser snarkjs (current behavior, unchanged).

Browser remains the canonical UI, wallet host, and on-chain submitter. Helper is a single-purpose accelerator for one step.

## Goals

1. **Surgically replace the prove step** for users on capable desktops (macOS / Windows / Linux), without touching the rest of the V5.2 register flow.
2. **Preserve "browser canonical" posture.** No part of the user journey requires the helper. Helper is purely an opt-in performance upgrade.
3. **No background process.** Helper runs only while doing work, not at login.
4. **Trust-narrative-first.** "Runs 14 seconds, exits" is the design intent and the marketing copy.
5. **Zero new wallet integration.** Browser keeps wagmi + MetaMask / WalletConnect. Helper never sees a private key.
6. **Reuse measured artifacts.** Ship the iden3 rapidsnark prebuilt (v0.0.8 already validated against V5.2 zkey).
7. **Browser code-path additive only.** Existing V5.2 register flow continues to work for users without the helper. Helper detection adds one wrapper around the prove step.

## Non-goals

- Mobile (iOS / Android) — Mopro is a separate track.
- Replacing the browser flow. Helper is an accelerator, not a successor.
- Embedded wallet, custom UI, native chrome.
- Multi-circuit support. V5.2 only; future versions will deliver new helper builds.
- Multi-user shared workstation security model. Trust boundary is "single user owns this machine."

## Background — why the helper

V5.2 in-browser prove costs **38.38 GiB peak content-process RSS, 90 s wall** (Firefox 64-bit on Linux x86_64; Chrome OOMs at the V8 ArrayBuffer cap before zkey load completes). The same V5.2 zkey + witness through native rapidsnark produces an **identical proof** in **13.86 s / 3.70 GiB peak**. The 6.5× speedup and ~10× memory drop are attributable entirely to C++ + asm vs JavaScript BigInt; rapidsnark's prover output is byte-identical to snarkjs's.

A WASM port of rapidsnark does not exist (iden3 has not built one; the asm speedups are platform-specific). A real port would be 1-3 months with uncertain savings (see browser-prove benchmark report §"Reducing the peak"). The pragmatic alternative is to invoke the existing native binary from a thin local helper. This spec defines that helper.

## Architecture

```
                       ┌─────────────────────────────────────┐
                       │ zkqes.org/v5/registerV5    │
                       │  • wallet (wagmi)                   │
                       │  • witness build (@zkqes/sdk)         │
                       │  • on-chain submit (wagmi)          │
                       └─────────────────────────────────────┘
                                       │
                                       │  prove step ──▶ POST localhost:9080/prove
                                       │                 (witness JSON, ~85 KB)
                                       │
                                       ▼
                       ┌─────────────────────────────────────┐
                       │ qkb-helper (Node, on-demand)        │
                       │  • HTTP listener on 127.0.0.1:9080  │
                       │  • Origin pin: zkqes.org   │
                       │  • Idle timeout: 300 s              │
                       │                                     │
                       │  ┌──────────────────────────────┐   │
                       │  │ snarkjs.wtns.calculate (WASM) │  │
                       │  └──────────────┬───────────────┘   │
                       │                 │                   │
                       │  ┌──────────────▼───────────────┐   │
                       │  │ rapidsnark sidecar (spawn)   │   │
                       │  │  prover <zkey> <wtns>        │   │
                       │  │         <proof> <public>     │   │
                       │  └──────────────────────────────┘   │
                       └─────────────────────────────────────┘
                                       │
                                       │  proof + publicSignals
                                       ▼
                       ┌─────────────────────────────────────┐
                       │ Browser: groth16.verify locally     │
                       │ Browser: registerOrRotate(...)      │
                       │ → QKBRegistry on chain              │
                       └─────────────────────────────────────┘
```

### Activation flow (cold start)

```
Browser loads /v5/registerV5
    │
    ▼
On "Generate proof" click:
    POST localhost:9080/prove ──▶ ECONNREFUSED?
    │                              │
    │                              ▼
    │                      window.location.href = 'qkb://launch'
    │                              │
    │                              ▼
    │                      OS spawns qkb-helper (~200-500 ms)
    │                              │
    │                              ▼
    │                      helper binds :9080, ready
    │                              │
    │                              ▼
    │                      Browser polls /status (5 retries × 500 ms backoff)
    │                              │
    │                              ▼
    └──── 200 OK ──── retry POST localhost:9080/prove ──▶ proof returned
                                                          │
                                                          ▼
                                                  helper continues serving
                                                  for 300 s after last request,
                                                  then exits
```

The retry-with-backoff on `/status` after deep-link launch is **load-bearing** — without it, the first prove on a freshly-launched helper shows a transient "helper unreachable" error in the 200-500 ms window between deep-link fire and port bind.

### Activation flow (warm — helper already running)

```
Browser loads /v5/registerV5
    │
    ▼
GET /status on page mount → 200 OK ─▶ "🟢 Fast prover available" badge in UI
    │
    ▼
On "Generate proof" click:
    POST localhost:9080/prove ─▶ proof returned (~13 s)
```

No deep-link fired. No retry needed. Same UX as a regular click.

## Helper internals

### Binary contents

| Component | Size | Source |
|---|---|---|
| Node runtime (bundled via `pkg` or `nexe`) | ~25-30 MB | Node 20 LTS standalone |
| Helper logic (HTTP listener + glue) | ~10 KB | This spec, derived from `scripts/v5_2-prove-server.mjs` |
| `snarkjs` UMD bundle (for `wtns.calculate`) | ~700 KB | `node_modules/snarkjs` |
| `rapidsnark` prover binary (sidecar) | 0.7 MB | iden3 `rapidsnark-linux-x86_64-v0.0.8`, `rapidsnark-darwin-arm64-v0.0.8`, `rapidsnark-darwin-x86_64-v0.0.8`, `rapidsnark-windows-x86_64-v0.0.8` |
| V5.2 WASM circuit (witness calculator) | 21 MB | `build/v5_2-stub/QKBPresentationV5_js/QKBPresentationV5.wasm` (Phase B will swap to production WASM with same name + sha256 manifest pin) |
| `verification_key.json` | 6.6 KB | `ceremony/v5_2/verification_key.json` |
| Installer wrapper (per OS) | ~1-2 MB | `pkgbuild`/`productbuild` (macOS), WiX (Windows), `dpkg-deb` + AppImage tooling (Linux) |
| **Total installer per OS** | **~50-55 MB** | — |

The 2.16 GB V5.2 zkey is **NOT bundled**. Helper downloads it on first use (see "zkey lifecycle" below).

### Endpoints

#### `GET /status`

```
Response 200 {
  "ok": true,
  "version": "qkb-helper@<semver>",
  "circuit": "v5.2",
  "zkeyLoaded": true | false,
  "busy": false | true,
  "provesCompleted": <n>,
  "uptimeSec": <n>
}
```

Used by browser to detect helper presence and zkey readiness. Returns 200 even if the helper has not yet downloaded the zkey (in which case `zkeyLoaded: false`); browser shows progress UI accordingly.

#### `POST /prove`

```
Request:
  Content-Type: application/json
  Origin: https://zkqes.org   (load-bearing; 403 otherwise)
  Body: { ...witness JSON from buildWitnessV5(...) ... }

Response 200 {
  "proof":          <Groth16 proof object>,
  "publicSignals":  [<22 strings>, ...],
  "verifyOk":       true,
  "timings": {
    "wtnsCalculateSec": 6.81,
    "groth16ProveSec":  5.86,
    "groth16VerifySec": 0.27,
    "totalSec":         12.94
  }
}

Response 4xx/5xx { "error": "<human-readable>" }
```

The helper performs `groth16.verify` server-side as a sanity check before returning, so a bad witness is caught locally with a clear error rather than producing a non-verifying proof. Browser re-verifies anyway (current code path).

#### `POST /shutdown` (optional, future)

Not in V1. Helper auto-quits after 300 s idle; explicit shutdown is unnecessary for V1 scope.

### Concurrency

V1 supports **one prove at a time**. A second `POST /prove` while the first is in-flight returns `429 Too Many Requests` with body `{ "error": "helper busy with another prove" }`. V5.2 register is a single-prove flow per session; this is sufficient.

### Idle exit

Helper sets a timer on each request completion. After `IDLE_TIMEOUT_MS = 300_000` (5 min) of no requests, it `process.exit(0)`. Browser-side, on next prove, the launch flow re-fires.

## Browser-side integration

### Detection

On `/v5/registerV5` mount:

```ts
async function detectHelper(): Promise<HelperStatus> {
  try {
    const res = await fetch('http://127.0.0.1:9080/status', {
      method: 'GET',
      mode: 'cors',
      credentials: 'omit',
      signal: AbortSignal.timeout(500),
    });
    if (res.ok) return await res.json();
  } catch {
    // ECONNREFUSED, CORS error, or timeout → not running
  }
  return { ok: false };
}
```

Result:
- `ok: true, zkeyLoaded: true` → render "🟢 Fast prover available (~14 s)" badge.
- `ok: true, zkeyLoaded: false` → render "Fast prover initializing… (downloading proving key)" with progress polling.
- `ok: false` → render normal browser-prove UX with an "Install zkqes Helper for ~14 s prove" CTA next to the prove button.

### Prove call (replaces current `SnarkjsProver` worker invocation)

```ts
async function proveViaHelper(witnessJson: object): Promise<ProveResult> {
  // 1. Try direct POST.
  let res = await tryPost('/prove', witnessJson);
  if (res.ok) return await res.json();
  if (res.status !== 0 /* network error */) throw new HelperError(res);

  // 2. Helper not running. Fire deep-link + poll /status until 200.
  window.location.href = 'qkb://launch';
  const ready = await pollStatusReady({
    intervalMs: 500,
    maxAttempts: 5,  // 2.5 s total
  });
  if (!ready) throw new HelperError('helper did not respond after deep-link launch');

  // 3. Retry POST.
  res = await tryPost('/prove', witnessJson);
  if (!res.ok) throw new HelperError(res);
  return await res.json();
}

async function pollStatusReady(opts: { intervalMs: number; maxAttempts: number }): Promise<boolean> {
  for (let i = 0; i < opts.maxAttempts; i++) {
    await sleep(opts.intervalMs);
    const status = await detectHelper();
    if (status.ok && status.zkeyLoaded) return true;
  }
  return false;
}
```

The poll budget (5 × 500 ms = 2.5 s) covers helper Node-startup (~200-500 ms) + zkey-already-cached check (~50 ms) + first-time setup if needed. If helper is doing first-launch zkey download (~3-5 min on broadband), the poll surfaces `zkeyLoaded: false` and the browser shows a "downloading proving key, ~3 min" progress UI rather than failing.

### Fallback to browser prove

If the helper is unreachable AFTER the deep-link launch attempt, browser falls back to `SnarkjsProver` Web Worker (web-eng task #24, already in main). User sees the slower-but-functional flow they had before. No silent failure.

### UI states

| State | UI |
|---|---|
| Helper detected, zkey ready | Green badge "Fast prover available (~14 s)". Prove button labeled "Generate proof". |
| Helper detected, zkey downloading | Yellow badge "Initializing fast prover… <progress>". Prove button labeled "Generate proof (using browser prover)" with subtle "Will switch to fast prover when ready" tooltip. |
| Helper not installed | Gray badge "Slower browser prover (~90 s, Firefox 64-bit / 32 GB only)". Inline CTA "Install zkqes Helper" linking to `/download`. |
| Helper installed but not running | Same as detected; deep-link fires automatically on prove click. |
| Deep-link failed (browser blocked / no handler) | Surface "Could not reach helper. Install or restart it from <link>." |
| Helper crashed mid-prove | 5xx response → fall back to browser prove with a "Helper failed; using browser prover" toast. |

## Security model

### Loopback only

Helper binds `127.0.0.1:9080`, never `0.0.0.0`. LAN devices cannot reach it. Verified by spec; CI test plan includes asserting the bind address.

### Origin pinning

Helper inspects the `Origin` header on every request. If `Origin !== https://zkqes.org`, returns `403 Forbidden` with body `{ "error": "origin not allowed" }`. This prevents arbitrary websites from co-opting a user's local helper.

For dev/staging (`https://staging.zkqes.org`, `http://localhost:5173`), the helper accepts an `--allowed-origin` CLI flag. Production builds hard-code production origin only; dev builds expose the flag.

Validated end-to-end in `scripts/v5_2-prove-server.mjs` prototype.

### Chrome Private Network Access

Helper emits `Access-Control-Allow-Private-Network: true` on every response. Required for Chrome 117+ to permit a public-origin (`https://zkqes.org`) → private-network (`http://127.0.0.1:9080`) request. Validated end-to-end via `OPTIONS` preflight returning 204.

### No auth tokens

The trust boundary is "anything running as this OS user has access to this loopback port." This is the same trust boundary the user already accepts for everything else they run. We do not add an HMAC / token / handshake on top.

### Witness JSON contains `walletSecret`

The witness includes `walletSecret` (32 bytes), which is keying material derived from the user's MetaMask `personal_sign` signature. The helper:

- **Reads it from the POST body** into in-process memory only.
- **Passes it to snarkjs.wtns.calculate** which writes a binary `.wtns` file to a tempdir under `os.tmpdir()` (e.g., `/tmp/qkb-prove-XXXXXX/witness.wtns`).
- **Spawns rapidsnark** which reads the `.wtns` and produces `proof.json` + `public.json` in the same tempdir.
- **Returns the proof** to the browser.
- **Deletes the entire tempdir** in a `finally` block, regardless of success/failure.

`walletSecret` is therefore on disk for the duration of one prove (~14 s). Documented explicitly in the helper's PRIVACY notes and in the web-app PRIVACY.md (web-eng to update).

### No telemetry by default

V1 ships zero telemetry. No crash reporting, no analytics, no version-check beacon (auto-update fetches the manifest only when user-initiated; see "Auto-update" below).

### Code-signing

- **macOS:** Apple Developer ID Application certificate; binary signed and notarized via `notarytool`. URL scheme handler MUST be signed or Gatekeeper refuses to register it. Hardened runtime enabled. Entitlements: only `com.apple.security.network.server` (for loopback bind) and `com.apple.security.network.client` (for zkey download).
- **Windows:** Authenticode SHA-256 signature with timestamp; EV cert preferred to avoid SmartScreen warm-up period. URL scheme registry entries written by the signed installer.
- **Linux:** No system-level signing required; we publish detached GPG signatures of the `.deb` and `.AppImage` alongside the artifact.

Code-signing is the longest-tail item (Apple notarization can take hours per build). Lead owns cert procurement (already on lead's plate per the broader plan).

## Distribution

### Channels

| OS | Primary | Secondary |
|---|---|---|
| macOS | `zkqes.org/download` → `QKBHelper-{version}-arm64.pkg` and `QKBHelper-{version}-x86_64.pkg` | `brew install qkb-eth/qkb/qkb-helper` (already-aliased tap; documented in `/ua/cli`) |
| Windows | `zkqes.org/download` → `QKBHelper-{version}.msi` | `winget install qkb-eth.qkb-helper` |
| Linux | `zkqes.org/download` → `qkb-helper-{version}.AppImage` and `qkb-helper-{version}.deb` | apt repo at `apt.zkqes.org` |

App Store and Microsoft Store are explicitly **out** for V1. Direct distribution preserves the "user trusts zkqes.org" trust chain.

### Landing page

Web-eng adds `/download` with:

- OS detection from User-Agent (existing pattern in `/ua/cli`).
- Direct download link for matched OS, with a "show all platforms" disclosure for the other two.
- Sha256 displayed alongside each download.
- Auto-detected "Already installed?" probe (calls helper `/status`); if reachable, page redirects to `/v5/registerV5`.
- Install instructions per OS (3 steps each, screenshots).

### Installer responsibilities

| Step | macOS | Windows | Linux (.deb) |
|---|---|---|---|
| Place binary | `/Applications/zkqes Helper.app/Contents/MacOS/qkb-helper` | `C:\Program Files\zkqes Helper\qkb-helper.exe` | `/usr/local/bin/qkb-helper` |
| Register URL scheme | `CFBundleURLTypes` in `Info.plist`, scheme `qkb` | Registry: `HKEY_CLASSES_ROOT\qkb` with `URL Protocol`, command `"%ProgramFiles%\zkqes Helper\qkb-helper.exe" "%1"` | `.desktop` file with `MimeType=x-scheme-handler/qkb;`, `xdg-mime default qkb-helper.desktop x-scheme-handler/qkb` post-install |
| First-launch zkey download | First `qkb://launch` triggers download with progress UI | Same | Same |

No login items, no services, no daemons registered. **The installer's only persistent side-effect is the URL scheme handler.**

### Uninstall

| OS | Mechanism |
|---|---|
| macOS | Drag `zkqes Helper.app` to Trash. Helper offers a "Reset and uninstall" command (`qkb-helper --uninstall`) that also removes the cached zkey (~2.16 GB). |
| Windows | Add/Remove Programs. Same `--uninstall` command available. |
| Linux | `apt remove qkb-helper` or remove the AppImage. Cached zkey at `~/.local/share/qkb-helper/circuits/` lingers; documented in README. |

Uninstall does NOT auto-remove the cached zkey by default (avoid surprising users who reinstall with a 2 GB re-download). The `--uninstall` command and platform-specific cleanup tooling get explicit cache-purge UX.

## Auto-update

### Mechanism

Helper checks for updates at most once per 24 hours, **only when invoked** (no background polling). On first launch within a 24-hour window:

1. Fetch `https://zkqes.org/helper-manifest.json` (signed by lead's release key).
2. Compare embedded version to current binary.
3. If update available, surface a one-time toast in the helper's stdout / system notification: "zkqes Helper update available: {version}. Download from zkqes.org/download".

V1 does **not** auto-install updates. Manual update only — user re-downloads from the website. This avoids the "background process modifies itself" trust footgun and the cross-OS auto-update tooling complexity. Future versions may add Tauri-style differential updates if user friction warrants.

### Manifest format

```
{
  "version": "1.0.0",
  "released": "2026-05-15T12:00:00Z",
  "changelog": "Initial V5.2 release",
  "circuits": {
    "v5.2": {
      "zkeyUrl":      "https://r2.zkqes.org/qkb-v5_2-stub.zkey",
      "zkeySha256":   "b66bad1d27f2e0b00f2db7437a0fab365433165dccb2f11d09ee3eb475debce2",
      "wasmUrl":      "https://r2.zkqes.org/qkb-v5_2.wasm",
      "wasmSha256":   "<hash>",
      "vkeyUrl":      "https://r2.zkqes.org/qkb-v5_2-vkey.json",
      "vkeySha256":   "<hash>"
    }
  }
}
```

Manifest is signed (detached signature `.sig` next to it). Helper verifies signature before trusting any URL or hash. Lead owns key management for the release key.

When V5.2 production ceremony swaps the stub zkey for the real one (Phase B output), the manifest gets updated; helper detects the new `zkeySha256`, downloads the new zkey, and replaces the cache. Old zkey is deleted only after new zkey verifies.

## zkey lifecycle

### Cache location

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/zkqes Helper/circuits/qkb-v5_2.zkey` |
| Windows | `%APPDATA%\zkqes Helper\circuits\qkb-v5_2.zkey` |
| Linux | `~/.local/share/qkb-helper/circuits/qkb-v5_2.zkey` |

### Download flow

On first invocation (or zkey sha256 mismatch):

```
1. Helper receives POST /prove or its launcher detects no cached zkey.
2. Helper enters "downloading" state. /status returns zkeyLoaded: false.
3. Helper downloads from manifest's zkeyUrl, streams to <cache>/qkb-v5_2.zkey.tmp.
4. SHA-256 verified against manifest's zkeySha256.
   ├─ match → atomic mv to qkb-v5_2.zkey, /status now reports zkeyLoaded: true.
   └─ mismatch → delete .tmp, /status reports error, helper logs & exits.
5. /prove now serves normally.
```

Browser shows progress percentage by polling `/status` at 1 Hz (helper exposes `downloadProgress: { downloadedBytes, totalBytes }` in `/status` while downloading).

### Verification on every launch

Each time helper starts, it sha256-verifies the cached zkey before accepting any prove. ~2 s overhead on cold start (one-time per launch session).

### Pump from Phase B

When the real V5.2 production ceremony lands (Phase B, separate plan), lead pumps the new zkey to R2 and updates the manifest. Helper auto-detects via the sha256 check, downloads the new zkey, replaces the cache. No user action needed.

## UX states (full enumeration)

| State | Browser UI | Helper state |
|---|---|---|
| Helper not installed, has not been launched | "Slower browser prover (~90 s, Firefox 64-bit only)" badge + "Install zkqes Helper" CTA | Not running, no install |
| Helper installed, never launched, zkey not downloaded | "Install detected. First prove will download proving key (~3 min)" CTA | Not running |
| Helper installed, launched once, zkey download in progress | "Initializing fast prover: 47% (downloading proving key, ~2 min remaining)" | Running, zkeyLoaded: false, downloadProgress |
| Helper running, zkey ready, no prove in flight | "🟢 Fast prover available (~14 s)" | Running, zkeyLoaded: true, busy: false |
| Helper running, prove in flight | "Generating proof… (~14 s)" with progress | Running, busy: true |
| Helper running, prove succeeded | "Proof generated in 13.8 s" + on-chain submit step | Running, busy: false, provesCompleted++ |
| Helper running, prove failed (witness invalid) | "Proof generation failed: <error>" + retry button | Running, busy: false |
| Helper running, prove failed (rapidsnark crash / OOM) | Surface as helper error + automatic fallback to browser prove | Running |
| Helper unreachable mid-flow | Auto-retry once with deep-link, then fall back to browser prove | Possibly crashed |

## Effort and ownership

| Task | Owner | Days |
|---|---|---|
| Helper binary: bundling Node + snarkjs + sidecar wiring + idle-exit + zkey-fetch-and-verify + URL-scheme entrypoint | circuits-eng | 4-5 |
| Cross-OS rapidsnark sidecar build matrix (macOS arm64, macOS x86_64, Windows x86_64, Linux x86_64) | circuits-eng | 1 |
| Per-OS installer (macOS .pkg, Windows .msi, Linux .deb + AppImage) | circuits-eng | 2-3 |
| Code-signing setup (Apple Developer ID + Authenticode + macOS notarization integration) | lead | 2-3 |
| Browser-side: helper detection + deep-link launch + retry-with-backoff + UI states | web-eng | 2-3 |
| Auto-update manifest + signature verification | circuits-eng | 1-2 |
| brew tap update (qkb-eth/qkb/qkb-helper) + winget config | lead | 1 |
| `/download` landing page on `zkqes.org` | web-eng | 1 |
| Apt repo setup at `apt.zkqes.org` | lead | 0.5-1 |
| E2E test on all 3 OSes | circuits-eng | 1-2 |
| PRIVACY.md updates (browser side; helper-side bundled in installer) | web-eng + lead | 0.5 |
| **Total** | — | **~15-22 days** |

Critical-path lockstep: code-signing certs are the longest tail; lead starts that on day 1 in parallel with helper development.

## Testing strategy

### Helper unit tests (Node)

- Origin pinning: requests with bad/missing/correct Origin → 403/403/200.
- CORS preflight: OPTIONS returns 204 with PNA header.
- Concurrency guard: second `/prove` while first in-flight → 429.
- Idle timeout: helper exits cleanly after `IDLE_TIMEOUT_MS` of inactivity.
- zkey sha256 verify: tampered cache → helper refuses to start until re-download.
- Witness validation: malformed witness → 5xx with parseable error.

### Integration tests (Node + real rapidsnark + real zkey)

- Full `POST /prove` against the V5.2 stub zkey + sample witness → byte-identical proof to `scripts/v5_2-prove.mjs --backend rapidsnark` output.
- Cold start: helper boots, downloads zkey from a local mock R2, verifies, serves prove. Timing budget ≤ 7 min on a 100 Mbps link.
- Warm start: helper boots with cached zkey, /status returns 200 within 3 s.
- Browser fixture: existing V5.2 mocha tests at `test/integration/v5-prove-verify.test.ts` extended to cover the helper path via Playwright + http-mock. Skip on CI without rapidsnark binary; run locally + on a self-hosted test runner.

### E2E tests (Playwright)

- Browser at `/v5/registerV5` with helper running → prove succeeds end-to-end, on-chain register call ABI matches.
- Browser at `/v5/registerV5` with helper NOT running → deep-link fired, helper starts, prove completes.
- Browser at `/v5/registerV5` with helper installed but zkey not yet downloaded → progress UI surfaces, prove waits, completes.
- Browser at `/v5/registerV5` with NO helper installed and deep-link blocked → graceful fallback to browser prove (existing flow).

### Cross-OS smoke tests

For each of macOS arm64 / macOS x86_64 / Windows x86_64 / Linux x86_64:

- Fresh install: `.pkg` / `.msi` / `.deb` runs cleanly, URL scheme registers, deep-link launches helper.
- Code-signing verification: Gatekeeper / SmartScreen / GPG check on the artifact.
- First-prove cold-path with real zkey download.
- Uninstall: artifact removed, cache optionally purged via `--uninstall`.

## Risks and mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Apple notarization rejects the Node-bundled binary (e.g., for "uses unstable APIs") | High — blocks macOS ship | Use `pkg`'s `--public-packages` flag, validate notarization on a test build day 1; fallback to building Node from source with hardened flags. |
| Chrome's PNA gate evolves and breaks our preflight | Medium | Pin to current spec; monitor Chrome release notes. Helper's CORS+PNA headers are explicit, easy to update. |
| Browser blocks `qkb://` deep-link without user prompt | Medium | First-launch UX doc includes "click 'Open with zkqes Helper' in browser prompt"; this is a one-time confirmation per browser per OS. |
| 2 GB zkey download fails / partials on slow links | Medium | Atomic write + sha256 verify + clear retry UX. Browser shows progress; helper supports HTTP Range resume in V1.1. |
| User runs multiple browsers simultaneously, both detect helper, race | Low | Concurrency guard (429 on busy); browsers handle 429 by queuing and retrying. |
| Phase B production ceremony zkey is materially larger than stub | Low | Spec-amendment checked: production zkey is bytewise the same size as stub (~2.0 GB; pot22 capacity dominates, contributor count is irrelevant to size). |
| `walletSecret` in tempfile during prove is read by another local process | Medium | Tempdir uses `mkdtemp` with 0700 perms; documented in PRIVACY. Multi-user shared workstation is out-of-scope. |
| Helper crashes leave zombie tempfiles | Low | Helper registers SIGINT/SIGTERM/uncaughtException handlers that wipe tempdir. Worst case: idle-timeout exit cleans up. |
| Auto-update manifest signature key compromised | High but managed | Signing key lives in lead's hardware-token store; rotation procedure documented in lead's release runbook. |

## Open questions

1. **`Sec-Fetch-Site` and `Sec-Fetch-Mode` enforcement?** Should helper additionally check `Sec-Fetch-Site: cross-site` to defend against a same-origin compromise on `zkqes.org`? Lean: yes for defense-in-depth, but Origin pin already covers the threat model. Defer to V1.1.
2. **Multi-circuit support.** When V5.3 lands, do we ship a new helper version that supports both V5.2 and V5.3 (auto-selects per request), or one helper per circuit version? Lean: same helper, multiple zkeys cached, manifest declares which is current. Defer until V5.3 design.
3. **Helper logging policy.** Helper's stderr logs include witness field counts and prove timings. Should there be a `--quiet` flag? A logs-to-disk option? Lean: stderr only, no disk by default; user can pipe with `qkb-helper >helper.log 2>&1` if they want diagnostics. Defer.
4. **Brew vs. official direct download as primary.** Marketing copy needs to pick one. Lean: direct download as primary CTA, brew/winget mentioned in `/ua/cli`-style power-user disclosure. Defer to web-eng during landing-page work.
5. **Linux distribution: AppImage vs Flatpak vs Snap?** V1 ships AppImage + .deb (broadest reach with least packaging effort). Flatpak/Snap deferred to community-PR.

## References

- V5.2 prove benchmark report: `docs/handoffs/2026-05-03-v5_2-browser-prove-benchmark.md`
- V5.2 native prove CLI: `packages/circuits/scripts/v5_2-prove.mjs` (commit `c1ce6a9`)
- Local prove server prototype: `packages/circuits/scripts/v5_2-prove-server.mjs` (uncommitted; lifts directly into the helper's HTTP layer)
- V5.2 ceremony: `packages/circuits/ceremony/v5_2/` and `packages/circuits/ceremony/scripts/stub-v5_2.sh` (commit `5cbd888`)
- V5.2 spec: `docs/superpowers/specs/2026-05-01-keccak-on-chain-amendment.md` v0.5
- iden3 rapidsnark: `https://github.com/iden3/rapidsnark` (v0.0.8, January 2026)
- iden3 proverServer (REST API in iden3/rapidsnark/service): documented but build-from-source; we use our own thin Node wrapper

## Revision history

- v0.1 (2026-05-03): initial draft.

End of v0.1 spec.
