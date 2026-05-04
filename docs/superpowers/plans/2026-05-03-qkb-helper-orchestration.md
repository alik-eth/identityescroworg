# zkqes Helper Orchestration Plan

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Coordinate the three-worker delivery of zkqes Helper V1 — a small on-demand local prove accelerator that turns the V5.2 register flow's prove step from 90 s / 38 GiB (in-browser snarkjs) into 13.9 s / 3.7 GiB (native rapidsnark via deep-link helper), while keeping browser canonical for everything else.

**Architecture:** Three independently-mergeable tracks — circuits-eng owns the helper binary + per-OS installers, web-eng owns browser detection + `/download` landing, lead owns code-signing certs + brew/winget + R2 manifest. All three converge on a single `feat/qkb-helper` integration branch for E2E. Spec at `docs/superpowers/specs/2026-05-03-qkb-helper-design.md` (commit `74605b2`).

**Tech Stack:** Node 20 LTS bundled via `pkg`, iden3 rapidsnark v0.0.8 (prebuilt sidecars for 4 platforms), TypeScript, React (existing web app), Apple Developer ID + Authenticode + GPG signing, Homebrew tap + winget.

---

## §1 — Interface contracts (FROZEN)

These contracts are load-bearing across all three workers. Changes require explicit lead sign-off and a cross-worker broadcast.

### §1.1 — HTTP API (helper ↔ browser)

```
GET http://127.0.0.1:9080/status
  Origin: <any> (no origin pin on /status — used by browser detection)
  Response 200 application/json:
    {
      "ok": true,
      "version": "qkb-helper@<semver>",         // string, e.g. "1.0.0"
      "circuit": "v5.2",                          // hard-coded for V1
      "zkeyLoaded": <boolean>,                    // false during first-run download
      "busy": <boolean>,                          // true if a /prove is in flight
      "provesCompleted": <integer>,               // monotonic counter
      "uptimeSec": <integer>,
      "downloadProgress": {                       // present iff zkeyLoaded == false
        "downloadedBytes": <integer>,
        "totalBytes": <integer>
      } | null
    }

POST http://127.0.0.1:9080/prove
  Origin: https://zkqes.org   (REQUIRED; 403 otherwise)
  Content-Type: application/json
  Body: <witness JSON from buildWitnessV5(...) — 22 public + 10518 private signals>
  Response 200 application/json:
    {
      "proof": <Groth16 proof object — same shape as snarkjs.groth16.fullProve output>,
      "publicSignals": [<22 decimal strings>],
      "verifyOk": true,
      "timings": {
        "wtnsCalculateSec": <number>,
        "groth16ProveSec": <number>,
        "groth16VerifySec": <number>,
        "totalSec": <number>
      }
    }
  Response 403: { "error": "origin not allowed", "allowed": "https://zkqes.org", "got": "<received>" }
  Response 429: { "error": "helper busy with another prove" }
  Response 5xx: { "error": "<human-readable message>" }

OPTIONS http://127.0.0.1:9080/prove
  Origin: https://zkqes.org
  Access-Control-Request-Method: POST
  Access-Control-Request-Private-Network: true
  Response 204:
    Access-Control-Allow-Origin: https://zkqes.org
    Access-Control-Allow-Methods: GET, POST, OPTIONS
    Access-Control-Allow-Headers: Content-Type
    Access-Control-Allow-Private-Network: true
    Vary: Origin
```

**Both workers freeze against this shape.** `verifyOk: true` is asserted server-side before the response is constructed; browser still re-verifies. Browser MUST NOT trust `verifyOk` alone.

### §1.2 — URL scheme

Scheme: `qkb://`

| Path | Behavior |
|---|---|
| `qkb://launch` | OS spawns helper binary if not running. Helper binds `127.0.0.1:9080`, returns immediately to caller (does NOT block). |

V1 supports only `qkb://launch`. Future expansion (`qkb://prove?...`, `qkb://shutdown`) deferred.

Per-OS registration:
- macOS: `CFBundleURLTypes` in `zkqes Helper.app/Contents/Info.plist`, scheme `qkb`.
- Windows: registry `HKEY_CLASSES_ROOT\qkb` with `URL Protocol`, command `"%ProgramFiles%\zkqes Helper\qkb-helper.exe" "%1"`.
- Linux: `.desktop` file with `MimeType=x-scheme-handler/qkb;`, `xdg-mime default qkb-helper.desktop x-scheme-handler/qkb` post-install.

### §1.3 — Auto-update manifest

URL: `https://zkqes.org/helper-manifest.json` (CloudFront/CDN-cached, 5 min TTL).

```json
{
  "version": "1.0.0",
  "released": "2026-05-15T12:00:00Z",
  "changelog": "Initial V5.2 release",
  "minSupportedVersion": "1.0.0",
  "circuits": {
    "v5.2": {
      "zkeyUrl":      "https://r2.zkqes.org/qkb-v5_2-stub.zkey",
      "zkeySha256":   "b66bad1d27f2e0b00f2db7437a0fab365433165dccb2f11d09ee3eb475debce2",
      "wasmUrl":      "https://r2.zkqes.org/qkb-v5_2.wasm",
      "wasmSha256":   "<from circuits-eng's vendor build>",
      "vkeyUrl":      "https://r2.zkqes.org/qkb-v5_2-vkey.json",
      "vkeySha256":   "<from circuits-eng's vendor build>"
    }
  }
}
```

Manifest signed via detached `helper-manifest.json.sig` (Ed25519). Lead's signing-key pubkey is **embedded in the helper binary at compile time** (no runtime fetch — eliminates substitution attacks).

### §1.4 — Cache paths

Helper writes to a per-user data directory:

| OS | Cache root |
|---|---|
| macOS | `~/Library/Application Support/zkqes Helper/` |
| Windows | `%APPDATA%\zkqes Helper\` |
| Linux | `~/.local/share/qkb-helper/` |

Subdirectories under cache root:
- `circuits/qkb-v5_2.zkey` — cached zkey (~2.16 GB)
- `circuits/qkb-v5_2.zkey.tmp` — partial download (atomic mv on completion)
- `manifest/helper-manifest.json` — last fetched manifest
- `logs/` — empty in V1 (no disk logs)

### §1.5 — Distributable artifacts

| OS | Filename | Architecture |
|---|---|---|
| macOS | `QKBHelper-{version}-arm64.pkg` | Apple Silicon |
| macOS | `QKBHelper-{version}-x86_64.pkg` | Intel |
| Windows | `QKBHelper-{version}-x86_64.msi` | x64 |
| Linux | `qkb-helper-{version}-x86_64.AppImage` | x64 |
| Linux | `qkb-helper_{version}_amd64.deb` | x64 (Debian/Ubuntu) |

All artifacts hosted at `https://zkqes.org/download/{filename}` (lead owns hosting). Sha256 sidecar files (`{filename}.sha256`) published alongside.

### §1.6 — Web frontend props

Web-eng's `proveViaHelper` function shape (consumed by existing prove call site in `Step4ProveAndRegister`):

```ts
interface HelperProveResult {
  proof: Groth16Proof;
  publicSignals: string[];
  verifyOk: boolean;          // from helper; NOT trusted alone
  timings: HelperTimings;
  source: 'helper' | 'browser';  // 'browser' if helper unreachable + fallback fired
}

async function proveViaHelper(witness: WitnessV5): Promise<HelperProveResult>;
```

Failure modes (web-eng must handle all):
- Helper detected at mount, but unreachable at prove time → fall back silently to browser prove.
- Deep-link fired but helper never responds → fall back to browser prove with a "Helper failed; using browser prover" toast.
- Helper returns 4xx (witness invalid) → surface error verbatim to user; do NOT fall back (browser would fail too).
- Helper returns 5xx (rapidsnark crash, OOM, etc.) → fall back to browser prove with a toast.

---

## §2 — Dispatch order

```
DAY 1                       DAY 2-5                      DAY 6-10                     DAY 11-15
─────                       ────────                     ─────────                    ──────────
[lead]    cert procurement  [lead]   apt repo + brew    [lead]   release runbook    [lead]   integration freeze
                                      (waits for cs)    [lead]   final certs land   [lead]   cut V1.0.0

[c-eng]   helper Phase 1    [c-eng]  helper Phase 2     [c-eng]  helper Phase 3      [c-eng]  E2E across 3 OS
          HTTP server core           zkey cache + url            installers                  cert-signed builds

                            [w-eng]  /v5/registerV5     [w-eng]  /download landing   [w-eng]  E2E Playwright
                                     prove-path swap            page + UA gating            against signed helper
```

Critical-path discipline:
- **lead's day-1 cert procurement** is the hard gate. Apple notarization can take hours per build; cert turnaround can take 1-3 days. If certs slip, day-15 ship slips.
- **circuits-eng's helper Phase 1 is independent** (HTTP server + tests; no certs needed). Can ship Phase 1 to a feature branch by end of day 3.
- **web-eng can dev against an unsigned local helper build** delivered by circuits-eng day 3. Doesn't wait for certs.
- **circuits-eng Phase 3 (installers) requires lead's certs.** That's the convergence point.

## §3 — Branches and worktrees

| Worker | Branch | Worktree |
|---|---|---|
| circuits-eng | `feat/qkb-helper-circuits` | `/data/Develop/qkb-wt-v5/qkb-helper-circuits/` |
| web-eng | `feat/qkb-helper-web` | `/data/Develop/qkb-wt-v5/qkb-helper-web/` |
| lead | `feat/qkb-helper-lead` (cert + infra docs only) | `/data/Develop/qkb-wt-v5/arch-circuits/` (lead's main checkout) |

All three branch from `feat/v5_2arch-circuits` (current lead checkout, contains the V5.2 stub + spec).

Lead does all merges. Order:
1. `feat/qkb-helper-circuits` first (provides the binary web-eng depends on).
2. `feat/qkb-helper-web` second.
3. `feat/qkb-helper-lead` rolls in cert configs + manifest publish docs.
4. Tag `v5.2.0-helper-rc1` after E2E green on all 3 OS.

## §4 — Lead-side scaffold (pre-dispatch)

Before dispatching workers, lead runs:

- [ ] **§4.1 — Create circuits-eng worktree**
```bash
cd /data/Develop/qkb-wt-v5/arch-circuits
git worktree add /data/Develop/qkb-wt-v5/qkb-helper-circuits -b feat/qkb-helper-circuits HEAD
```

- [ ] **§4.2 — Create web-eng worktree**
```bash
cd /data/Develop/qkb-wt-v5/arch-web
git worktree add /data/Develop/qkb-wt-v5/qkb-helper-web -b feat/qkb-helper-web feat/v5_2arch-web
```

- [ ] **§4.3 — Verify rapidsnark sidecar binary present**
```bash
ls -la /home/alikvovk/.cache/qkb-bin/rapidsnark-linux-x86_64-v0.0.8/bin/prover
# Expected: file exists, ~700 KB.
```

- [ ] **§4.4 — Pump the V5.2 stub artifacts to circuits-eng's worktree**
The fixtures are already in `feat/v5_2arch-circuits` HEAD; the worktree inherits them. Verify:
```bash
ls /data/Develop/qkb-wt-v5/qkb-helper-circuits/packages/circuits/ceremony/v5_2/
# Expected: Groth16VerifierV5_2Stub.sol, README.md, proof-sample.json,
#           public-sample.json, verification_key.json,
#           witness-input-sample.json, zkey.sha256.
```

- [ ] **§4.5 — Verify pot22 V5.2 zkey accessible at the documented R2 URL**
Lead procures the R2 hosting before the helper landing-page goes live. For dev, the zkey can be served from a local file URL passed via `--manifest-url file:///...`.

```bash
# Dev manifest stub (lead drops this in /tmp/dev-manifest.json):
cat > /tmp/dev-manifest.json <<'EOF'
{
  "version": "1.0.0-dev",
  "released": "2026-05-03T00:00:00Z",
  "changelog": "dev",
  "minSupportedVersion": "1.0.0-dev",
  "circuits": {
    "v5.2": {
      "zkeyUrl":     "file:///data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/ceremony/v5_2/qkb-v5_2-stub.zkey",
      "zkeySha256":  "b66bad1d27f2e0b00f2db7437a0fab365433165dccb2f11d09ee3eb475debce2",
      "wasmUrl":     "file:///data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/build/v5_2-stub/QKBPresentationV5_js/QKBPresentationV5.wasm",
      "wasmSha256":  "TBD (compute via sha256sum)",
      "vkeyUrl":     "file:///data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/ceremony/v5_2/verification_key.json",
      "vkeySha256":  "TBD (compute via sha256sum)"
    }
  }
}
EOF

# Compute the wasm + vkey hashes:
sha256sum /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/build/v5_2-stub/QKBPresentationV5_js/QKBPresentationV5.wasm
sha256sum /data/Develop/qkb-wt-v5/arch-circuits/packages/circuits/ceremony/v5_2/verification_key.json
# Splice the actual hashes into /tmp/dev-manifest.json before workers consume it.
```

- [ ] **§4.6 — Generate dev signing keypair (Ed25519)**
For local dev, lead creates a stub Ed25519 keypair so the manifest signature path can be exercised without the production key.
```bash
mkdir -p /tmp/qkb-helper-dev-keys
openssl genpkey -algorithm Ed25519 -out /tmp/qkb-helper-dev-keys/manifest.priv.pem
openssl pkey -in /tmp/qkb-helper-dev-keys/manifest.priv.pem -pubout -out /tmp/qkb-helper-dev-keys/manifest.pub.pem
# Sign the dev manifest:
openssl pkeyutl -sign -inkey /tmp/qkb-helper-dev-keys/manifest.priv.pem \
  -rawin -in /tmp/dev-manifest.json \
  -out /tmp/dev-manifest.json.sig
```
Hand the dev pubkey path (`/tmp/qkb-helper-dev-keys/manifest.pub.pem`) to circuits-eng for embedding into dev builds.

- [ ] **§4.7 — Dispatch workers**

```bash
# Single message with three Agent calls in parallel.
# circuits-eng dispatch:
Agent({
  name: "circuits-eng",
  subagent_type: "general-purpose",
  prompt: "...read docs/superpowers/plans/2026-05-03-qkb-helper-circuits-eng.md, work through tasks 1-N in order, commit after each."
})
# web-eng dispatch:
Agent({
  name: "web-eng",
  subagent_type: "general-purpose",
  prompt: "...read docs/superpowers/plans/2026-05-03-qkb-helper-web-eng.md, work through tasks 1-N in order. circuits-eng will deliver an unsigned dev helper binary by end of day 3 you can dev against."
})
```

## §5 — Cross-worker dependencies

| Dep | Provider | Consumer | When |
|---|---|---|---|
| Unsigned dev helper binary (Linux x86_64) | circuits-eng | web-eng | End of day 3 |
| Apple Developer ID + Authenticode certs | lead | circuits-eng | End of day 5 (must beat day-11 installer phase) |
| Brew tap + winget config | lead | circuits-eng | End of day 12 (after signed installers ready) |
| Production manifest URL + signing pubkey embedding | lead | circuits-eng | End of day 5 (compile-time embed) |
| `proveViaHelper` shape contract | (frozen in §1.6 above) | web-eng | day 1 |
| HTTP API contract | (frozen in §1.1 above) | both | day 1 |

## §6 — Pump table

Cross-package outputs that lead manually moves between worktrees:

| Artifact | From | To | When |
|---|---|---|---|
| Unsigned dev helper binary | `qkb-helper-circuits/packages/qkb-helper/dist/qkb-helper-linux` | `qkb-helper-web/packages/web/test/fixtures/qkb-helper-dev-linux` | end of day 3 (web-eng's E2E test fixture) |
| Helper installer artifacts (signed) | `qkb-helper-circuits/packages/qkb-helper/dist/installers/` | R2 + `zkqes.org/download/` (lead-managed) | end of day 11 |
| Updated `helper-manifest.json.sig` | `lead's signing-key store` | R2 root | end of day 11 |

## §7 — Merge strategy

Lead does all merges from main checkout (`/data/Develop/qkb-wt-v5/arch-circuits/`).

```
feat/qkb-helper-circuits ──┐
                           ├──▶ feat/v5_2arch-circuits (existing)
feat/qkb-helper-web ───────┤
                           │
feat/qkb-helper-lead ──────┘
```

Each branch merges via `git merge --no-ff` with a summary commit. After all three merge:
```bash
git tag -a v5.2.0-helper-rc1 -m "zkqes Helper V1 release candidate"
```

Final ship after E2E green across all 3 OSes:
```bash
git tag -a v5.2.0-helper -m "zkqes Helper V1 production"
```

## §8 — CI / verification per worker

After each worker commit, lead runs:

| Worker | Commands |
|---|---|
| circuits-eng | `pnpm -F @zkqes/helper test && pnpm -F @zkqes/helper typecheck && pnpm -F @zkqes/helper build` |
| circuits-eng (Phase 3) | Per-OS smoke test on a clean VM (manual; no automated cross-OS CI in V1) |
| web-eng | `pnpm -F @zkqes/web test && pnpm -F @zkqes/web typecheck && pnpm -F @zkqes/web build && pnpm -F @zkqes/web exec playwright test --grep helper-flow` |
| lead | manifest signature roundtrip + brew formula syntax check |

## §9 — Risks & escalation triggers

| Risk | Trigger | Action |
|---|---|---|
| Apple cert procurement slip | lead day-3 standup says "still in Apple review" | re-sequence: ship Linux + Windows V1.0.0 first, macOS V1.0.1 follow-up |
| circuits-eng helper hits a Node-bundling-via-pkg gotcha | Day 7 demo missing | switch to `nexe` or `caxa`; budget +2 days |
| web-eng /download landing page blocked on branding (task #21) | Day 8 demo uses placeholder copy | ship with placeholder; lead fast-tracks branding |
| Chrome PNA enforcement changes mid-flight | helper rejected by browser | hard-stop: revert to "always-on daemon" Pattern B (V1.1) |

## §10 — Worker plan paths

- circuits-eng: `docs/superpowers/plans/2026-05-03-qkb-helper-circuits-eng.md`
- web-eng: `docs/superpowers/plans/2026-05-03-qkb-helper-web-eng.md`
- lead: `docs/superpowers/plans/2026-05-03-qkb-helper-lead.md`
