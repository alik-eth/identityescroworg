# QKB CLI-Server Orchestration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Coordinate three-track delivery of QKB CLI-Server V1 — a `qkb serve` command that turns the V5.2 register flow's prove step from 90s / 38 GiB (in-browser snarkjs) into 13.86s / 3.70 GiB (native rapidsnark via terminal-launched localhost server), while keeping browser canonical for everything else.

**Architecture:** Three independently-mergeable tracks — circuits-eng owns the `@qkb/cli` package, web-eng owns browser detection + `/ua/cli` page upgrade, lead owns npm publish + brew tap + GitHub releases binaries. All three converge on a single `feat/qkb-cli-server` integration branch for E2E.

**Tech Stack:** Node 20 LTS bundled via `pkg`, iden3 rapidsnark v0.0.8 (prebuilt sidecars for 4 platforms), TypeScript, React (existing web app), npm + Homebrew tap + GitHub releases.

**Supersedes:** the deep-link helper design at `docs/superpowers/specs/2026-05-03-qkb-helper-design.md` + `docs/superpowers/plans/2026-05-03-qkb-helper-orchestration.md`. Helper architecture's load-bearing pieces (HTTP API, manifest, cache paths) are inherited verbatim; consumer-app trappings (deep-link URL scheme, per-OS installers, code-signing certs, /download landing) are dropped.

---

## §1 — Interface contracts (FROZEN)

These contracts are load-bearing across all three workers. Changes require explicit lead sign-off and a cross-worker broadcast.

### §1.1 — HTTP API (CLI server ↔ browser)

**Identical to helper §1.1 — see `docs/superpowers/plans/2026-05-03-qkb-helper-orchestration.md` §1.1 for full contract.**

Summary:
- `GET http://127.0.0.1:9080/status` — returns `{ok, version, circuit, zkeyLoaded, busy, provesCompleted, uptimeSec, downloadProgress}`
- `POST http://127.0.0.1:9080/prove` — body is witness JSON (22 public + 10518 private signals), returns `{proof, publicSignals, verifyOk, timings}`. Origin pin: `https://identityescrow.org` (403 otherwise).
- `OPTIONS http://127.0.0.1:9080/prove` — Chrome PNA preflight.

Validated prototype lives at `packages/circuits/scripts/v5_2-prove-server.mjs` (250 LOC, 12.94s end-to-end measured). The CLI package lifts this directly with minimal changes.

### §1.2 — CLI command surface

```
qkb serve [--port 9080] [--circuit v5.2] [--manifest-url <url>] [--no-verify]
  Starts the localhost HTTP server. Blocks until SIGINT/SIGTERM.

qkb status
  Prints whether a server is running on :9080 (calls /status).

qkb cache
  Prints cache directory + currently cached circuit artifacts.

qkb cache clear [--circuit v5.2]
  Removes cached artifacts for one or all circuits.

qkb version
  Prints qkb-cli version + bundled rapidsnark version.
```

V1 supports only `v5.2`. The `--circuit` flag and manifest-keyed circuits dict in §1.3 are forward-compatibility hooks for V5.3+.

### §1.3 — Auto-update manifest

URL: `https://identityescrow.org/qkb-cli-manifest.json` (CloudFront/CDN-cached, 5 min TTL).

```json
{
  "version": "1.0.0",
  "released": "2026-05-15T12:00:00Z",
  "changelog": "Initial V5.2 release",
  "minSupportedVersion": "1.0.0",
  "circuits": {
    "v5.2": {
      "zkeyUrl":      "https://r2.identityescrow.org/qkb-v5_2-stub.zkey",
      "zkeySha256":   "b66bad1d27f2e0b00f2db7437a0fab365433165dccb2f11d09ee3eb475debce2",
      "wasmUrl":      "https://r2.identityescrow.org/qkb-v5_2.wasm",
      "wasmSha256":   "<from circuits-eng's vendor build>",
      "vkeyUrl":      "https://r2.identityescrow.org/qkb-v5_2-vkey.json",
      "vkeySha256":   "<from circuits-eng's vendor build>"
    }
  }
}
```

Manifest signed via detached `qkb-cli-manifest.json.sig` (Ed25519). Lead's signing-key pubkey embedded in CLI binary at compile time.

**V1 simplification:** unsigned manifest acceptable if `--no-verify` flag passed. Signed verification path implemented but bypass available for dev. Production CLI builds reject unsigned manifests by default.

### §1.4 — Cache paths

CLI writes to a per-user data directory (XDG-conformant on Linux):

| OS | Cache root |
|---|---|
| macOS | `~/Library/Application Support/qkb-cli/` |
| Windows | `%APPDATA%\qkb-cli\` |
| Linux | `~/.local/share/qkb-cli/` (respects `$XDG_DATA_HOME` if set) |

Subdirectories under cache root:
- `circuits/qkb-v5_2.zkey` — cached zkey (~2.0 GB)
- `circuits/qkb-v5_2.zkey.tmp` — partial download (atomic mv on completion)
- `circuits/qkb-v5_2.wasm` — witness calculator wasm
- `circuits/qkb-v5_2-vkey.json` — verification key
- `manifest/qkb-cli-manifest.json` — last fetched manifest
- (no logs in V1 — server logs to stderr only)

### §1.5 — Distribution surface

| Channel | Artifact | Notes |
|---|---|---|
| npm | `@qkb/cli` (scoped package) | `npm install -g @qkb/cli` ships postinstall script that downloads the matching rapidsnark sidecar. Node 20+ required. |
| Homebrew | `identityescrow/qkb/qkb` (custom tap) | `brew install identityescrow/qkb/qkb` installs prebuilt binary + bundled sidecar |
| GitHub releases | `qkb-darwin-arm64`, `qkb-darwin-x86_64`, `qkb-linux-x86_64`, `qkb-linux-arm64`, `qkb-windows-x86_64.exe` | Single-file binaries via `pkg`. Sha256 sidecar `.sha256` published alongside each. |
| curl install | `https://identityescrow.org/install.sh` | Detects platform, downloads matching binary, writes to `~/.local/bin/qkb` (Linux/macOS only). |

**Code-signing for V1: optional, deferred.** Unsigned binaries ship with Gatekeeper / SmartScreen warnings. Tradeoff: warning UX vs cert procurement timeline. V1.1 adds signing if user-feedback warrants.

### §1.6 — Web frontend props

Web-eng's `proveViaCli` function shape (consumed by existing prove call site in `Step4ProveAndRegister`):

```ts
interface CliProveResult {
  proof: Groth16Proof;
  publicSignals: string[];
  verifyOk: boolean;          // from CLI; NOT trusted alone
  timings: CliTimings;
  source: 'cli' | 'browser';  // 'browser' if CLI unreachable + fallback fired
}

async function proveViaCli(witness: WitnessV5): Promise<CliProveResult>;
```

Failure modes (web-eng must handle all):
- CLI not detected at mount → show "Install `qkb` for faster proof generation (optional)" banner with link to /ua/cli; fall through to browser prove silently when user clicks Generate Proof.
- CLI detected at mount but unreachable at prove time → fall back silently to browser prove with a "CLI server stopped; using browser prover" toast.
- CLI returns 4xx (witness invalid) → surface error verbatim; do NOT fall back (browser would fail too).
- CLI returns 5xx (rapidsnark crash, OOM) → fall back to browser prove with a toast.

**No deep-link auto-launch.** User starts `qkb serve` in their terminal manually before initiating prove. Browser detects via `fetch('http://127.0.0.1:9080/status')` at /v5/registerV5 mount.

---

## §2 — Dispatch order

```
DAY 1                       DAY 2-3                      DAY 4-5                      DAY 6-7
─────                       ────────                     ─────────                    ──────────
[c-eng]   Phase 1 begins    [c-eng]  Phase 1 ships      [c-eng]  fixes from web-eng  [c-eng]  ship signed-manifest
          @qkb/cli scaffold          unsigned binary             dev-fixture issues          path; release prep

                            [w-eng]  Phase 2 begins     [w-eng]  Phase 2 ships
                                     against c-eng's            browser detection +
                                     dev binary                  /ua/cli page upgrade

[lead]    npm scope claim   [lead]   brew tap setup     [lead]   GitHub releases     [lead]   v5.2.0-cli-rc1 cut
          (@qkb/cli)                  (identityescrow/qkb)        binaries upload             then E2E test pass
                                                                  + R2 manifest publish
```

Critical-path discipline:
- **circuits-eng Phase 1 is independent** (HTTP server already validated; just packaging). Can ship by end of day 3.
- **web-eng can dev against an unsigned local binary** delivered by circuits-eng end of day 2. Doesn't wait for distribution.
- **lead distribution work** is parallel — npm publish + brew tap can start day 1 (claim namespace, write formula skeleton) and finalize day 5 once binaries are ready.

## §3 — Branches and worktrees

| Worker | Branch | Worktree |
|---|---|---|
| circuits-eng | `feat/qkb-cli-server-circuits` | `/data/Develop/qkb-wt-v5/qkb-cli-circuits/` |
| web-eng | `feat/qkb-cli-server-web` | `/data/Develop/qkb-wt-v5/qkb-cli-web/` |
| lead | `feat/qkb-cli-server-lead` (distribution + manifest infra) | `/data/Develop/qkb-wt-v5/arch-circuits/` (lead's main checkout) |

All three branch from `main` post-V5.2-merge. **Dispatch gated on V5.2 merge.**

Lead does all merges. Order:
1. `feat/qkb-cli-server-circuits` first (provides the binary web-eng depends on)
2. `feat/qkb-cli-server-web` second
3. `feat/qkb-cli-server-lead` rolls in distribution configs + manifest publish docs
4. Tag `v5.2.0-cli-rc1` after E2E green on all 3 OS

## §4 — Lead-side scaffold (pre-dispatch)

Before dispatching workers, lead runs:

- [ ] **§4.1 — Verify V5.2 merge complete** — `feat/qkb-cli-server-*` branches branch from main; main must contain V5.2.
- [ ] **§4.2 — Create circuits-eng worktree** — `git worktree add /data/Develop/qkb-wt-v5/qkb-cli-circuits -b feat/qkb-cli-server-circuits main`
- [ ] **§4.3 — Create web-eng worktree** — `git worktree add /data/Develop/qkb-wt-v5/qkb-cli-web -b feat/qkb-cli-server-web main`
- [ ] **§4.4 — Verify rapidsnark sidecar binary present** — `ls /home/alikvovk/.cache/qkb-bin/rapidsnark-linux-x86_64-v0.0.8/bin/prover`
- [ ] **§4.5 — Stage dev manifest** — drop `/tmp/dev-manifest.json` with the V5.2 stub artifacts at `file://...` URLs (see helper orchestration §4.5 for template)
- [ ] **§4.6 — Generate dev signing keypair** — Ed25519 stub (see helper orchestration §4.6 for commands). Hand pubkey path to circuits-eng for embedding.
- [ ] **§4.7 — Claim npm namespace** — `npm access ls-packages` to confirm `@qkb` scope ownership; reserve `@qkb/cli` if not taken.
- [ ] **§4.8 — Set up GitHub releases automation** — workflow at `.github/workflows/qkb-cli-release.yml` that builds binaries on tag push; can scaffold pre-dispatch.
- [ ] **§4.9 — Dispatch workers** — single message with two parallel SendMessage to circuits-eng + web-eng pointing at their plan paths.

## §5 — Cross-worker dependencies

| Dep | Provider | Consumer | When |
|---|---|---|---|
| Unsigned dev CLI binary (Linux x86_64) | circuits-eng | web-eng | End of day 2 |
| `proveViaCli` shape contract | (frozen in §1.6 above) | web-eng | day 1 |
| HTTP API contract | (frozen in §1.1 above) | both | day 1 |
| npm `@qkb/cli` namespace claim | lead | circuits-eng | End of day 1 |
| Production manifest URL + signing pubkey embedding | lead | circuits-eng | End of day 4 (compile-time embed) |
| GitHub releases pipeline | lead | circuits-eng | End of day 5 |

## §6 — Pump table

Cross-package outputs that lead manually moves between worktrees:

| Artifact | From | To | When |
|---|---|---|---|
| Unsigned dev CLI binary | `qkb-cli-circuits/packages/qkb-cli/dist/qkb-linux-x86_64` | `qkb-cli-web/packages/web/test/fixtures/qkb-cli-dev-linux` | end of day 2 (web-eng's E2E test fixture) |
| Built CLI binaries (5 platforms) | circuits-eng's GitHub Actions artifacts | GitHub releases page (lead-managed) | end of day 5 |
| Updated `qkb-cli-manifest.json.sig` | lead's signing-key store | R2 root | end of day 5 |

## §7 — Merge strategy

Lead does all merges from main checkout.

```
feat/qkb-cli-server-circuits ──┐
                                ├──▶ main
feat/qkb-cli-server-web ────────┤
                                │
feat/qkb-cli-server-lead ───────┘
```

Each branch merges via `git merge --no-ff` with a summary commit. After all three merge:
```bash
git tag -a v5.2.0-cli-rc1 -m "QKB CLI V1 release candidate"
```

Final ship after E2E green across 3 OSes:
```bash
git tag -a v5.2.0-cli -m "QKB CLI V1 production"
npm publish --access public  # @qkb/cli
brew bump-formula-pr ...      # identityescrow/qkb tap
gh release create ...         # GitHub releases with all 5 platform binaries
```

## §8 — CI / verification per worker

After each worker commit, lead runs:

| Worker | Commands |
|---|---|
| circuits-eng | `pnpm -F @qkb/cli test && pnpm -F @qkb/cli typecheck && pnpm -F @qkb/cli build` |
| circuits-eng (Phase 1 ship) | `node packages/qkb-cli/dist/qkb-linux-x86_64 serve --manifest-url file:///tmp/dev-manifest.json` then `curl -sf http://127.0.0.1:9080/status` |
| web-eng | `pnpm -F @qkb/web test && pnpm -F @qkb/web typecheck && pnpm -F @qkb/web build && pnpm -F @qkb/web exec playwright test --grep cli-flow` |
| lead | manifest signature roundtrip + brew formula syntax check (`brew audit`) |

## §9 — Risks & escalation triggers

Significantly slimmer than helper risk register because cert/notarization risks are dropped.

| Risk | Trigger | Action |
|---|---|---|
| circuits-eng `pkg` Node-bundling gotcha | Day 3 binary missing or broken | switch to `nexe` or `caxa`; budget +1 day |
| web-eng /ua/cli page blocked on branding (task #21) | Day 5 demo uses placeholder copy | ship with placeholder; lead fast-tracks branding |
| Chrome PNA enforcement changes mid-flight | CLI rejected by browser | hard-stop: validate against current Chrome stable before each release |
| npm `@qkb` scope unavailable | Day 1 namespace claim fails | fall back to `@identityescrow/qkb-cli` or unscoped `qkb-cli` |
| User-installed Node version conflict | Day 6 GitHub releases binary OOM on Node <20 | pkg-bundle Node 20 LTS into binary (eliminates user Node dep) |

## §10 — Worker plan paths

- circuits-eng: `docs/superpowers/plans/2026-05-03-qkb-cli-server-circuits-eng.md`
- web-eng: `docs/superpowers/plans/2026-05-03-qkb-cli-server-web-eng.md`
- lead: this document covers lead's Phase 3 (distribution) work; no separate plan
