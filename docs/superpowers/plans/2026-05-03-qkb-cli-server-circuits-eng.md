# zkqes CLI-Server — circuits-eng Implementation Plan

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `@zkqes/cli` package — a single-file binary that runs `qkb serve` to host a localhost HTTP server bridging the browser's prove call to the native rapidsnark binary at 13.86s / 3.70 GiB.

**Architecture:** Lift the validated prototype at `packages/circuits/scripts/v5_2-prove-server.mjs` into a proper TypeScript package with subcommands, manifest verification, zkey caching, and cross-platform builds. Three subcommands ship in V1: `serve`, `status`, `cache`. Distribution covered by lead (npm + brew + GitHub releases).

**Tech Stack:** Node 20 LTS, TypeScript 5.x, `commander` for CLI parsing, `pkg` for single-file bundling, `node:crypto` for Ed25519 signature verification, `fetch` for manifest/zkey download, native `prover` binary from iden3 rapidsnark v0.0.8.

**Branch:** `feat/qkb-cli-server-circuits`. **Worktree:** `/data/Develop/qkb-wt-v5/qkb-cli-circuits/`.

**Cross-worker contracts (FROZEN — see orchestration §1):** HTTP API §1.1, CLI command surface §1.2, manifest §1.3, cache paths §1.4.

---

## File structure

```
packages/qkb-cli/
├── package.json
├── tsconfig.json
├── README.md
├── src/
│   ├── index.ts                  # CLI entrypoint, commander wiring
│   ├── commands/
│   │   ├── serve.ts              # qkb serve - HTTP server (lifted from prototype)
│   │   ├── status.ts             # qkb status - calls /status on running server
│   │   ├── cache.ts              # qkb cache / qkb cache clear
│   │   └── version.ts            # qkb version
│   ├── manifest/
│   │   ├── fetch.ts              # fetch + Ed25519 verify
│   │   ├── signing-key.ts        # embedded production pubkey (compile-time)
│   │   └── types.ts              # ManifestV1 schema + zod validation
│   ├── circuit/
│   │   ├── download.ts           # zkey/wasm/vkey fetch + sha256 verify + cache
│   │   ├── cache-paths.ts        # XDG/macOS/Windows resolution
│   │   └── prove.ts              # invoke rapidsnark binary with witness
│   ├── server/
│   │   ├── http.ts               # express routes (/status, /prove, OPTIONS)
│   │   ├── origin-pin.ts         # origin allowlist + Chrome PNA preflight
│   │   └── busy-flag.ts          # mutex on /prove (return 429 if busy)
│   └── rapidsnark/
│       ├── sidecar-path.ts       # resolves bundled rapidsnark binary
│       └── postinstall.ts        # downloads matching sidecar on npm install
├── test/
│   ├── unit/
│   │   ├── manifest-verify.test.ts
│   │   ├── zkey-download.test.ts
│   │   ├── origin-pin.test.ts
│   │   └── cache-paths.test.ts
│   └── integration/
│       ├── serve-prove-roundtrip.test.ts
│       └── busy-mutex.test.ts
└── dist/                          # gitignored
    ├── qkb-darwin-arm64
    ├── qkb-darwin-x86_64
    ├── qkb-linux-x86_64
    ├── qkb-linux-arm64
    └── qkb-windows-x86_64.exe
```

---

## Tasks

### Task 1: Scaffold `@zkqes/cli` package

**Files:**
- Create: `packages/qkb-cli/package.json`
- Create: `packages/qkb-cli/tsconfig.json`
- Create: `packages/qkb-cli/src/index.ts`
- Create: `packages/qkb-cli/src/commands/version.ts`
- Modify: `pnpm-workspace.yaml` (already includes `packages/*` glob — verify)

- [ ] **Step 1: Write the failing test**

```ts
// test/unit/version.test.ts
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

describe('qkb version', () => {
  it('prints qkb-cli version + bundled rapidsnark version', () => {
    const cli = resolve(__dirname, '../../dist/qkb-linux-x86_64');
    const result = spawnSync(cli, ['version']);
    expect(result.stdout.toString()).toMatch(/qkb-cli@\d+\.\d+\.\d+/);
    expect(result.stdout.toString()).toMatch(/rapidsnark v0\.0\.8/);
  });
});
```

- [ ] **Step 2: Run test, verify it fails** (`pnpm -F @zkqes/cli test` — fails because dist binary doesn't exist).

- [ ] **Step 3: Write package.json + tsconfig.json + index.ts skeleton**

```json
// packages/qkb-cli/package.json
{
  "name": "@zkqes/cli",
  "version": "0.5.2-pre",
  "type": "module",
  "bin": { "qkb": "./dist/qkb.cjs" },
  "scripts": {
    "build": "tsc && pkg . --targets node20-linux-x64,node20-macos-arm64,node20-macos-x64,node20-linux-arm64,node20-win-x64 --output dist/qkb",
    "test": "vitest run",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "commander": "^12.0.0",
    "zod": "^3.22.0"
  },
  "devDependencies": {
    "pkg": "^5.8.1",
    "vitest": "^1.0.0",
    "@types/node": "^20.11.0",
    "typescript": "^5.4.0"
  }
}
```

```ts
// src/index.ts
#!/usr/bin/env node
import { Command } from 'commander';
import { versionCommand } from './commands/version.js';

const program = new Command();
program.name('qkb').description('zkqes CLI server for native rapidsnark proving');
versionCommand(program);
program.parseAsync();
```

```ts
// src/commands/version.ts
import { Command } from 'commander';
const PKG_VERSION = '0.5.2-pre';
const RAPIDSNARK_VERSION = 'v0.0.8';
export function versionCommand(program: Command): void {
  program.command('version').action(() => {
    console.log(`qkb-cli@${PKG_VERSION}`);
    console.log(`rapidsnark ${RAPIDSNARK_VERSION}`);
  });
}
```

- [ ] **Step 4: Build and run** (`pnpm -F @zkqes/cli build`, manually run `./dist/qkb-linux-x86_64 version`).

- [ ] **Step 5: Verify test passes** (`pnpm -F @zkqes/cli test`).

- [ ] **Step 6: Commit**

```bash
git add packages/qkb-cli pnpm-workspace.yaml
git commit -m "cli(v52): T1 — scaffold @zkqes/cli package with qkb version"
```

### Task 2: Lift prototype HTTP server into `qkb serve`

**Files:**
- Reference: `packages/circuits/scripts/v5_2-prove-server.mjs` (validated prototype, 250 LOC)
- Create: `packages/qkb-cli/src/server/http.ts`
- Create: `packages/qkb-cli/src/server/origin-pin.ts`
- Create: `packages/qkb-cli/src/server/busy-flag.ts`
- Create: `packages/qkb-cli/src/circuit/prove.ts`
- Create: `packages/qkb-cli/src/commands/serve.ts`
- Create: `packages/qkb-cli/test/integration/serve-prove-roundtrip.test.ts`

- [ ] **Step 1: Write the failing test** — boots `qkb serve` against a fixture witness, posts to `/prove`, expects valid Groth16 proof + verifyOk:true.

```ts
// test/integration/serve-prove-roundtrip.test.ts
// Test that boots qkb serve on :9080 with the V5.2 stub fixture,
// POSTs witness-input-sample.json to /prove, asserts:
//   - response status 200
//   - response.publicSignals.length === 22
//   - response.verifyOk === true
//   - response.timings.totalSec is < 30 (CI machine; 13.86s on workstation)
```

- [ ] **Step 2: Run test, verify it fails** (no serve command yet).

- [ ] **Step 3: Lift prototype** — copy server logic from `packages/circuits/scripts/v5_2-prove-server.mjs` into `src/server/http.ts`. Keep route handlers identical; just wrap in a class `CliServer` with start/stop methods. Preserve origin pin, Chrome PNA preflight, busy-flag mutex.

- [ ] **Step 4: Wire `qkb serve` command** — `src/commands/serve.ts` parses `--port`, `--circuit`, `--manifest-url`, `--no-verify` flags; instantiates `CliServer`; awaits SIGINT/SIGTERM.

- [ ] **Step 5: Run test, verify it passes**.

- [ ] **Step 6: Commit** — `cli(v52): T2 — qkb serve subcommand lifts validated prototype server`.

### Task 3: Manifest fetch + Ed25519 signature verification

**Files:**
- Create: `packages/qkb-cli/src/manifest/fetch.ts`
- Create: `packages/qkb-cli/src/manifest/types.ts`
- Create: `packages/qkb-cli/src/manifest/signing-key.ts`
- Create: `packages/qkb-cli/test/unit/manifest-verify.test.ts`

- [ ] **Step 1: Write the failing test** — fetches manifest URL, verifies detached signature against embedded pubkey, returns parsed `ManifestV1`. Negative cases: malformed JSON, sig-pubkey mismatch, missing circuits.v5.2 entry.

- [ ] **Step 2: Run test, verify it fails**.

- [ ] **Step 3: Implement fetch + verify** — uses `node:crypto.verify('ed25519', ...)`. Embedded pubkey at `signing-key.ts` is hard-coded at compile time; `--no-verify` bypass logs a warning.

- [ ] **Step 4: Run test, verify it passes**.

- [ ] **Step 5: Commit** — `cli(v52): T3 — manifest Ed25519 signature verification`.

### Task 4: Zkey download + cache + sha256 verify

**Files:**
- Create: `packages/qkb-cli/src/circuit/download.ts`
- Create: `packages/qkb-cli/src/circuit/cache-paths.ts`
- Create: `packages/qkb-cli/test/unit/zkey-download.test.ts`
- Create: `packages/qkb-cli/test/unit/cache-paths.test.ts`

- [ ] **Step 1: Write the failing tests** — (a) `cache-paths` resolves XDG/macOS/Windows correctly per platform; (b) `zkey-download` streams, computes sha256 incrementally, atomic-renames `.tmp → .zkey` on success, rejects mismatched hash.

- [ ] **Step 2: Run tests, verify they fail**.

- [ ] **Step 3: Implement** — uses `node:fs/promises` for streaming, `node:crypto.createHash('sha256')` incremental, `process.platform` + `os.homedir()` + `$XDG_DATA_HOME` for paths.

- [ ] **Step 4: Run tests, verify they pass**.

- [ ] **Step 5: Commit** — `cli(v52): T4 — zkey download + cache + sha256 verify`.

### Task 5: `qkb status`, `qkb cache`, `qkb cache clear`

**Files:**
- Create: `packages/qkb-cli/src/commands/status.ts`
- Create: `packages/qkb-cli/src/commands/cache.ts`
- Test: `packages/qkb-cli/test/unit/cache-commands.test.ts`

- [ ] **Step 1: Write the failing test** — `qkb status` prints "no server running" if :9080 unreachable; prints uptimeSec + zkeyLoaded if reachable. `qkb cache` lists circuit files + sizes. `qkb cache clear --circuit v5.2` removes the directory.

- [ ] **Step 2: Run, verify fail**.

- [ ] **Step 3: Implement** — `status` uses fetch with 500ms timeout; `cache` walks `cache-paths.ts` resolved root.

- [ ] **Step 4: Run, verify pass**.

- [ ] **Step 5: Commit** — `cli(v52): T5 — qkb status + qkb cache subcommands`.

### Task 6: Rapidsnark sidecar resolution + postinstall

**Files:**
- Create: `packages/qkb-cli/src/rapidsnark/sidecar-path.ts`
- Create: `packages/qkb-cli/src/rapidsnark/postinstall.ts`
- Modify: `packages/qkb-cli/package.json` — add `"postinstall": "node ./dist/postinstall.cjs"` script
- Test: `packages/qkb-cli/test/unit/sidecar-path.test.ts`

- [ ] **Step 1: Write the failing test** — `sidecar-path.ts` resolves to bundled binary path inside the pkg-snapshot filesystem AND falls back to `~/.cache/qkb-bin/rapidsnark-{platform}-v0.0.8/bin/prover` if running un-pkg'd (dev mode).

- [ ] **Step 2: Run, verify fail**.

- [ ] **Step 3: Implement** — checks `process.pkg ? bundled : devPath`. Postinstall downloads matching sidecar from GitHub release URL based on `process.platform + process.arch` and verifies sha256 against an embedded manifest table.

- [ ] **Step 4: Wire `prove.ts` to invoke sidecar** — spawns `prover` binary with witness/zkey/proof paths, parses stdout/stderr.

- [ ] **Step 5: Run, verify pass** — integration test from T2 should now use the real rapidsnark binary path.

- [ ] **Step 6: Commit** — `cli(v52): T6 — rapidsnark sidecar resolution + postinstall download`.

### Task 7: pkg single-file binary build (Linux x86_64 first)

**Files:**
- Verify: `packages/qkb-cli/package.json` `pkg` field has correct `targets` + `assets` (rapidsnark sidecar embedded)
- Create: `packages/qkb-cli/.pkgignore` (exclude test files)

- [ ] **Step 1: Run `pnpm -F @zkqes/cli build`** — should produce `dist/qkb-linux-x86_64` (~50 MB).

- [ ] **Step 2: Smoke-test** — `./dist/qkb-linux-x86_64 version` prints expected; `./dist/qkb-linux-x86_64 serve --manifest-url file:///tmp/dev-manifest.json` boots the server.

- [ ] **Step 3: Pump unsigned dev binary to web-eng** — copy to `qkb-cli-web/packages/web/test/fixtures/qkb-cli-dev-linux` for their E2E test fixture.

- [ ] **Step 4: Commit** — `cli(v52): T7 — pkg single-file Linux binary + dev fixture`.

### Task 8: Cross-platform builds (darwin x64+arm64, linux arm64, windows x64)

- [ ] **Step 1: Verify pkg targets in package.json** include all 5 platforms.
- [ ] **Step 2: Run `pnpm -F @zkqes/cli build`** — produces 5 binaries in `dist/`.
- [ ] **Step 3: Document per-platform sidecar requirement** — postinstall handles user-side; pkg build embeds same-platform sidecar in dev binary.
- [ ] **Step 4: Commit** — `cli(v52): T8 — cross-platform pkg builds (5 targets)`.

### Task 9: Failure-mode integration tests

**Files:**
- Create: `packages/qkb-cli/test/integration/failure-modes.test.ts`

- [ ] **Step 1: Write tests** for:
  - Manifest URL unreachable → CLI exits with clear message
  - Manifest signature mismatch → CLI exits with clear message (or warns + continues if `--no-verify`)
  - zkey sha256 mismatch → CLI deletes partial download + exits with clear message
  - Rapidsnark binary missing → CLI exits with clear message + suggests `qkb cache` to retrigger postinstall
  - Witness invalid (e.g. wrong publicSignals length) → /prove returns 4xx with structured error
  - Two simultaneous /prove requests → second returns 429

- [ ] **Step 2: Run tests, verify all pass**.

- [ ] **Step 3: Commit** — `cli(v52): T9 — failure-mode integration tests`.

### Task 10: README + CLAUDE.md V5.23+ invariants

**Files:**
- Create: `packages/qkb-cli/README.md` — install/usage instructions for end users
- Modify: `packages/qkb-cli/CLAUDE.md` (NEW) — invariants for future agents working on this package

- [ ] **Step 1: Write README** — covers install (npm/brew/binary), `qkb serve` usage, troubleshooting (port conflict, sidecar missing, manifest fetch fail), security narrative (origin-pinned, runs only when invoked).

- [ ] **Step 2: Write CLAUDE.md invariants:**
  - V5.23: `qkb serve` is ON-DEMAND, not a daemon. SIGINT exits cleanly. No PID file, no systemd unit, no LaunchAgent.
  - V5.24: Origin pin is `https://zkqes.org` exclusively. Localhost-served browser apps cannot consume the API.
  - V5.25: Manifest signature verification is REQUIRED for production builds. `--no-verify` bypass logs a stderr warning every prove.
  - V5.26: Cache is per-user, never per-system. No shared state across users.
  - V5.27: Rapidsnark sidecar is bundled into pkg binary; fallback to `~/.cache/qkb-bin/...` in dev only.

- [ ] **Step 3: Commit** — `cli(v52): T10 — README + CLAUDE.md V5.23-V5.27 invariants`.

---

## Acceptance gates

Before declaring Phase 1 complete:

- [ ] `pnpm -F @zkqes/cli test` — all green (unit + integration)
- [ ] `pnpm -F @zkqes/cli typecheck` — clean
- [ ] `pnpm -F @zkqes/cli build` — produces 5 binaries in `dist/`, each ~45-55 MB
- [ ] Linux x86_64 binary smoke test: `qkb version`, `qkb serve --manifest-url file:///tmp/dev-manifest.json`, then `curl -sf http://127.0.0.1:9080/status` returns ok
- [ ] End-to-end: web-eng's local dev (Phase 2 in flight) successfully proves against the dev binary
- [ ] Codex review on each commit; VERDICT PASS or annotated P2/P3 only

After Phase 1 ships, lead pumps the binary to web-eng's worktree and notifies for Phase 2 dev.
