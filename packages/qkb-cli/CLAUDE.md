# `@qkb/cli` package — invariants for future agents

This package hosts `qkb serve` — the localhost-bound native rapidsnark
prover that the V5.2 register flow at
`app.zkqes.org/v5/registerV5` offloads its prove step to.

**The package's purpose is single**: turn a witness JSON into a
Groth16 proof in ~13 s using native rapidsnark, behind an
origin-pinned HTTP API. Browser stays canonical for everything else
(wallet, witness gen, on-chain submission).

## V5.23 — `qkb serve` is on-demand, NEVER a daemon

V5.4 V1's defining invariant per founder direction (2026-05-03):

- `qkb serve` runs in the foreground, blocks until SIGINT/SIGTERM.
- No PID file. No LaunchAgent (macOS). No systemd user unit (Linux).
  No Windows Service.
- The installer (`postinstall.ts`) only downloads the rapidsnark
  sidecar; it does NOT register an auto-start hook.
- `Ctrl-C` exits cleanly via the SIGINT/SIGTERM handlers in
  `src/commands/serve.ts`. Workers spawn no orphaned children
  beyond the rapidsnark sidecar (which exits when its parent does).

If a future agent proposes "let's ship a service definition for
auto-start at login" — push back. The trust narrative ("runs only
when you invoke it, exits 14 s later") is the product, not a nice-
to-have. See also: helper-vs-app design history at
`docs/superpowers/specs/2026-05-03-qkb-helper-design.md` (superseded
by the CLI-server design).

## V5.24 — Origin pin is `https://app.zkqes.org` exclusively

`POST /prove` requires the request's `Origin` header to match the
configured `--allowed-origin`. Default: production
(`https://app.zkqes.org`); production CLI builds will eventually
hard-code this with no flag. Dev builds expose `--allowed-origin
<url>` for local development against `http://localhost:5173` or
similar staging origins.

`/status` is exempt from the origin pin — it must be probable from
any origin so the browser-side detection works regardless of which
host the SPA is served from.

Empty `Origin` (e.g., `curl` without `-H Origin`) is also exempt.
The threat model is "browser tab on a different origin" and browsers
always set `Origin` on cross-origin fetches; an empty header can't
be a hostile browser request.

If a future agent proposes broadening the allowlist to multiple
origins or removing the exact-match check — push back. Wildcard or
multi-origin support widens the attack surface; per-build config
keeps it tight. See `src/server/origin-pin.ts` for the gate
implementation.

## V5.25 — Manifest signature verification is REQUIRED in production

The auto-update manifest at `https://app.zkqes.org/qkb-cli-manifest.json`
is signed by an Ed25519 key whose public half is embedded in the CLI
binary at compile time (`src/manifest/signing-key.ts`). The
verification path lives in `src/manifest/fetch.ts` and runs by
default on every `qkb serve` boot that reads from a `--manifest-url`.

`--no-verify` bypasses signature verification. Use ONLY for dev. Per
plan T9 step 1, production CLI builds reject unsigned manifests with
no override; the `--no-verify` flag will be removed at the
production-build switch (or hard-gated behind a `QKB_DEV_BUILD=1`
env var; lead's call at release time).

**`signing-key.ts` currently embeds the lead-issued dev key** from
`/tmp/qkb-cli-dev-keys/manifest.pub.pem` (commit `f67595a`). Production
swap happens at build-time before V1 ship; the constant
`IS_DEV_SIGNING_KEY = true` flags this build state and the CLI emits
a stderr warning on every `qkb serve` boot when true.

## V5.26 — Cache is per-user, never per-system

Cache root resolution lives in `src/circuit/cache-paths.ts`:

| OS | Cache root |
|---|---|
| macOS | `~/Library/Application Support/qkb-cli/` |
| Windows | `%APPDATA%\qkb-cli\` |
| Linux | `$XDG_DATA_HOME/qkb-cli/` (default `~/.local/share/qkb-cli/`) |

No `/var/cache/qkb-cli/`, no `/usr/local/share/qkb-cli/`, no shared
state across users. Each user's cache is independent; if Alice and
Bob both use `qkb serve`, each has their own ~2 GB zkey cache.

Reasons:
1. Witness JSON contains `walletSecret` (32-byte keying material).
   Per-user caches mean a multi-user shared workstation doesn't
   leak Alice's prove residue to Bob.
2. Per-user is the conventional XDG/macOS/Windows layout for
   user-level apps; deviating would surprise users.
3. Avoids needing root/admin for `npm install -g` to work — no
   system-level paths means no permission escalation.

If a future agent proposes a system-level shared cache — push back
unless the threat model fundamentally changes (e.g., a multi-tenant
deployment model that's NOT what V1 ships).

## V5.27 — Rapidsnark sidecar: postinstall download, fallback to dev cache

The CLI invokes the iden3/rapidsnark `prover` binary as a sidecar
(spawned via `child_process.spawn`). Resolution order
(`src/rapidsnark/sidecar-path.ts`):

1. **`--rapidsnark-bin <path>`** if explicitly passed at `qkb serve`
   command line — wins. Used by tests, alternate builds, manual
   overrides.
2. **Bundled position** when `process.pkg` is set (V1.1 SEA builds):
   `<exe-dir>/rapidsnark-<platform>-v0.0.8/bin/prover`. NOT used in
   V1 (V1 ships via npm only; SEA single-file binaries land in
   V1.1).
3. **Dev cache** at `~/.cache/qkb-bin/rapidsnark-<platform>-v0.0.8/bin/prover`.
   Populated by `postinstall.ts` on first `npm install -g @qkb/cli`.

The `<platform>` keys match iden3 release filename casing exactly:
- `linux-x86_64`
- `linux-arm64`
- `macOS-arm64` (NOT `darwin-arm64` — capitalization quirk)
- `macOS-x86_64`

**v0.0.8 ships no Windows prebuilt.** Windows users build
rapidsnark from source and pass `--rapidsnark-bin <path>`;
`detectRapidsnarkPlatform` throws an actionable error in that case.

Sha256 pins for all 4 platforms live in
`src/rapidsnark/postinstall.ts:PREBUILTS`. Pins captured 2026-05-03
against the iden3/rapidsnark v0.0.8 GitHub release; independently
verified by curl + sha256sum. A tampered mirror at the canonical
URL would mismatch and abort the postinstall (without failing the
npm install — postinstall errors are swallowed, runtime gracefully
errors with `--rapidsnark-bin` guidance).

## V5.28 — `/status` schema is FROZEN

Per orchestration plan §1.1, the GET `/status` response shape is
frozen across all CLI versions. Adding a field is non-breaking;
removing or renaming a field requires a cross-worker contract
change.

```ts
{
  ok: true,
  version: 'qkb-cli@<semver>',
  circuit: 'v5.2',                // hard-coded for V1
  zkeyLoaded: boolean,
  busy: boolean,
  provesCompleted: number,
  uptimeSec: number,
  downloadProgress: null | {      // null when zkeyLoaded === true
    downloadedBytes: number,
    totalBytes: number,
  },
}
```

The 8-field assertion lives in
`test/integration/serve-prove-roundtrip.test.ts` —
catches future drift. Web-eng's `detectCli` strict shape gate
requires every field's presence; a missing field returns null on
their side and breaks the browser auto-detection.

## V5.29 — bun-runtime support is BLOCKED upstream (V1.1 candidate)

`bun build --compile` produces a working binary for `qkb version` /
`status` / `cache` but `qkb serve` panics during `/prove`:

```
TypeError: Argument 1 ('event') to EventTarget.dispatchEvent must
be an instance of Event
  at node_modules/web-worker@1.2.0/cjs/node.js:175:10
```

Root cause: snarkjs depends on `web-worker@1.2.0`, which calls
`EventTarget.dispatchEvent(err)` with a non-Event arg in its Node
shim. Node tolerates this; Bun's stricter EventTarget rejects.

V1 ships via Node only (npm install path). V1.1 single-file binaries
will use Node 24's SEA (Single Executable Application) support
instead of bun-compile to sidestep this. Future contributors trying
`bun build --compile` again — don't, until upstream snarkjs ships a
Bun-compatible worker shim.

Caught + documented during T7 packaging investigation
(commit `da274e5`).

## V5.30 — `busy.release()` MUST be synchronous

The single-prove mutex in `src/server/busy-flag.ts` is released in
`src/server/http.ts:handleProve`'s `finally` block. **`busy.release()`
must run synchronously BEFORE awaiting tempdir cleanup.**

Original implementation released busy AFTER `await rm(tempdir)` in
finally. Window between `res.end()` and `busy.release()` was wide
enough (the rm is async, yields to event loop) for a fast follow-up
POST to see `busy=true` and get 429. Caught on first integration run
in T2; fix documented at the call site.

If a future agent "tidies up" the finally block by reordering
release after cleanup — push back. The 429-mutex test in
`test/integration/failure-modes.test.ts` (T9) is the regression
guard but only catches it if the test runs.

## V5.31 — Production origin is `app.zkqes.org` (post-V5.4-tag rename)

The CLI was originally written against `https://identityescrow.org`
as the production origin (per the V5.4 dispatch + the `v0.5.4-cli`
tag that shipped at commit `95561ba`).  Founder direction
2026-05-03 (post-tag, pre-npm-publish) renamed the production app
to `https://app.zkqes.org`.  The CLI's frozen origin pin updated
on a separate branch (`feat/cli-origin-pin-app-zkqes`) without
re-tagging; npm publish picks up the new origin from the current
HEAD whenever it fires.

Future contributors checking out the `v0.5.4-cli` tag verbatim
will see `identityescrow.org` references; main HEAD has
`app.zkqes.org`.  The orchestration §1.1 contract update (§ "Origin
allowlist") is the load-bearing source of truth.

Multi-origin allowlist explicitly NOT supported (per V5.24 — single
origin keeps the security narrative tight).  Dev builds expose
`--allowed-origin <url>` for `http://localhost:5173` etc.;
production CLI builds will eventually hard-code the production
origin with no flag.

Bumped `@qkb/cli` package version `0.5.2-pre` → `0.5.4.1-pre` to
signal the post-tag fix.

## File map

```
src/
├── index.ts                    # commander entrypoint, wires subcommands
├── commands/
│   ├── version.ts              # qkb version
│   ├── serve.ts                # qkb serve (boots CliServer)
│   ├── status.ts               # qkb status (probes /status)
│   └── cache.ts                # qkb cache, qkb cache clear
├── server/
│   ├── http.ts                 # CliServer class (lifted from prototype)
│   ├── origin-pin.ts           # Origin allowlist + corsHeaders
│   └── busy-flag.ts            # single-prove mutex
├── circuit/
│   ├── prove.ts                # spawns rapidsnark sidecar
│   ├── cache-paths.ts          # per-OS cache root resolution
│   └── download.ts             # streaming + sha256 + atomic-rename
├── manifest/
│   ├── types.ts                # zod schema for ManifestV1
│   ├── fetch.ts                # fetch + Ed25519 verify
│   └── signing-key.ts          # embedded production pubkey (compile-time)
├── rapidsnark/
│   ├── sidecar-path.ts         # platform → on-disk binary path
│   └── postinstall.ts          # postinstall download + sha256 verify
└── types-snarkjs.d.ts          # minimal declare module 'snarkjs'

scripts/
└── postinstall-shim.cjs        # CJS bridge to ESM postinstall.js

test/
├── unit/
│   ├── version.test.ts
│   ├── manifest-verify.test.ts
│   ├── zkey-download.test.ts
│   ├── cache-paths.test.ts
│   ├── cache-commands.test.ts
│   └── sidecar-path.test.ts
└── integration/
    ├── serve-prove-roundtrip.test.ts
    └── failure-modes.test.ts
```

## Test budget

`pnpm -F @qkb/cli test` runs 57 tests in ~30 s. Two integration
test files require:

- V5.2 fixtures present (`packages/circuits/ceremony/v5_2/qkb-v5_2-stub.zkey`
  + `build/v5_2-stub/QKBPresentationV5_js/QKBPresentationV5.wasm`)
- iden3 rapidsnark sidecar at `~/.cache/qkb-bin/rapidsnark-linux-x86_64-v0.0.8/bin/prover`

Both gate via `existsSync` checks; CI without these auto-skips the
heavy `describe` blocks. ~50 GB cgroup is needed for the heavy prove
tests (snarkjs + rapidsnark working set).

## Build

```
pnpm -F @qkb/cli build       # tsc → dist/src/**/*.js
pnpm -F @qkb/cli typecheck   # tsc --noEmit
pnpm -F @qkb/cli test        # vitest run
pnpm -F @qkb/cli pack        # prepack (tsc) + pnpm pack → qkb-cli-*.tgz
```

The pack output is the V1 distribution artifact. End users get it
via `npm install -g @qkb/cli`.
