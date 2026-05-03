# `@qkb/cli`

Localhost-bound native rapidsnark prover for the V5.2 register flow.

`qkb serve` boots an HTTP server on `127.0.0.1:9080` that the browser
flow at `identityescrow.org/v5/registerV5` detects and offloads the
prove step to. Same proof, **6× faster, ~10× less memory** than the
in-browser snarkjs path:

| Path | Wall (V5.2 stub) | Peak RSS |
|---|---|---|
| Browser snarkjs (Firefox 64-bit) | 90.3 s | 38.38 GiB |
| Native rapidsnark via `qkb serve` | 13.1 s | 3.70 GiB |

Browser stays canonical for everything else: wallet (MetaMask via
wagmi), witness gen, on-chain submission. CLI just turns the prove
step into a localhost roundtrip.

## Install

```bash
npm install -g @qkb/cli
```

The postinstall hook downloads the matching iden3 rapidsnark sidecar
binary for your platform from the [iden3/rapidsnark v0.0.8 GitHub
release](https://github.com/iden3/rapidsnark/releases/tag/v0.0.8),
sha256-verifies, and caches at `~/.cache/qkb-bin/`. No additional
setup needed on supported platforms.

### Supported platforms (V1)

- Linux x86_64
- Linux arm64
- macOS arm64 (Apple Silicon)
- macOS x86_64 (Intel Macs)

**Windows is not supported in V1** — iden3/rapidsnark v0.0.8 ships no
Windows prebuilt. Windows users either build rapidsnark from source +
pass `--rapidsnark-bin <path>` at runtime, or wait for V1.1 (which
will bundle a Windows build).

## Usage

```bash
# Start the localhost prove server.
qkb serve \
  --zkey ~/.local/share/qkb-cli/circuits/qkb-v5.2.zkey \
  --wasm ~/.local/share/qkb-cli/circuits/qkb-v5.2.wasm \
  --vkey ~/.local/share/qkb-cli/circuits/qkb-v5.2-vkey.json
# Listening on http://127.0.0.1:9080
# zkey:           …
# allowed origin: https://identityescrow.org
# endpoints:      GET /status   POST /prove

# In another terminal: probe.
qkb status
# running: qkb-cli@0.5.2-pre  circuit=v5.2  zkey=ready  busy=false  …

# Or via curl directly.
curl -s http://127.0.0.1:9080/status

# Stop with Ctrl-C — clean shutdown via SIGINT.
```

The browser at `identityescrow.org/v5/registerV5` auto-detects a
running `qkb serve` instance via a `/status` probe on page load and
switches its prove path automatically. No browser configuration
needed.

## Subcommands

```
qkb version              Print CLI + bundled rapidsnark version.
qkb serve [options]      Start the localhost HTTP prove server.
qkb status [options]     Probe whether a server is running.
qkb cache                List cached circuit artifacts + sizes.
qkb cache clear [-c id]  Remove cached artifacts for one or all circuits.
```

`qkb serve --help` for the full flag surface.

## Security model

- **Loopback only** — server binds `127.0.0.1`, never `0.0.0.0`. LAN
  devices cannot reach it. The `--host` flag rejects non-loopback
  bind addresses with a startup error.
- **Origin-pinned** — `POST /prove` accepts only the configured
  `--allowed-origin` (default: `https://identityescrow.org`). A
  malicious tab on a different origin cannot co-opt your local
  prover.
- **No background process** — `qkb serve` runs only while you've
  invoked it. No daemon, no LaunchAgent / Windows Service / systemd
  unit, no auto-start at login. Ctrl-C exits cleanly; the prover
  isn't running unless you say so.
- **Manifest signature verification** — circuit artifacts (`zkey`,
  `wasm`, `vkey`) downloaded by `postinstall` are sha256-verified
  against an Ed25519-signed manifest. The signing pubkey is embedded
  in the CLI binary at compile time, so a substituted manifest URL
  cannot redirect to malicious artifacts.
- **No telemetry** — V1 ships zero telemetry. No crash reports, no
  analytics, no version-check beacons. The auto-update manifest is
  only fetched when explicitly requested.

## Troubleshooting

### `rapidsnark sidecar not found at …`

The postinstall hook didn't run (or its download failed silently).
Re-run by reinstalling:

```bash
npm install -g @qkb/cli
```

Or if you've built rapidsnark from source, pass the binary path
explicitly:

```bash
qkb serve --rapidsnark-bin /path/to/your/rapidsnark/build/bin/prover …
```

### `port 9080 already in use`

Either another `qkb serve` is already running (check `qkb status`)
or another service is squatting the port. Choose a different port:

```bash
qkb serve --port 9091 …
```

The browser-side detection probes `127.0.0.1:9080` by default, so
non-default ports require the browser to be configured to match.

### `qkb serve: refusing to bind non-loopback host`

`--host` was set to a non-loopback address (e.g., `0.0.0.0` or a
LAN IP). The CLI hard-rejects this since the prover has no auth — a
LAN-reachable bind would expose your local prove API to any device
on the network. Use `127.0.0.1` (default) or `::1`.

### `Origin not allowed`

The browser is making requests from an origin different from the
configured `--allowed-origin`. For dev against a local web app at
e.g. `http://localhost:5173`:

```bash
qkb serve --allowed-origin http://localhost:5173 …
```

Production CLI builds reject this flag — `--allowed-origin` is
hard-coded to `https://identityescrow.org` to prevent a malicious
local script from surreptitiously authorizing a bad origin.

## V1.1 roadmap (deferred from V1 scope)

- Single-file binaries (`qkb-linux-x86_64`, `qkb-darwin-arm64`, …) via
  Node 24's Single Executable Application (SEA) support, distributed
  via Homebrew tap + GitHub releases. V1's npm install path covers
  the same UX with one extra step (`npm install -g`).
- Windows native support — building rapidsnark from source on
  Windows + bundling.
- bun-runtime support — currently blocked by upstream's `web-worker@1.2.0`
  calling `EventTarget.dispatchEvent(err)` with a non-Event arg
  (Node tolerates; Bun's stricter EventTarget rejects). Waiting for
  upstream to ship a Bun-compatible worker shim, or for Bun to relax
  the EventTarget check.
- Multi-circuit support — V5.3 (OID-anchor amendment) will publish
  alongside V5.2; the manifest's `circuits` map is forward-compatible.

## License

(Pending — see project root LICENSE / COPYING when filled in by lead.)
