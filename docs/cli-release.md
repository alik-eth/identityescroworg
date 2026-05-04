# `zkqes` CLI release pipeline

> **Renamed 2026-05-03** — see [`docs/superpowers/specs/2026-05-03-zkqes-rename-design.md`](2026-05-03-zkqes-rename-design.md) for the rename baseline. Historical references to QKB/QIE/Identity-Escrow in pre-2026-05-03 commits remain immutable in git history.

This document describes the secrets and external resources the
`.github/workflows/release-cli.yml` workflow needs in order to ship a
signed, multi-platform release of the `zkqes` CLI.

## Tag → release flow

1. Bump `packages/zkqes-cli/package.json` `version` and commit on a release branch.
2. Tag the commit `cli-v<X.Y.Z>` (e.g. `cli-v0.1.0`).
3. Push the tag — the workflow builds 5 binaries via `bun build --compile`,
   signs the macOS + Windows binaries, attaches them all to the GitHub release,
   publishes `@zkqes/cli` to npm, and bumps `Formula/zkqes.rb` in the
   `alik-eth/homebrew-zkqes` tap repo.

## Required GitHub repo secrets

| Secret | Purpose | Cost / setup |
|---|---|---|
| `NPM_TOKEN` | publishes `@zkqes/cli` to the npm registry | free; create at npmjs.com → Access Tokens |
| `APPLE_DEVELOPER_ID` | the human-readable identity name for `codesign --sign` (e.g. `"Developer ID Application: Acme LLC (ABCDEF1234)"`) | $99/yr Apple Developer Program |
| `APPLE_ID` | the Apple ID email used for notarization | included in Developer Program |
| `APPLE_APP_PASSWORD` | an app-specific password for `notarytool` | created at appleid.apple.com |
| `APPLE_TEAM_ID` | your 10-character team ID | included in Developer Program |
| `WIN_PFX_BASE64` | base64 of the Authenticode `.pfx` certificate | $200–400/yr from Sectigo, DigiCert, etc. |
| `WIN_PFX_PASSWORD` | password for the `.pfx` | set when generating the cert |
| `HOMEBREW_TAP_TOKEN` | a fine-grained PAT that can push to `alik-eth/homebrew-zkqes` | free; create at github.com/settings/tokens |

Without `APPLE_*` the macOS matrix legs will fail (Gatekeeper blocks
unsigned binaries on macOS 14+). Without `WIN_PFX_*` the Windows leg
fails (SmartScreen warns users on unsigned `.exe`s; the workflow does
hard-fail rather than emit an unsigned binary).

If you need to ship an interim release without one of the platforms
working, comment out that matrix entry rather than removing the secret
gating — losing the gate later is harder to spot.

## External resources

- Homebrew tap repo: must exist at `https://github.com/alik-eth/homebrew-zkqes`
  before the first release. The repo only needs a `Formula/zkqes.rb` file;
  the workflow's `update-tap` job rewrites the `version` and `sha256` lines
  on each release.
- npm scope `@zkqes`: the `NPM_TOKEN` must have publish rights to the scope.
  First publish needs to be done manually with `--access public` flag set
  in `package.json` or via the workflow's `--access public` argument.
- GitHub release: `softprops/action-gh-release@v2` creates the release on
  the first matrix step that runs and appends each subsequent binary.

## Homebrew tap setup (one-time)

Before the first release, create the tap repo at
`https://github.com/alik-eth/homebrew-zkqes`:

1. Create the repo (private or public, Homebrew works either way; public
   is conventional). Initialize with a README.
2. Copy `docs/cli-release-homebrew/Formula/zkqes.rb` from this repo into
   `Formula/zkqes.rb` in the tap repo. Commit and push.
3. Provision the `HOMEBREW_TAP_TOKEN` secret in this repo's settings:
   a fine-grained PAT scoped to the tap repo with `Contents: read & write`.

After step 3, every `cli-v*` tag push to this repo runs the workflow's
`update-tap` job, which clones the tap repo, rewrites the four `sha256`
lines and the `version` line in `Formula/zkqes.rb`, and pushes a commit
`zkqes cli-v<X.Y.Z>`. Users then `brew tap alik-eth/homebrew-zkqes && brew install zkqes`.

The formula template in `docs/cli-release-homebrew/Formula/zkqes.rb` is
load-bearing for the tap repo's initial state. If you change the binary
file naming (e.g. add a new architecture, rename `zkqes-linux-x64`), update
the template here AND the `update-tap` job's loop.

## Local dry-run

The workflow can't be run locally end-to-end because of the secrets, but
the binary build step is exactly what `pnpm -F @zkqes/cli build:binaries`
runs. Use `ZKQES_BUILD_TARGETS=linux-x64` to limit a local smoke-build to
your host architecture.
