# `qkb` CLI release pipeline

This document describes the secrets and external resources the
`.github/workflows/release-cli.yml` workflow needs in order to ship a
signed, multi-platform release of the `qkb` CLI.

## Tag → release flow

1. Bump `packages/qkb-cli/package.json` `version` and commit on a release branch.
2. Tag the commit `cli-v<X.Y.Z>` (e.g. `cli-v0.1.0`).
3. Push the tag — the workflow builds 5 binaries via `bun build --compile`,
   signs the macOS + Windows binaries, attaches them all to the GitHub release,
   publishes `@qkb/cli` to npm, and bumps `Formula/qkb.rb` in the
   `qkb-eth/homebrew-qkb` tap repo.

## Required GitHub repo secrets

| Secret | Purpose | Cost / setup |
|---|---|---|
| `NPM_TOKEN` | publishes `@qkb/cli` to the npm registry | free; create at npmjs.com → Access Tokens |
| `APPLE_DEVELOPER_ID` | the human-readable identity name for `codesign --sign` (e.g. `"Developer ID Application: Acme LLC (ABCDEF1234)"`) | $99/yr Apple Developer Program |
| `APPLE_ID` | the Apple ID email used for notarization | included in Developer Program |
| `APPLE_APP_PASSWORD` | an app-specific password for `notarytool` | created at appleid.apple.com |
| `APPLE_TEAM_ID` | your 10-character team ID | included in Developer Program |
| `WIN_PFX_BASE64` | base64 of the Authenticode `.pfx` certificate | $200–400/yr from Sectigo, DigiCert, etc. |
| `WIN_PFX_PASSWORD` | password for the `.pfx` | set when generating the cert |
| `HOMEBREW_TAP_TOKEN` | a fine-grained PAT that can push to `qkb-eth/homebrew-qkb` | free; create at github.com/settings/tokens |

Without `APPLE_*` the macOS matrix legs will fail (Gatekeeper blocks
unsigned binaries on macOS 14+). Without `WIN_PFX_*` the Windows leg
fails (SmartScreen warns users on unsigned `.exe`s; the workflow does
hard-fail rather than emit an unsigned binary).

If you need to ship an interim release without one of the platforms
working, comment out that matrix entry rather than removing the secret
gating — losing the gate later is harder to spot.

## External resources

- Homebrew tap repo: must exist at `https://github.com/qkb-eth/homebrew-qkb`
  before the first release. The repo only needs a `Formula/qkb.rb` file;
  the workflow's `update-tap` job rewrites the `version` and `sha256` lines
  on each release.
- npm scope `@qkb`: the `NPM_TOKEN` must have publish rights to the scope.
  First publish needs to be done manually with `--access public` flag set
  in `package.json` or via the workflow's `--access public` argument.
- GitHub release: `softprops/action-gh-release@v2` creates the release on
  the first matrix step that runs and appends each subsequent binary.

## Homebrew tap setup (one-time)

Before the first release, create the tap repo at
`https://github.com/qkb-eth/homebrew-qkb`:

1. Create the repo (private or public, Homebrew works either way; public
   is conventional). Initialize with a README.
2. Copy `docs/cli-release-homebrew/Formula/qkb.rb` from this repo into
   `Formula/qkb.rb` in the tap repo. Commit and push.
3. Provision the `HOMEBREW_TAP_TOKEN` secret in this repo's settings:
   a fine-grained PAT scoped to the tap repo with `Contents: read & write`.

After step 3, every `cli-v*` tag push to this repo runs the workflow's
`update-tap` job, which clones the tap repo, rewrites the four `sha256`
lines and the `version` line in `Formula/qkb.rb`, and pushes a commit
`qkb cli-v<X.Y.Z>`. Users then `brew tap qkb-eth/qkb && brew install qkb`.

The formula template in `docs/cli-release-homebrew/Formula/qkb.rb` is
load-bearing for the tap repo's initial state. If you change the binary
file naming (e.g. add a new architecture, rename `qkb-linux-x64`), update
the template here AND the `update-tap` job's loop.

## Local dry-run

The workflow can't be run locally end-to-end because of the secrets, but
the binary build step is exactly what `pnpm -F @qkb/cli build:binaries`
runs. Use `QKB_BUILD_TARGETS=linux-x64` to limit a local smoke-build to
your host architecture.
