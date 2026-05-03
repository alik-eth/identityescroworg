// `qkb version` — emits two lines: the CLI's own semver + the bundled
// rapidsnark version it ships with.  Both are compile-time constants so
// the binary's identity is immutable post-build.
//
// The rapidsnark version is load-bearing: the CLI's `serve` subcommand
// (T2) shells out to a sidecar prover binary, and the proof-format/zkey
// compatibility surface is pinned to the rapidsnark release we vendor.
// Future bumps require a coordinated CLI release, not a runtime swap.

import type { Command } from 'commander';

export const PKG_VERSION = '0.5.2-pre';
export const RAPIDSNARK_VERSION = 'v0.0.8';

export function versionCommand(program: Command): void {
  program
    .command('version')
    .description('Print the CLI version and bundled rapidsnark version.')
    .action(() => {
      process.stdout.write(`qkb-cli@${PKG_VERSION}\n`);
      process.stdout.write(`rapidsnark ${RAPIDSNARK_VERSION}\n`);
    });
}
