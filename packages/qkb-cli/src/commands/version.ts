/**
 * `qkb version` — print the package version.
 *
 * Imports package.json statically so the version is inlined at build time.
 * This keeps the bun-compiled single-file binary self-contained — no runtime
 * filesystem lookup that breaks when the executable is moved off the source
 * tree.
 */

import pkg from '../../package.json' with { type: 'json' };

export function runVersion(): void {
  console.log(`qkb v${pkg.version}`);
}
