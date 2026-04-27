/**
 * `qkb version` — print the package version. Reads from package.json
 * relative to the compiled bin so it works whether invoked as
 * `node dist/src/cli.js version` (development build) or as a bun-compiled
 * single-file binary (the bundle inlines the JSON via createRequire).
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export function runVersion(): void {
  const here = dirname(fileURLToPath(import.meta.url));
  // dist/src/commands/version.js → ../../../package.json
  const pkgPath = join(here, '..', '..', '..', 'package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as {
    version: string;
  };
  console.log(`qkb v${pkg.version}`);
}
