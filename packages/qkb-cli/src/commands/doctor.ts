/**
 * `qkb doctor` — environment diagnostics. Prints node + rapidsnark + platform
 * so users can see at a glance whether the rapidsnark backend is reachable.
 */

import { execSync } from 'node:child_process';

export function runDoctor(): void {
  console.log(`node:        v${process.versions.node}`);

  let rapidsnark = 'not on PATH';
  try {
    const out = execSync('rapidsnark --version', {
      stdio: ['ignore', 'pipe', 'ignore'],
    })
      .toString()
      .trim();
    rapidsnark = out.length > 0 ? out : 'present (no --version output)';
  } catch {
    /* keep default */
  }
  console.log(`rapidsnark:  ${rapidsnark}`);
  console.log(`platform:    ${process.platform} ${process.arch}`);
}
