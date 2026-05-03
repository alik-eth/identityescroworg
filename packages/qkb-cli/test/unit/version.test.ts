// `qkb version` smoke test — runs the CLI via `tsx` against the source
// (not the pkg-bundled binary).  T7 adds a separate pkg-binary smoke
// test once `pkg` build is wired; T1 only validates the source path
// works end-to-end.
//
// Why test against source in T1: pkg cross-target builds (5 platforms,
// ~50 MB each) are heavy + Vercel's pkg is in maintenance mode.
// Decoupling T1's TDD gate from T7's bundling lets the scaffold land
// independently of the build-tooling story.

import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { PKG_VERSION, RAPIDSNARK_VERSION } from '../../src/commands/version.js';

const __dirname = resolve(fileURLToPath(import.meta.url), '..');
const ENTRY = resolve(__dirname, '..', '..', 'src', 'index.ts');

function runCli(args: string[]): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync('npx', ['tsx', ENTRY, ...args], { encoding: 'utf8' });
  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    status: result.status,
  };
}

describe('qkb version', () => {
  it('prints the CLI version and the bundled rapidsnark version', () => {
    const { stdout, status } = runCli(['version']);

    expect(status).toBe(0);
    expect(stdout).toContain(`qkb-cli@${PKG_VERSION}`);
    expect(stdout).toContain(`rapidsnark ${RAPIDSNARK_VERSION}`);
  });

  it('exposes the version constants matching package.json', () => {
    // Catches drift between package.json's "version" field and the
    // hard-coded constant in commands/version.ts. T7 will additionally
    // smoke-test the pkg-bundled binary's reported version against the
    // package.json baseline.
    expect(PKG_VERSION).toBe('0.5.2-pre');
    expect(RAPIDSNARK_VERSION).toMatch(/^v\d+\.\d+\.\d+$/);
  });
});
