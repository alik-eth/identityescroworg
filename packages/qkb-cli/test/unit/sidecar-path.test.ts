// Sidecar-path resolver unit tests.
//
// All tests inject platform / isPkg / execPath / home — no monkey-
// patching of process internals.  resolveSidecarPath is a pure
// function modulo an existsSync call (only in
// resolveSidecarPathOrThrow), and tests don't exercise that branch.

import { describe, expect, it } from 'vitest';
import {
  detectRapidsnarkPlatform,
  resolveSidecarPath,
  RAPIDSNARK_VERSION,
} from '../../src/rapidsnark/sidecar-path.js';

describe('detectRapidsnarkPlatform', () => {
  it.each([
    ['linux', 'x64', 'linux-x86_64'],
    ['linux', 'arm64', 'linux-arm64'],
    ['darwin', 'arm64', 'darwin-arm64'],
    ['darwin', 'x64', 'darwin-x86_64'],
    ['win32', 'x64', 'windows-x86_64'],
  ] as const)('maps %s + %s → %s', (platform, arch, expected) => {
    expect(detectRapidsnarkPlatform(platform, arch)).toBe(expected);
  });

  it('rejects unsupported platform/arch combos', () => {
    expect(() => detectRapidsnarkPlatform('linux', 'ia32')).toThrow(
      /unsupported platform\/arch/,
    );
    expect(() => detectRapidsnarkPlatform('android', 'arm64')).toThrow(
      /unsupported platform\/arch/,
    );
  });
});

describe('resolveSidecarPath', () => {
  it('dev mode (un-pkg\'d) resolves under ~/.cache/qkb-bin', () => {
    const path = resolveSidecarPath({
      platform: 'linux-x86_64',
      isPkg: false,
      home: '/home/alice',
    });
    expect(path).toBe(
      `/home/alice/.cache/qkb-bin/rapidsnark-linux-x86_64-${RAPIDSNARK_VERSION}/bin/prover`,
    );
  });

  it('bundled (pkg) mode resolves alongside the executable', () => {
    const path = resolveSidecarPath({
      platform: 'linux-x86_64',
      isPkg: true,
      execPath: '/usr/local/bin/qkb',
    });
    expect(path).toBe(
      `/usr/local/bin/rapidsnark-linux-x86_64-${RAPIDSNARK_VERSION}/bin/prover`,
    );
  });

  it('Windows pkg mode appends .exe', () => {
    const path = resolveSidecarPath({
      platform: 'windows-x86_64',
      isPkg: true,
      execPath: 'C:\\Program Files\\qkb-cli\\qkb.exe',
    });
    expect(path.endsWith('prover.exe')).toBe(true);
  });

  it('Windows dev mode also appends .exe', () => {
    const path = resolveSidecarPath({
      platform: 'windows-x86_64',
      isPkg: false,
      home: 'C:\\Users\\alice',
    });
    expect(path.endsWith('prover.exe')).toBe(true);
  });

  it('macOS arm64 dev mode resolves to the conventional cache layout', () => {
    const path = resolveSidecarPath({
      platform: 'darwin-arm64',
      isPkg: false,
      home: '/Users/bob',
    });
    expect(path).toBe(
      `/Users/bob/.cache/qkb-bin/rapidsnark-darwin-arm64-${RAPIDSNARK_VERSION}/bin/prover`,
    );
  });

  it('the path includes the rapidsnark version (catches accidental version drift)', () => {
    const path = resolveSidecarPath({
      platform: 'linux-x86_64',
      isPkg: false,
      home: '/home/alice',
    });
    expect(path).toContain(RAPIDSNARK_VERSION);
  });
});
