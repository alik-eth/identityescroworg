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
    ['darwin', 'arm64', 'macOS-arm64'],
    ['darwin', 'x64', 'macOS-x86_64'],
  ] as const)('maps %s + %s → %s', (platform, arch, expected) => {
    expect(detectRapidsnarkPlatform(platform, arch)).toBe(expected);
  });

  it('rejects Windows (no v0.0.8 prebuilt) with actionable message', () => {
    // Documented limitation: iden3/rapidsnark v0.0.8 ships no
    // Windows binary.  Windows users must build from source.
    expect(() => detectRapidsnarkPlatform('win32', 'x64')).toThrow(
      /no rapidsnark v0\.0\.8 prebuilt/,
    );
    expect(() => detectRapidsnarkPlatform('win32', 'x64')).toThrow(
      /--rapidsnark-bin/,
    );
  });

  it('rejects other unsupported platform/arch combos', () => {
    expect(() => detectRapidsnarkPlatform('linux', 'ia32')).toThrow(
      /no rapidsnark v0\.0\.8 prebuilt/,
    );
    expect(() => detectRapidsnarkPlatform('android', 'arm64')).toThrow(
      /no rapidsnark v0\.0\.8 prebuilt/,
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

  it('macOS arm64 dev mode resolves to the conventional cache layout', () => {
    const path = resolveSidecarPath({
      platform: 'macOS-arm64',
      isPkg: false,
      home: '/Users/bob',
    });
    expect(path).toBe(
      `/Users/bob/.cache/qkb-bin/rapidsnark-macOS-arm64-${RAPIDSNARK_VERSION}/bin/prover`,
    );
  });

  it('macOS x86_64 dev mode resolves under .cache (Intel Macs still supported)', () => {
    const path = resolveSidecarPath({
      platform: 'macOS-x86_64',
      isPkg: false,
      home: '/Users/carol',
    });
    expect(path).toBe(
      `/Users/carol/.cache/qkb-bin/rapidsnark-macOS-x86_64-${RAPIDSNARK_VERSION}/bin/prover`,
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
