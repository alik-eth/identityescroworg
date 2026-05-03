// Cache-path resolution unit tests.
//
// All inputs are injected (platform / home / env), so tests are
// deterministic across the actual host OS and don't need to
// monkey-patch process.platform.

import { describe, expect, it } from 'vitest';
import {
  resolveCacheRoot,
  circuitCachePaths,
} from '../../src/circuit/cache-paths.js';

describe('resolveCacheRoot', () => {
  it('macOS uses ~/Library/Application Support/qkb-cli/', () => {
    const path = resolveCacheRoot({
      platform: 'darwin',
      home: '/Users/alice',
      env: {},
    });
    expect(path).toBe('/Users/alice/Library/Application Support/qkb-cli');
  });

  it('Windows uses %APPDATA%\\qkb-cli when APPDATA set', () => {
    const path = resolveCacheRoot({
      platform: 'win32',
      home: 'C:\\Users\\alice',
      env: { APPDATA: 'C:\\Users\\alice\\AppData\\Roaming' },
    });
    expect(path.replace(/\\/g, '/')).toBe(
      'C:/Users/alice/AppData/Roaming/qkb-cli',
    );
  });

  it('Windows falls back to home/AppData/Roaming when APPDATA unset', () => {
    const path = resolveCacheRoot({
      platform: 'win32',
      home: 'C:\\Users\\alice',
      env: {},
    });
    expect(path.replace(/\\/g, '/')).toBe(
      'C:/Users/alice/AppData/Roaming/qkb-cli',
    );
  });

  it('Linux respects $XDG_DATA_HOME if set', () => {
    const path = resolveCacheRoot({
      platform: 'linux',
      home: '/home/alice',
      env: { XDG_DATA_HOME: '/var/lib/alice/data' },
    });
    expect(path).toBe('/var/lib/alice/data/qkb-cli');
  });

  it('Linux defaults to ~/.local/share/qkb-cli when XDG_DATA_HOME unset', () => {
    const path = resolveCacheRoot({
      platform: 'linux',
      home: '/home/alice',
      env: {},
    });
    expect(path).toBe('/home/alice/.local/share/qkb-cli');
  });

  it('Linux ignores empty XDG_DATA_HOME (treats as unset)', () => {
    const path = resolveCacheRoot({
      platform: 'linux',
      home: '/home/alice',
      env: { XDG_DATA_HOME: '' },
    });
    expect(path).toBe('/home/alice/.local/share/qkb-cli');
  });

  it('unknown platform falls through to XDG layout', () => {
    // FreeBSD, etc. — share Linux's user-level conventions in
    // practice.  Better to give them the XDG-style path than to
    // reject with an error.
    const path = resolveCacheRoot({
      platform: 'freebsd',
      home: '/home/alice',
      env: {},
    });
    expect(path).toBe('/home/alice/.local/share/qkb-cli');
  });
});

describe('circuitCachePaths', () => {
  it('emits all five paths under the resolved cache root for v5.2', () => {
    const paths = circuitCachePaths('v5.2', {
      platform: 'linux',
      home: '/home/alice',
      env: {},
    });

    const root = '/home/alice/.local/share/qkb-cli';
    expect(paths.cacheRoot).toBe(root);
    expect(paths.circuitsDir).toBe(`${root}/circuits`);
    expect(paths.zkey).toBe(`${root}/circuits/qkb-v5.2.zkey`);
    expect(paths.zkeyTmp).toBe(`${root}/circuits/qkb-v5.2.zkey.tmp`);
    expect(paths.wasm).toBe(`${root}/circuits/qkb-v5.2.wasm`);
    expect(paths.vkey).toBe(`${root}/circuits/qkb-v5.2-vkey.json`);
    expect(paths.manifestDir).toBe(`${root}/manifest`);
    expect(paths.manifest).toBe(`${root}/manifest/qkb-cli-manifest.json`);
  });

  it('parameterizes by circuit version (forward compat with V5.3)', () => {
    const paths = circuitCachePaths('v5.3', {
      platform: 'darwin',
      home: '/Users/bob',
      env: {},
    });
    expect(paths.zkey).toBe(
      '/Users/bob/Library/Application Support/qkb-cli/circuits/qkb-v5.3.zkey',
    );
  });
});
