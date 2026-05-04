// Cache-path resolution per orchestration plan §1.4.
//
// Each OS has a conventional per-user data directory:
//   macOS   →  ~/Library/Application Support/qkb-cli/
//   Windows →  %APPDATA%\qkb-cli\
//   Linux   →  ~/.local/share/qkb-cli/   (respects $XDG_DATA_HOME if set)
//
// Subdirectory layout under the cache root (frozen):
//   circuits/qkb-<version>.zkey         — cached proving key (~2 GB)
//   circuits/qkb-<version>.zkey.tmp     — partial download (atomic-mv on completion)
//   circuits/qkb-<version>.wasm         — witness-calc WASM
//   circuits/qkb-<version>-vkey.json    — verification key
//   manifest/qkb-cli-manifest.json      — last fetched manifest
//
// The functions here take platform + homedir + env as parameters so
// tests can inject synthetic environments without monkey-patching
// process.platform.  `resolveCacheRoot()` with zero args reads from
// the current process — this is the default production caller.

import { join } from 'node:path';
import { homedir } from 'node:os';

export type Platform = 'darwin' | 'win32' | 'linux' | (string & {});

export interface CacheRootInput {
  /** Defaults to process.platform. */
  readonly platform?: Platform;
  /** Defaults to os.homedir(). */
  readonly home?: string;
  /** Defaults to process.env.  Only `APPDATA` and `XDG_DATA_HOME` are read. */
  readonly env?: Readonly<Record<string, string | undefined>>;
}

export function resolveCacheRoot(input: CacheRootInput = {}): string {
  const platform = input.platform ?? process.platform;
  const home = input.home ?? homedir();
  const env = input.env ?? process.env;

  if (platform === 'darwin') {
    return join(home, 'Library', 'Application Support', 'qkb-cli');
  }
  if (platform === 'win32') {
    // %APPDATA% is the conventional per-user roaming app-data dir on
    // Windows.  Fall back to home/AppData/Roaming if APPDATA is unset
    // (rare; only happens in misconfigured shells).
    const appdata = env['APPDATA'] ?? join(home, 'AppData', 'Roaming');
    return join(appdata, 'qkb-cli');
  }
  // Linux + everything else: XDG.
  const xdg = env['XDG_DATA_HOME'];
  const xdgRoot = xdg && xdg.length > 0 ? xdg : join(home, '.local', 'share');
  return join(xdgRoot, 'qkb-cli');
}

export interface CircuitCachePaths {
  readonly cacheRoot: string;
  readonly circuitsDir: string;
  readonly zkey: string;
  readonly zkeyTmp: string;
  readonly wasm: string;
  readonly vkey: string;
  readonly manifestDir: string;
  readonly manifest: string;
}

export function circuitCachePaths(
  circuitVersion: string,
  cacheInput: CacheRootInput = {},
): CircuitCachePaths {
  const cacheRoot = resolveCacheRoot(cacheInput);
  const circuitsDir = join(cacheRoot, 'circuits');
  const manifestDir = join(cacheRoot, 'manifest');
  return {
    cacheRoot,
    circuitsDir,
    zkey: join(circuitsDir, `qkb-${circuitVersion}.zkey`),
    zkeyTmp: join(circuitsDir, `qkb-${circuitVersion}.zkey.tmp`),
    wasm: join(circuitsDir, `qkb-${circuitVersion}.wasm`),
    vkey: join(circuitsDir, `qkb-${circuitVersion}-vkey.json`),
    manifestDir,
    manifest: join(manifestDir, 'qkb-cli-manifest.json'),
  };
}
