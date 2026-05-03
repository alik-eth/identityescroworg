// Resolves the on-disk path to the iden3 rapidsnark `prover` binary.
//
// Two modes (dispatched via the presence of `process.pkg`):
//
//   1. Bundled (production: built via `pkg . --targets ...`):
//      pkg embeds the prover binary as an asset.  `process.pkg` is
//      set; the binary lives inside the pkg snapshot filesystem at
//      a path relative to the executable.  Currently we look for
//      `<exe-dir>/rapidsnark-<platform>-<arch>/bin/prover[.exe]`.
//
//   2. Dev (running un-pkg'd via tsx / ts-node / node src/index.ts):
//      Fall back to the lead-issued cache directory at
//      `~/.cache/qkb-bin/rapidsnark-<platform>-<arch>-v0.0.8/bin/prover`.
//      This is what the dispatch context provided; the postinstall
//      script populates it on first `npm install -g @qkb/cli`.
//
// Both modes return an absolute path.  Caller is responsible for
// stat-ing it and producing a clear error if missing — that's
// where the user gets actionable advice (run `qkb cache` etc.).

import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export type RapidsnarkPlatform = 'linux-x86_64' | 'linux-arm64' | 'darwin-arm64' | 'darwin-x86_64' | 'windows-x86_64';
export const RAPIDSNARK_VERSION = 'v0.0.8';

export interface SidecarPathInput {
  /** Defaults to process.platform + process.arch detection. */
  readonly platform?: RapidsnarkPlatform;
  /** Defaults to detection from `process.pkg`.  Tests inject false to exercise dev path. */
  readonly isPkg?: boolean;
  /** Defaults to process.execPath.  Tests inject for fakes. */
  readonly execPath?: string;
  /** Defaults to os.homedir(). */
  readonly home?: string;
}

/**
 * Detect which prebuilt rapidsnark archive matches the current host.
 * iden3 publishes prebuilts for these five platforms in v0.0.8.
 */
export function detectRapidsnarkPlatform(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): RapidsnarkPlatform {
  if (platform === 'linux' && arch === 'x64') return 'linux-x86_64';
  if (platform === 'linux' && arch === 'arm64') return 'linux-arm64';
  if (platform === 'darwin' && arch === 'arm64') return 'darwin-arm64';
  if (platform === 'darwin' && arch === 'x64') return 'darwin-x86_64';
  if (platform === 'win32' && arch === 'x64') return 'windows-x86_64';
  throw new Error(
    `unsupported platform/arch for rapidsnark sidecar: ${platform}-${arch}.  ` +
      'iden3/rapidsnark v0.0.8 ships Linux x64/arm64, macOS arm64/x64, Windows x64 only.',
  );
}

/**
 * Resolve the sidecar binary path for the current process.  Pure
 * function: no fs-side-effects beyond `existsSync`.  Caller verifies
 * the returned path actually points at a file before invoking.
 */
export function resolveSidecarPath(input: SidecarPathInput = {}): string {
  const platform = input.platform ?? detectRapidsnarkPlatform();
  const isPkg = input.isPkg ?? Boolean((process as unknown as { pkg?: unknown }).pkg);
  const exeName = platform.startsWith('windows') ? 'prover.exe' : 'prover';

  if (isPkg) {
    // Bundled path: pkg copies the prover binary alongside the exe
    // at build time via the `pkg.assets` config.
    const execPath = input.execPath ?? process.execPath;
    const exeDir = dirname(execPath);
    return join(
      exeDir,
      `rapidsnark-${platform}-${RAPIDSNARK_VERSION}`,
      'bin',
      exeName,
    );
  }

  // Dev path: ~/.cache/qkb-bin/...  Mirrors the lead-staged location.
  const home = input.home ?? homedir();
  return join(
    home,
    '.cache',
    'qkb-bin',
    `rapidsnark-${platform}-${RAPIDSNARK_VERSION}`,
    'bin',
    exeName,
  );
}

/**
 * Like resolveSidecarPath but throws a CLI-friendly error if the
 * resolved path doesn't exist.  Used by `serve.ts` when the user
 * didn't pass an explicit `--rapidsnark-bin`.
 */
export function resolveSidecarPathOrThrow(input: SidecarPathInput = {}): string {
  const path = resolveSidecarPath(input);
  if (!existsSync(path)) {
    throw new Error(
      `rapidsnark sidecar not found at ${path}.\n` +
        'Run `qkb cache` to inspect cache, or re-install the CLI to retrigger postinstall.',
    );
  }
  return path;
}
