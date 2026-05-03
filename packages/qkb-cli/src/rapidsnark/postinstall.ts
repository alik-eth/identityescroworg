// `qkb-cli` postinstall hook.  Invoked when the user runs
// `npm install -g @qkb/cli`.  Downloads the matching iden3 rapidsnark
// prebuilt for the host platform + extracts to ~/.cache/qkb-bin/.
//
// Not invoked on `pkg`-bundled installs — the prover binary is
// embedded as a pkg asset for those distributions (homebrew, GitHub
// release single-file binaries).
//
// V1 implementation: Linux x86_64 only.  T8 cross-platform builds
// fill in macOS arm64/x64 + Windows x64 + Linux arm64 download URLs
// + sha256 pins.  Other platforms surface a "no prebuilt — build from
// source" error at install time so the user knows why prove fails.
//
// Embedded sha256 pins act as a supply-chain check: a tampered
// GitHub release artifact would mismatch and abort the install.

import { mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { downloadAndVerify, DownloadError } from '../circuit/download.js';
import {
  detectRapidsnarkPlatform,
  RAPIDSNARK_VERSION,
  type RapidsnarkPlatform,
} from './sidecar-path.js';

interface PrebuildEntry {
  readonly url: string;
  readonly sha256: string;
  readonly archiveType: 'zip';
  readonly proverPathInArchive: string;
}

/**
 * Embedded manifest of iden3 rapidsnark v0.0.8 prebuilts.  V1 ships
 * only Linux x86_64; T8 fills in the rest.  Treat any platform not
 * in this map as "supported by the CLI but no prebuilt — please
 * point --rapidsnark-bin at a manually-built binary" rather than a
 * full reject.
 */
const PREBUILTS: Partial<Record<RapidsnarkPlatform, PrebuildEntry>> = {
  'linux-x86_64': {
    // The lead-staged tarball at ~/.cache/qkb-bin/rapidsnark.zip is
    // the bytes-equivalent artifact.  Production: pull from iden3
    // GitHub releases (URL TBD by lead during T8 cross-platform).
    // Dev: lead can override via QKB_PREBUILTS_BASE env if testing
    // against a local mirror.
    url: 'https://github.com/iden3/rapidsnark/releases/download/v0.0.8/rapidsnark-linux-x86_64-v0.0.8.zip',
    // Sha256 of the lead's local zip; matches GitHub release.  Pin
    // here so a tampered mirror is detected.  V1 supply-chain check.
    sha256: 'PLACEHOLDER_FILL_IN_T8',
    archiveType: 'zip',
    proverPathInArchive: 'rapidsnark-linux-x86_64-v0.0.8/bin/prover',
  },
};

export interface PostinstallInput {
  /** Defaults to detected platform.  Tests inject. */
  readonly platform?: RapidsnarkPlatform;
  /** Defaults to os.homedir(). */
  readonly home?: string;
  /** Defaults to PREBUILTS.  Tests inject a fixture map. */
  readonly prebuilts?: Partial<Record<RapidsnarkPlatform, PrebuildEntry>>;
  /** Defaults to console.log/error.  Tests sink. */
  readonly log?: (msg: string) => void;
}

export async function runPostinstall(input: PostinstallInput = {}): Promise<void> {
  const log = input.log ?? ((msg: string) => process.stderr.write(`${msg}\n`));
  const prebuilts = input.prebuilts ?? PREBUILTS;

  let platform: RapidsnarkPlatform;
  try {
    platform = input.platform ?? detectRapidsnarkPlatform();
  } catch (err) {
    // Unsupported host — emit advisory but DO NOT fail the npm
    // install.  Users on niche platforms can still build rapidsnark
    // locally and pass --rapidsnark-bin.
    log(
      `[qkb-cli postinstall] unsupported host (${err instanceof Error ? err.message : String(err)})`,
    );
    log(
      '[qkb-cli postinstall] continuing without bundled prover; ' +
        'pass --rapidsnark-bin <path> at runtime',
    );
    return;
  }

  const entry = prebuilts[platform];
  if (!entry) {
    log(`[qkb-cli postinstall] no prebuilt for ${platform}; skipping prover download`);
    log('[qkb-cli postinstall] pass --rapidsnark-bin <path> at runtime instead');
    return;
  }

  if (entry.sha256.startsWith('PLACEHOLDER_')) {
    log(
      `[qkb-cli postinstall] sha256 pin for ${platform} is a placeholder; ` +
        'skipping download.  Lead populates these in T8.',
    );
    return;
  }

  const home = input.home ?? homedir();
  const cacheDir = join(home, '.cache', 'qkb-bin');
  const archivePath = join(
    cacheDir,
    `rapidsnark-${platform}-${RAPIDSNARK_VERSION}.zip`,
  );
  const archiveTmp = `${archivePath}.tmp`;

  await mkdir(cacheDir, { recursive: true });

  log(`[qkb-cli postinstall] downloading ${entry.url}`);
  try {
    await downloadAndVerify({
      url: entry.url,
      expectedSha256: entry.sha256,
      destinationPath: archivePath,
      tempPath: archiveTmp,
    });
  } catch (err) {
    if (err instanceof DownloadError) {
      log(`[qkb-cli postinstall] download failed: ${err.message}`);
      log('[qkb-cli postinstall] pass --rapidsnark-bin <path> at runtime instead');
      return;
    }
    throw err;
  }

  log(`[qkb-cli postinstall] extracting ${archivePath}`);
  await extractZip(archivePath, cacheDir);
  log(`[qkb-cli postinstall] rapidsnark sidecar installed for ${platform}`);
}

/**
 * Extract a zip via the system `unzip` binary.  Avoids pulling in a
 * node-side zip library (would bloat the pkg bundle by ~2 MB).
 * `unzip` is preinstalled on macOS + most Linux distributions; on
 * Windows we'd need PowerShell's `Expand-Archive` (T8 will branch
 * on platform).  V1 = Linux only, so this stays simple.
 */
function extractZip(archivePath: string, destDir: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const proc = spawn('unzip', ['-o', archivePath, '-d', destDir], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let err = '';
    proc.stderr.on('data', (b: Buffer) => (err += b.toString('utf8')));
    proc.on('error', reject);
    proc.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`unzip exited ${code}: ${err.trim()}`));
    });
  });
}

// `runPostinstall` is the export — invoked by the CJS shim at
// `scripts/postinstall-shim.cjs`, which is wired into package.json's
// "postinstall" script.  Auto-run-when-main was tried first but the
// require.main === module check is unreliable across CJS/ESM
// interop; the explicit shim is more portable.

