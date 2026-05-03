// `qkb cache` + `qkb cache clear` — inspect / wipe the per-user cache
// directory.
//
// UX shape:
//   $ qkb cache
//   cache root: /home/alice/.local/share/qkb-cli
//     circuits/qkb-v5.2.zkey       2.01 GiB
//     circuits/qkb-v5.2.wasm      21.06 MiB
//     circuits/qkb-v5.2-vkey.json  6.61 KiB
//     manifest/qkb-cli-manifest.json  812 B
//
//   $ qkb cache clear --circuit v5.2
//   removed: /home/alice/.local/share/qkb-cli/circuits/qkb-v5.2.zkey
//   removed: /home/alice/.local/share/qkb-cli/circuits/qkb-v5.2.wasm
//   removed: /home/alice/.local/share/qkb-cli/circuits/qkb-v5.2-vkey.json
//
// Operator-facing diagnostic; not security-sensitive.  Bytes shown
// in IEC binary units (MiB, GiB) since the artifacts span that range.

import type { Command } from 'commander';
import { type Dirent } from 'node:fs';
import { readdir, rm, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import {
  circuitCachePaths,
  resolveCacheRoot,
} from '../circuit/cache-paths.js';

interface CacheOptions {
  readonly circuit?: string;
}

export function cacheCommand(program: Command): void {
  const cache = program
    .command('cache')
    .description('Inspect or clear the qkb-cli cache directory.');

  cache
    .command('list', { isDefault: true })
    .description('List cached files + sizes (default).')
    .action(async () => {
      await listCache();
    });

  cache
    .command('clear')
    .description('Remove cached artifacts for one or all circuits.')
    .option('--circuit <id>', 'circuit version to wipe (e.g. v5.2). Defaults to all.')
    .action(async (rawOpts: CacheOptions) => {
      await clearCache(rawOpts.circuit);
    });
}

async function listCache(): Promise<void> {
  const root = resolveCacheRoot();
  process.stdout.write(`cache root: ${root}\n`);

  const entries: { path: string; size: number }[] = [];
  await collectFiles(root, entries);

  if (entries.length === 0) {
    process.stdout.write('  (empty)\n');
    return;
  }

  // Pretty-print: relative path + human size, right-aligned size.
  const formatted = entries.map((e) => ({
    rel: relative(root, e.path),
    size: humanBytes(e.size),
  }));
  const widest = Math.max(...formatted.map((f) => f.rel.length));
  for (const { rel, size } of formatted) {
    process.stdout.write(`  ${rel.padEnd(widest)}  ${size}\n`);
  }
}

async function clearCache(circuitVersion?: string): Promise<void> {
  if (circuitVersion === undefined) {
    // Wipe entire cache root.
    const root = resolveCacheRoot();
    await rm(root, { recursive: true, force: true });
    process.stdout.write(`removed entire cache: ${root}\n`);
    return;
  }
  const paths = circuitCachePaths(circuitVersion);
  let removedAny = false;
  for (const target of [paths.zkey, paths.zkeyTmp, paths.wasm, paths.vkey]) {
    try {
      await stat(target);
      await rm(target, { force: true });
      process.stdout.write(`removed: ${target}\n`);
      removedAny = true;
    } catch {
      // File not present; nothing to do.
    }
  }
  if (!removedAny) {
    process.stdout.write(`no cached files found for circuit ${circuitVersion}\n`);
  }
}

async function collectFiles(
  dir: string,
  out: { path: string; size: number }[],
): Promise<void> {
  let entries: Dirent[];
  try {
    // Node 20 typings have a polymorphic `readdir` overload set; the
    // string-name flavour is what we need here, but the TS inference
    // picks Dirent<NonSharedBuffer> when `withFileTypes: true` alone
    // is supplied.  Cast at the call site to the string variant.
    entries = (await readdir(dir, { withFileTypes: true })) as unknown as Dirent[];
  } catch {
    return; // Cache root doesn't exist yet — first-run case.
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      await collectFiles(full, out);
    } else if (entry.isFile()) {
      const s = await stat(full);
      out.push({ path: full, size: s.size });
    }
  }
}

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(2)} ${units[unit]}`;
}
