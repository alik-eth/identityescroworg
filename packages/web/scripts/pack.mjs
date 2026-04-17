#!/usr/bin/env node
// Package the built dist/ tree into a self-contained tarball:
//
//   pnpm --filter @qkb/web run package
//
// Produces packages/web/qkb-web-<sha>.tar.gz (or qkb-web-dev.tar.gz when not in
// a git checkout). The tarball is sha-pinned so a release can ship a single
// file that opens identically from `python -m http.server` or `file://`.

import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, '..');
const distDir = join(pkgRoot, 'dist');
const releaseDir = join(pkgRoot, 'release');

if (!existsSync(distDir)) {
  console.error('error: dist/ not found — run `pnpm build` first');
  process.exit(1);
}

const sha = resolveSha();
mkdirSync(releaseDir, { recursive: true });
const tarball = join(releaseDir, `qkb-web-${sha}.tar.gz`);

const result = spawnSync(
  'tar',
  ['-czf', tarball, '-C', pkgRoot, 'dist'],
  { stdio: 'inherit' },
);
if (result.status !== 0) {
  console.error('error: tar failed');
  process.exit(result.status ?? 1);
}

const size = statSync(tarball).size;
const distFiles = walk(distDir).length;
console.log(
  `wrote ${tarball.replace(`${process.cwd()}/`, '')} (${(size / 1024).toFixed(1)} KB, ${distFiles} files)`,
);

function resolveSha() {
  try {
    return execFileSync('git', ['rev-parse', '--short', 'HEAD'], {
      cwd: pkgRoot,
      stdio: ['ignore', 'pipe', 'ignore'],
    })
      .toString()
      .trim();
  } catch {
    return 'dev';
  }
}

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const s = statSync(p);
    if (s.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}
