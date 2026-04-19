/**
 * Artifact cache + download + SHA-256 verification.
 *
 * The ceremony zkeys are multi-GB (leaf ≈ 4.47 GB, chain ≈ 2.00 GB) and
 * downloading them on every prove is a non-starter. Cache them once under
 * `$XDG_CACHE_HOME/qkb/` (fallback `$HOME/.cache/qkb/`) keyed by sha256 so a
 * zkey rotation forces a re-fetch automatically.
 *
 * SHA verification is mandatory — a CDN-mutated or half-downloaded zkey
 * silently produces invalid proofs that waste gas on-chain. We verify both on
 * download and on cache hit.
 */

import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, stat, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { homedir } from 'node:os';

export function defaultCacheDir(): string {
  const xdg = process.env.XDG_CACHE_HOME;
  if (xdg && xdg.length > 0) return join(xdg, 'qkb');
  return join(homedir(), '.cache', 'qkb');
}

export async function ensureArtifact(args: {
  url: string;
  expectedSha256: string;
  cacheDir: string;
  label: string; // human-readable for progress (e.g. "leaf zkey")
  onProgress?: (bytes: number, total: number | null) => void;
}): Promise<string> {
  const { url, expectedSha256, cacheDir, label, onProgress } = args;
  const target = join(cacheDir, expectedSha256.toLowerCase());
  await mkdir(dirname(target), { recursive: true });
  if (await exists(target)) {
    const actual = await sha256File(target);
    if (actual === expectedSha256.toLowerCase()) return target;
    // Cached file corrupted or expected hash changed; drop and re-fetch.
    await unlink(target);
  }
  await downloadTo(url, target, label, onProgress);
  const actual = await sha256File(target);
  if (actual !== expectedSha256.toLowerCase()) {
    await unlink(target);
    throw new Error(
      `sha256 mismatch for ${label} from ${url}: expected ${expectedSha256}, got ${actual}`,
    );
  }
  return target;
}

async function downloadTo(
  url: string,
  target: string,
  label: string,
  onProgress?: (bytes: number, total: number | null) => void,
): Promise<void> {
  const res = await fetch(url);
  if (!res.ok || !res.body) {
    throw new Error(`${label} fetch failed: ${res.status} ${res.statusText}`);
  }
  const totalHeader = res.headers.get('content-length');
  const total = totalHeader ? parseInt(totalHeader, 10) : null;
  let bytes = 0;
  const web = res.body as unknown as ReadableStream<Uint8Array>;
  const nodeStream = Readable.fromWeb(web as unknown as import('stream/web').ReadableStream);
  const out = createWriteStream(target);
  if (onProgress) {
    nodeStream.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      onProgress(bytes, total);
    });
  }
  await pipeline(nodeStream, out);
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

export async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  await pipeline(createReadStream(path), hash);
  return hash.digest('hex');
}
