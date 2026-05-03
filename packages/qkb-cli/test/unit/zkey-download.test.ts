// Download + sha256-verify + atomic-rename unit tests.
//
// Stand up a tiny in-process HTTP server that serves a synthetic
// 5-MiB blob, verify the cache lifecycle: stream → hash incrementally
// → rename .tmp → final on sha-match; reject with cleanup on
// sha-mismatch; short-circuit on already-cached-and-correct.
//
// Tests stay deterministic by computing the expected sha256 over the
// synthetic blob at setup time, not hardcoding a hash.

import { createHash, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DownloadError, downloadAndVerify } from '../../src/circuit/download.js';

const BLOB_SIZE_BYTES = 5 * 1024 * 1024; // 5 MiB

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

describe('downloadAndVerify', () => {
  let tmp: string;
  let blob: Buffer;
  let blobSha: string;
  let server: Server;
  let serverUrl: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), 'qkb-cli-dl-test-'));
    blob = randomBytes(BLOB_SIZE_BYTES);
    blobSha = sha256Hex(blob);

    server = createServer((req, res) => {
      if (req.url === '/blob.bin') {
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', String(blob.byteLength));
        res.end(blob);
        return;
      }
      if (req.url === '/blob-truncated.bin') {
        // Server returns content-length larger than what it actually
        // sends — simulates a flaky network producing a partial body
        // that should fail sha-verify.
        res.setHeader('Content-Length', String(blob.byteLength));
        res.end(blob.subarray(0, 1024));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address();
    if (typeof addr !== 'object' || addr === null) throw new Error('no addr');
    serverUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(tmp, { recursive: true, force: true });
  });

  it('streams + verifies + atomic-renames a well-formed blob', async () => {
    const dest = join(tmp, 'circuits', 'qkb.zkey');
    const tempPath = join(tmp, 'circuits', 'qkb.zkey.tmp');

    const result = await downloadAndVerify({
      url: `${serverUrl}/blob.bin`,
      expectedSha256: blobSha,
      destinationPath: dest,
      tempPath,
    });

    expect(result.bytesWritten).toBe(BLOB_SIZE_BYTES);
    expect(result.sha256).toBe(blobSha);
    expect(result.destinationPath).toBe(dest);

    // Final file present, .tmp wiped.
    expect(existsSync(dest)).toBe(true);
    expect(existsSync(tempPath)).toBe(false);

    // On-disk content matches.
    const onDisk = await readFile(dest);
    expect(onDisk.byteLength).toBe(BLOB_SIZE_BYTES);
    expect(sha256Hex(onDisk)).toBe(blobSha);
  });

  it('rejects with sha mismatch and cleans up .tmp', async () => {
    const dest = join(tmp, 'circuits', 'qkb.zkey');
    const tempPath = join(tmp, 'circuits', 'qkb.zkey.tmp');

    await expect(
      downloadAndVerify({
        url: `${serverUrl}/blob.bin`,
        expectedSha256:
          '0000000000000000000000000000000000000000000000000000000000000000',
        destinationPath: dest,
        tempPath,
      }),
    ).rejects.toBeInstanceOf(DownloadError);

    // No final file; no leftover .tmp.
    expect(existsSync(dest)).toBe(false);
    expect(existsSync(tempPath)).toBe(false);
  });

  it('short-circuits on already-cached-and-matching destination', async () => {
    const dest = join(tmp, 'circuits', 'qkb.zkey');
    const tempPath = join(tmp, 'circuits', 'qkb.zkey.tmp');

    // Pre-populate the destination with the correct content.
    await writeFile(dest, blob).catch(async () => {
      // First write requires the dir; create it.
      const { mkdir } = await import('node:fs/promises');
      await mkdir(join(tmp, 'circuits'), { recursive: true });
      await writeFile(dest, blob);
    });

    // Use a URL that DOESN'T resolve (would 404) — short-circuit
    // means the download function should not attempt the network.
    const result = await downloadAndVerify({
      url: `${serverUrl}/this-would-404`,
      expectedSha256: blobSha,
      destinationPath: dest,
      tempPath,
    });

    expect(result.sha256).toBe(blobSha);
    expect(result.bytesWritten).toBe(BLOB_SIZE_BYTES);
  });

  it('replaces stale cache when destination exists with WRONG sha', async () => {
    const dest = join(tmp, 'circuits', 'qkb.zkey');
    const tempPath = join(tmp, 'circuits', 'qkb.zkey.tmp');

    const { mkdir } = await import('node:fs/promises');
    await mkdir(join(tmp, 'circuits'), { recursive: true });
    // Old cached content with the wrong hash.
    await writeFile(dest, Buffer.from('stale cache content'));

    const result = await downloadAndVerify({
      url: `${serverUrl}/blob.bin`,
      expectedSha256: blobSha,
      destinationPath: dest,
      tempPath,
    });

    expect(result.sha256).toBe(blobSha);
    const onDisk = await readFile(dest);
    expect(sha256Hex(onDisk)).toBe(blobSha);
  });

  it('emits onProgress callbacks during download', async () => {
    const dest = join(tmp, 'circuits', 'qkb.zkey');
    const tempPath = join(tmp, 'circuits', 'qkb.zkey.tmp');
    const observations: { downloaded: number; total: number | null }[] = [];

    await downloadAndVerify({
      url: `${serverUrl}/blob.bin`,
      expectedSha256: blobSha,
      destinationPath: dest,
      tempPath,
      onProgress: (downloaded, total) => {
        observations.push({ downloaded, total });
      },
    });

    expect(observations.length).toBeGreaterThan(0);
    const last = observations[observations.length - 1]!;
    expect(last.downloaded).toBe(BLOB_SIZE_BYTES);
    // 5 MiB blob streams in one HTTP response, server sets
    // Content-Length, so total is known.
    expect(last.total).toBe(BLOB_SIZE_BYTES);
  });

  it('rejects unsupported URL schemes', async () => {
    const dest = join(tmp, 'circuits', 'qkb.zkey');
    const tempPath = join(tmp, 'circuits', 'qkb.zkey.tmp');

    await expect(
      downloadAndVerify({
        url: 'ftp://malicious.example.com/blob.bin',
        expectedSha256: blobSha,
        destinationPath: dest,
        tempPath,
      }),
    ).rejects.toBeInstanceOf(DownloadError);
  });

  it('handles file:// URLs (dev manifest case)', async () => {
    // Write the blob to a local file, then download from file://URL.
    const sourcePath = join(tmp, 'source-blob.bin');
    await writeFile(sourcePath, blob);

    const dest = join(tmp, 'circuits', 'qkb.zkey');
    const tempPath = join(tmp, 'circuits', 'qkb.zkey.tmp');

    const result = await downloadAndVerify({
      url: `file://${sourcePath}`,
      expectedSha256: blobSha,
      destinationPath: dest,
      tempPath,
    });

    expect(result.sha256).toBe(blobSha);
    expect(result.bytesWritten).toBe(BLOB_SIZE_BYTES);
  });
});
