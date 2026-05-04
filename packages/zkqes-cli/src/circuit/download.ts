// `downloadAndVerify` — fetches an artifact (zkey, wasm, vkey) to the
// cache directory, computing sha256 incrementally during the stream
// and atomically renaming `.tmp → final` on success.
//
// Failure modes (all surfaced via DownloadError):
//   - HTTP 4xx/5xx → DownloadError with status code
//   - sha256 mismatch → DownloadError, .tmp file deleted
//   - filesystem ENOSPC mid-stream → DownloadError, .tmp file deleted
//
// Atomicity invariant: the FINAL filename only ever contains
// sha256-verified bytes.  An interrupted download leaves either no
// final file (if download/verify failed) or a complete verified file
// (if download/verify succeeded).  Never a half-file at the final
// path.  Achieved via write-to-tmp + atomic rename.
//
// Schemes supported: http://, https://, file:// (file:// for dev
// against locally-cached fixtures; production zkey URLs are HTTPS).

import { createHash } from 'node:crypto';
import { mkdir, rename, rm, stat } from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { dirname } from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

export class DownloadError extends Error {
  public override readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'DownloadError';
    this.cause = cause;
  }
}

export interface DownloadInput {
  /** URL to fetch (http://, https://, or file://). */
  readonly url: string;
  /** Expected lowercase-hex sha256 of the downloaded bytes. */
  readonly expectedSha256: string;
  /** Final on-disk path for the verified file. */
  readonly destinationPath: string;
  /** Working file used during streaming.  Atomic-mv'd to `destinationPath` on verify-ok. */
  readonly tempPath: string;
  /** Optional progress callback — invoked at most every ~250 ms with cumulative bytes. */
  readonly onProgress?: (downloadedBytes: number, totalBytes: number | null) => void;
}

export interface DownloadResult {
  readonly bytesWritten: number;
  readonly sha256: string;
  readonly destinationPath: string;
}

export async function downloadAndVerify(
  input: DownloadInput,
): Promise<DownloadResult> {
  // Short-circuit if the destination already exists with the matching
  // sha256.  Re-running `zkqes serve` against an unchanged manifest
  // shouldn't re-download.
  if (await fileExists(input.destinationPath)) {
    const existingHash = await sha256OfFile(input.destinationPath);
    if (existingHash === input.expectedSha256) {
      const s = await stat(input.destinationPath);
      return {
        bytesWritten: s.size,
        sha256: existingHash,
        destinationPath: input.destinationPath,
      };
    }
    // Hash mismatch — could be a partial-overwrite from a previous
    // crash or a manifest change.  Delete and re-download.
    await rm(input.destinationPath, { force: true });
  }

  await mkdir(dirname(input.destinationPath), { recursive: true });
  await mkdir(dirname(input.tempPath), { recursive: true });
  // Wipe any leftover .tmp from a previous interrupted download.
  await rm(input.tempPath, { force: true });

  const hash = createHash('sha256');
  let bytesWritten = 0;
  let totalBytes: number | null = null;
  let lastProgressEmit = 0;

  try {
    const sourceStream = await openSourceStream(input.url, (size) => {
      totalBytes = size;
    });

    const destStream = createWriteStream(input.tempPath, { flags: 'w' });

    // Manual stream pump that hashes and writes simultaneously.
    // Could express as a Transform stream but Transform's error
    // semantics are subtle when the writer errors mid-flight;
    // explicit loop with backpressure is easier to reason about.
    await new Promise<void>((resolve, reject) => {
      sourceStream.on('data', (raw: string | Buffer) => {
        // createReadStream + http body Readable both yield Buffer chunks
        // unless an encoding was set (we never set one).  The string
        // branch is unreachable but TS types are defensively wide.
        const chunk = typeof raw === 'string' ? Buffer.from(raw) : raw;
        hash.update(chunk);
        bytesWritten += chunk.byteLength;
        const ok = destStream.write(chunk);
        if (!ok) {
          // Backpressure — pause source until drain.
          sourceStream.pause();
        }
        const now = Date.now();
        if (input.onProgress && now - lastProgressEmit >= 250) {
          lastProgressEmit = now;
          input.onProgress(bytesWritten, totalBytes);
        }
      });
      destStream.on('drain', () => sourceStream.resume());
      sourceStream.on('end', () => {
        destStream.end((err?: Error | null) => {
          if (err) reject(err);
          else resolve();
        });
      });
      sourceStream.on('error', reject);
      destStream.on('error', reject);
    });

    const actualHash = hash.digest('hex');
    if (actualHash !== input.expectedSha256) {
      throw new DownloadError(
        `sha256 mismatch for ${input.url}: expected ${input.expectedSha256}, got ${actualHash}`,
      );
    }

    // Final progress emit (in case onProgress hadn't fired in the
    // last 250 ms before stream end).
    if (input.onProgress) input.onProgress(bytesWritten, totalBytes);

    await rename(input.tempPath, input.destinationPath);

    return {
      bytesWritten,
      sha256: actualHash,
      destinationPath: input.destinationPath,
    };
  } catch (err) {
    // Best-effort cleanup of the .tmp file; don't shadow the original
    // error if cleanup fails.
    await rm(input.tempPath, { force: true }).catch(() => {});
    if (err instanceof DownloadError) throw err;
    throw new DownloadError(
      `download failed for ${input.url}: ${err instanceof Error ? err.message : String(err)}`,
      err,
    );
  }
}

async function openSourceStream(
  url: string,
  setSize: (size: number | null) => void,
): Promise<Readable> {
  if (url.startsWith('file://')) {
    const path = fileURLToPath(url);
    const s = await stat(path);
    setSize(s.size);
    return createReadStream(path);
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    throw new DownloadError(`unsupported URL scheme: ${url}`);
  }
  const res = await fetch(url, { redirect: 'follow', credentials: 'omit' });
  if (!res.ok) {
    throw new DownloadError(`HTTP ${res.status} fetching ${url}`);
  }
  const lenHdr = res.headers.get('content-length');
  setSize(lenHdr !== null ? Number(lenHdr) : null);
  if (!res.body) {
    throw new DownloadError(`response body missing for ${url}`);
  }
  // ReadableStream<Uint8Array> → node Readable.  fromWeb is in Node 18+.
  return Readable.fromWeb(res.body as unknown as import('stream/web').ReadableStream<Uint8Array>);
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function sha256OfFile(path: string): Promise<string> {
  const hash = createHash('sha256');
  const stream = createReadStream(path);
  return new Promise((resolve, reject) => {
    stream.on('data', (raw: string | Buffer) => {
      hash.update(typeof raw === 'string' ? Buffer.from(raw) : raw);
    });
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}
