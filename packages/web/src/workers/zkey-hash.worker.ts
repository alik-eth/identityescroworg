/// <reference lib="webworker" />
/**
 * SHA-256 over a (potentially multi-GB) zkey blob.
 *
 * Runs in a Web Worker so the main thread doesn't freeze for the
 * minute-or-two it takes to digest 2.2 GB. We stream the file via
 * `Blob.stream() → ReadableStreamDefaultReader.read()` and feed each
 * chunk into a single-pass `@noble/hashes/sha2` digest, so peak heap
 * stays bounded by the chunk size (~64 KB) rather than the file size.
 *
 * Protocol:
 *   inbound:  { kind: 'hash'; id: number; file: File }
 *   outbound: { kind: 'progress'; id; pct } |
 *             { kind: 'result';   id; sha256Hex } |
 *             { kind: 'error';    id; message }
 */
import { sha256 } from '@noble/hashes/sha2';

interface HashRequest {
  kind: 'hash';
  id: number;
  file: File;
}

type WorkerScope = {
  addEventListener<K extends 'message'>(
    type: K,
    listener: (e: MessageEvent<HashRequest>) => void,
  ): void;
  postMessage(data: unknown): void;
};
declare const self: WorkerScope;

self.addEventListener('message', (e) => {
  const msg = e.data;
  if (msg?.kind !== 'hash') return;
  void run(msg);
});

async function run(req: HashRequest): Promise<void> {
  try {
    const total = req.file.size;
    let read = 0;
    const hasher = sha256.create();
    const reader = req.file.stream().getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      hasher.update(value);
      read += value.byteLength;
      const pct = total > 0 ? Math.min(99, Math.floor((read / total) * 100)) : 0;
      self.postMessage({ kind: 'progress', id: req.id, pct });
    }
    const digest = hasher.digest();
    let hex = '';
    for (let i = 0; i < digest.length; i++) {
      hex += digest[i]!.toString(16).padStart(2, '0');
    }
    self.postMessage({ kind: 'result', id: req.id, sha256Hex: hex });
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    self.postMessage({ kind: 'error', id: req.id, message });
  }
}
