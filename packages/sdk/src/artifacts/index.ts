/**
 * urls.json loader + SHA-256-verified artifact fetcher with cache.
 *
 * Per orchestration §4.0 (committed in 2cf1517) the SPA fetches the Groth16
 * `.wasm` and `.zkey` from a public CDN at runtime. The repo only commits
 * `urls.json` — the binary blobs themselves never enter git.
 *
 * Trust model:
 *   1. urls.json is committed to the repo and shipped inside the SPA bundle.
 *      Tampering with it requires a code change (PR-reviewed).
 *   2. We download the wasm + zkey from the URLs in urls.json.
 *   3. We hash the downloaded bytes with SHA-256 and compare against the
 *      `wasmSha256` / `zkeySha256` recorded in urls.json. Mismatch ⇒
 *      ZkqesError('prover.artifactMismatch'). This catches CDN poisoning and
 *      partial downloads.
 *   4. Verified bytes are stored in CacheStorage keyed by sha256 (not URL),
 *      so a future urls.json update with a new sha invalidates automatically
 *      and a CDN-side mutation under the same URL never reaches the prover.
 *
 * The fetcher is injectable so tests can drive happy + tamper + cache-hit
 * paths without hitting the network.
 */
import type { AlgorithmTag } from '../cert/cades.js';
import { ALGORITHM_TAG_RSA, ALGORITHM_TAG_ECDSA } from '../cert/cades.js';
import { ZkqesError } from '../errors/index.js';

export type CircuitVariant = 'rsa' | 'ecdsa';

export interface UrlsJson {
  variant: CircuitVariant;
  wasmUrl: string;
  zkeyUrl: string;
  wasmSha256: string;
  zkeySha256: string;
  uploadedAt?: string;
  circuitVersion?: string;
}

interface ArtifactDescriptor {
  url: string;
  sha256: string;
}

export interface LoadedArtifacts {
  wasmBytes: Uint8Array;
  zkeyBytes: Uint8Array;
  wasmSha256: string;
  zkeySha256: string;
  circuitVersion: string;
}

export type Fetcher = (url: string) => Promise<ArrayBuffer>;

export interface ArtifactCache {
  get(key: string): Promise<Uint8Array | undefined>;
  put(key: string, bytes: Uint8Array): Promise<void>;
}

export interface LoadOptions {
  fetcher?: Fetcher;
  cache?: ArtifactCache;
  signal?: AbortSignal;
}

const CACHE_NAME = 'zkqes-circuit-artifacts-v1';

export function variantForAlgorithmTag(tag: AlgorithmTag): CircuitVariant {
  if (tag === ALGORITHM_TAG_RSA) return 'rsa';
  if (tag === ALGORITHM_TAG_ECDSA) return 'ecdsa';
  throw new ZkqesError('prover.artifactMismatch', { reason: 'unknown-algorithm-tag', tag });
}

/**
 * Phase-2 dual-variant urls.json schema (orchestration §0 S0.3).
 *
 * Phase-1 urls.json pinned a single variant at the top level. Phase-2
 * ships two ceremony artifacts (one RSA, one unified ECDSA) and the SPA
 * picks between them at runtime based on the detected leaf cert's
 * algorithmTag. The dual-variant file nests one UrlsJson under each
 * `rsa`/`ecdsa` key:
 *
 *   {
 *     "rsa":   { "wasmUrl": "...", "zkeyUrl": "...", "wasmSha256": "...", "zkeySha256": "..." },
 *     "ecdsa": { "wasmUrl": "...", "zkeyUrl": "...", "wasmSha256": "...", "zkeySha256": "..." }
 *   }
 *
 * For backward-compat with the Phase-1 single-variant file that ships in
 * the SPA bundle today, `pickVariantUrls` accepts either shape and dispatches
 * to the requested variant.
 */
export interface DualUrlsJson {
  rsa: UrlsJson;
  ecdsa: UrlsJson;
}

/**
 * Pick the UrlsJson for the requested variant out of a file that may be
 * either the Phase-1 single-variant shape or the Phase-2 dual-variant shape.
 * Throws prover.artifactMismatch when the requested variant is absent.
 */
export function pickVariantUrls(
  raw: unknown,
  wanted: CircuitVariant,
): UrlsJson {
  if (!isRecord(raw)) {
    throw new ZkqesError('prover.artifactMismatch', { reason: 'urls-not-object' });
  }
  // Dual-variant shape: top-level has `rsa` + `ecdsa` keys.
  if ('rsa' in raw && 'ecdsa' in raw) {
    const entry = raw[wanted];
    if (!isRecord(entry)) {
      throw new ZkqesError('prover.artifactMismatch', {
        reason: 'urls-variant-missing',
        wanted,
      });
    }
    // Pin the inner object's variant for downstream validation.
    const withVariant = { ...entry, variant: wanted } as Record<string, unknown>;
    return validateUrlsJson(withVariant, wanted);
  }
  // Single-variant fallback (Phase-1 shape).
  return validateUrlsJson(raw, wanted);
}

export function validateUrlsJson(raw: unknown, expectedVariant?: CircuitVariant): UrlsJson {
  if (!isRecord(raw)) {
    throw new ZkqesError('prover.artifactMismatch', { reason: 'urls-not-object' });
  }
  const variant = raw.variant;
  if (variant !== 'rsa' && variant !== 'ecdsa') {
    throw new ZkqesError('prover.artifactMismatch', { reason: 'urls-bad-variant', variant });
  }
  if (expectedVariant && variant !== expectedVariant) {
    throw new ZkqesError('prover.artifactMismatch', {
      reason: 'urls-variant-mismatch',
      want: expectedVariant,
      got: variant,
    });
  }
  validateUrl(raw.wasmUrl, 'wasmUrl');
  validateUrl(raw.zkeyUrl, 'zkeyUrl');
  validateSha(raw.wasmSha256, 'wasmSha256');
  validateSha(raw.zkeySha256, 'zkeySha256');
  return raw as unknown as UrlsJson;
}

export async function loadArtifacts(
  variant: CircuitVariant,
  urls: UrlsJson,
  opts: LoadOptions = {},
): Promise<LoadedArtifacts> {
  validateUrlsJson(urls, variant);
  const fetcher = opts.fetcher ?? defaultFetcher;
  const cache = opts.cache ?? (await defaultCache());

  const [wasmBytes, zkeyBytes] = await Promise.all([
    fetchAndVerify({ url: urls.wasmUrl, sha256: urls.wasmSha256 }, fetcher, cache, opts.signal),
    fetchAndVerify({ url: urls.zkeyUrl, sha256: urls.zkeySha256 }, fetcher, cache, opts.signal),
  ]);

  return {
    wasmBytes,
    zkeyBytes,
    wasmSha256: stripHex(urls.wasmSha256),
    zkeySha256: stripHex(urls.zkeySha256),
    circuitVersion: urls.circuitVersion ?? 'unknown',
  };
}

async function fetchAndVerify(
  desc: ArtifactDescriptor,
  fetcher: Fetcher,
  cache: ArtifactCache,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  throwIfAborted(signal);
  const want = stripHex(desc.sha256);
  const cached = await cache.get(want);
  if (cached) {
    const ok = await verifySha(cached, want);
    if (ok) return cached;
    // Cache hit but hash didn't match — drop and re-fetch.
  }
  throwIfAborted(signal);
  const ab = await fetcher(desc.url);
  const bytes = new Uint8Array(ab);
  const ok = await verifySha(bytes, want);
  if (!ok) {
    throw new ZkqesError('prover.artifactMismatch', {
      url: desc.url,
      want,
      got: await sha256Hex(bytes),
    });
  }
  await cache.put(want, bytes);
  return bytes;
}

function stripHex(s: string): string {
  return (s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s).toLowerCase();
}

async function verifySha(bytes: Uint8Array, want: string): Promise<boolean> {
  const got = await sha256Hex(bytes);
  return got === want.toLowerCase();
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', toAB(bytes));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

const defaultFetcher: Fetcher = async (url) => {
  const res = await fetch(url);
  if (!res.ok) {
    throw new ZkqesError('prover.artifactMismatch', {
      reason: 'fetch-status',
      url,
      status: res.status,
    });
  }
  return res.arrayBuffer();
};

class CacheStorageBackend implements ArtifactCache {
  constructor(private readonly cache: Cache) {}
  async get(key: string): Promise<Uint8Array | undefined> {
    const res = await this.cache.match(keyUrl(key));
    if (!res) return undefined;
    return new Uint8Array(await res.arrayBuffer());
  }
  async put(key: string, bytes: Uint8Array): Promise<void> {
    await this.cache.put(keyUrl(key), new Response(toAB(bytes)));
  }
}

class MemoryBackend implements ArtifactCache {
  private store = new Map<string, Uint8Array>();
  async get(key: string): Promise<Uint8Array | undefined> {
    return this.store.get(key);
  }
  async put(key: string, bytes: Uint8Array): Promise<void> {
    this.store.set(key, bytes);
  }
}

async function defaultCache(): Promise<ArtifactCache> {
  if (typeof caches !== 'undefined') {
    try {
      const c = await caches.open(CACHE_NAME);
      return new CacheStorageBackend(c);
    } catch {
      // fall through to memory
    }
  }
  return new MemoryBackend();
}

function keyUrl(sha: string): string {
  return `https://qkb.cache/${sha}`;
}

function validateUrl(value: unknown, field: string): void {
  if (typeof value !== 'string' || value.length === 0) {
    throw new ZkqesError('prover.artifactMismatch', { reason: 'urls-bad-url', field });
  }
}

function validateSha(value: unknown, field: string): void {
  if (typeof value !== 'string') {
    throw new ZkqesError('prover.artifactMismatch', { reason: 'urls-bad-sha', field });
  }
  const stripped = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(stripped)) {
    throw new ZkqesError('prover.artifactMismatch', { reason: 'urls-bad-sha', field });
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new ZkqesError('prover.cancelled');
}

function toAB(b: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  return ab;
}
