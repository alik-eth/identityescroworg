import { describe, expect, it, vi } from 'vitest';
import {
  loadArtifacts,
  validateUrlsJson,
  variantForAlgorithmTag,
  type ArtifactCache,
  type Fetcher,
  type UrlsJson,
} from '../../src/lib/circuitArtifacts';

const WASM = new TextEncoder().encode('test-wasm-bytes');
const ZKEY = new TextEncoder().encode('test-zkey-bytes');

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

async function shaHex(b: Uint8Array): Promise<string> {
  const ab = new ArrayBuffer(b.byteLength);
  new Uint8Array(ab).set(b);
  const h = await crypto.subtle.digest('SHA-256', ab);
  return Array.from(new Uint8Array(h), (x) => x.toString(16).padStart(2, '0')).join('');
}

async function makeUrls(variant: 'rsa' | 'ecdsa' = 'rsa'): Promise<UrlsJson> {
  return {
    variant,
    wasmUrl: 'https://utfs.io/f/wasm-key',
    zkeyUrl: 'https://utfs.io/f/zkey-key',
    wasmSha256: `0x${await shaHex(WASM)}`,
    zkeySha256: `0x${await shaHex(ZKEY)}`,
    uploadedAt: '2026-04-17T03:00:00.000Z',
    circuitVersion: 'qkb-presentation-v1',
  };
}

class MemCache implements ArtifactCache {
  store = new Map<string, Uint8Array>();
  async get(k: string) {
    return this.store.get(k);
  }
  async put(k: string, v: Uint8Array) {
    this.store.set(k, v);
  }
}

describe('validateUrlsJson', () => {
  it('accepts a well-formed urls.json', async () => {
    const u = await makeUrls();
    expect(validateUrlsJson(u)).toEqual(u);
  });

  it('rejects unknown variant', () => {
    expect(() => validateUrlsJson({ ...({ variant: 'dsa' } as unknown as UrlsJson) })).toThrowError(
      expect.objectContaining({ code: 'prover.artifactMismatch' }) as unknown as Error,
    );
  });

  it('rejects when expectedVariant disagrees', async () => {
    const u = await makeUrls('rsa');
    expect(() => validateUrlsJson(u, 'ecdsa')).toThrowError(
      expect.objectContaining({ code: 'prover.artifactMismatch' }) as unknown as Error,
    );
  });

  it('rejects bad sha format', async () => {
    const u = await makeUrls();
    expect(() => validateUrlsJson({ ...u, wasmSha256: 'not-hex' })).toThrowError(
      expect.objectContaining({ code: 'prover.artifactMismatch' }) as unknown as Error,
    );
  });

  it('rejects empty wasmUrl', async () => {
    const u = await makeUrls();
    expect(() => validateUrlsJson({ ...u, wasmUrl: '' })).toThrowError(
      expect.objectContaining({ code: 'prover.artifactMismatch' }) as unknown as Error,
    );
  });
});

describe('variantForAlgorithmTag', () => {
  it('maps tag 0 → rsa, 1 → ecdsa', () => {
    expect(variantForAlgorithmTag(0)).toBe('rsa');
    expect(variantForAlgorithmTag(1)).toBe('ecdsa');
  });
});

describe('loadArtifacts', () => {
  it('happy path: fetches both blobs, verifies sha, populates cache', async () => {
    const u = await makeUrls();
    const cache = new MemCache();
    const fetcher: Fetcher = vi.fn(async (url) => {
      if (url === u.wasmUrl) return WASM.buffer.slice(0);
      if (url === u.zkeyUrl) return ZKEY.buffer.slice(0);
      throw new Error('unexpected url ' + url);
    });
    const out = await loadArtifacts('rsa', u, { fetcher, cache });
    expect(toHex(out.wasmBytes)).toBe(toHex(WASM));
    expect(toHex(out.zkeyBytes)).toBe(toHex(ZKEY));
    expect(out.circuitVersion).toBe('qkb-presentation-v1');
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(cache.store.size).toBe(2);
  });

  it('cache hit: skips fetcher entirely on second call', async () => {
    const u = await makeUrls();
    const cache = new MemCache();
    const fetcher = vi.fn(async (url: string) => {
      if (url === u.wasmUrl) return WASM.buffer.slice(0);
      if (url === u.zkeyUrl) return ZKEY.buffer.slice(0);
      throw new Error('x');
    });
    await loadArtifacts('rsa', u, { fetcher, cache });
    fetcher.mockClear();
    await loadArtifacts('rsa', u, { fetcher, cache });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('throws prover.artifactMismatch when downloaded sha disagrees', async () => {
    const u = await makeUrls();
    const cache = new MemCache();
    const tampered = new TextEncoder().encode('TAMPERED');
    const fetcher: Fetcher = async (url) => {
      if (url === u.wasmUrl) return tampered.buffer.slice(0);
      return ZKEY.buffer.slice(0);
    };
    await expect(loadArtifacts('rsa', u, { fetcher, cache })).rejects.toMatchObject({
      code: 'prover.artifactMismatch',
    });
    // No tampered bytes were cached.
    expect(cache.store.size).toBeLessThanOrEqual(1);
  });

  it('treats a poisoned cache entry as a miss and re-fetches', async () => {
    const u = await makeUrls();
    const cache = new MemCache();
    cache.store.set(
      (u.wasmSha256.slice(2) as string).toLowerCase(),
      new TextEncoder().encode('GARBAGE'),
    );
    cache.store.set(
      (u.zkeySha256.slice(2) as string).toLowerCase(),
      new TextEncoder().encode('GARBAGE'),
    );
    const fetcher = vi.fn(async (url: string) => {
      if (url === u.wasmUrl) return WASM.buffer.slice(0);
      if (url === u.zkeyUrl) return ZKEY.buffer.slice(0);
      throw new Error('x');
    });
    const out = await loadArtifacts('rsa', u, { fetcher, cache });
    expect(toHex(out.wasmBytes)).toBe(toHex(WASM));
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('honors AbortSignal before any fetch', async () => {
    const u = await makeUrls();
    const ctrl = new AbortController();
    ctrl.abort();
    const fetcher: Fetcher = vi.fn(async () => WASM.buffer.slice(0));
    await expect(
      loadArtifacts('rsa', u, { fetcher, cache: new MemCache(), signal: ctrl.signal }),
    ).rejects.toMatchObject({ code: 'prover.cancelled' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('rejects loading when expected variant disagrees with urls.json', async () => {
    const u = await makeUrls('rsa');
    await expect(
      loadArtifacts('ecdsa', u, { fetcher: async () => WASM.buffer.slice(0), cache: new MemCache() }),
    ).rejects.toMatchObject({ code: 'prover.artifactMismatch' });
  });
});
