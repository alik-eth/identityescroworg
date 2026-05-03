// Unit tests for `detectCli` — the CLI server presence probe used by
// `useCliPresence` at /v5/registerV5 mount + on tab visibility change.
//
// Tests pin:
//   - timeout (500 ms) — slow servers are treated as absent
//   - circuit gate ('v5.2' only — V5.1 helper rejected)
//   - readiness gate (zkeyLoaded:false rejected — first-run download)
//   - shape gate (malformed JSON / non-object body rejected)
//   - HTTP error (non-2xx) rejected
//   - network error (ECONNREFUSED, abort) rejected uniformly
import { afterEach, describe, expect, it, vi } from 'vitest';
import { detectCli } from './detectCli.js';

const VALID_STATUS = {
  ok: true,
  version: 'qkb-cli@1.0.0',
  circuit: 'v5.2',
  zkeyLoaded: true,
  busy: false,
  provesCompleted: 0,
  uptimeSec: 12,
  downloadProgress: null,
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('detectCli', () => {
  it('returns null when /status is unreachable (network error)', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(
      new TypeError('Failed to fetch'),
    );
    expect(await detectCli()).toBeNull();
  });

  it('returns null when /status hangs past the 500 ms timeout', async () => {
    // A fetch that never resolves on its own — only the AbortController
    // signal cancels it. We assert resolution-to-null within a tight
    // bound; if AbortController isn't wired correctly this hangs forever
    // and vitest fails the suite via its outer timeout.
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(new DOMException('aborted', 'AbortError'));
          });
        }),
    );
    const start = Date.now();
    const result = await detectCli();
    const elapsed = Date.now() - start;
    expect(result).toBeNull();
    // 500 ms timeout + a little jitter buffer
    expect(elapsed).toBeLessThan(1500);
  });

  it('returns null on non-2xx HTTP response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('error', { status: 500 }),
    );
    expect(await detectCli()).toBeNull();
  });

  it('returns CliStatus when /status returns a valid v5.2-ready payload', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(VALID_STATUS), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const status = await detectCli();
    expect(status).toMatchObject({
      ok: true,
      circuit: 'v5.2',
      zkeyLoaded: true,
      version: 'qkb-cli@1.0.0',
    });
  });

  it('rejects a status response with the wrong circuit', async () => {
    // V5.1 helper still listening on :9080 from a previous setup — we
    // do NOT want to silently take it over for the V5.2 register flow.
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({ ...VALID_STATUS, circuit: 'v5.1' }),
        { status: 200 },
      ),
    );
    expect(await detectCli()).toBeNull();
  });

  it('rejects a status response with zkeyLoaded:false (first-run download)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          ...VALID_STATUS,
          zkeyLoaded: false,
          downloadProgress: { downloadedBytes: 1_000_000, totalBytes: 2_000_000_000 },
        }),
        { status: 200 },
      ),
    );
    expect(await detectCli()).toBeNull();
  });

  it('rejects malformed JSON body', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('not json at all', { status: 200 }),
    );
    expect(await detectCli()).toBeNull();
  });

  it('rejects a JSON body that is not an object', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify('just a string'), { status: 200 }),
    );
    expect(await detectCli()).toBeNull();
  });

  it('rejects a CliStatus with missing required fields', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({ ok: true, circuit: 'v5.2' }),
        { status: 200 },
      ),
    );
    expect(await detectCli()).toBeNull();
  });

  it('rejects a CliStatus where `ok` is not a boolean', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({ ...VALID_STATUS, ok: 'true' }),
        { status: 200 },
      ),
    );
    expect(await detectCli()).toBeNull();
  });
});
