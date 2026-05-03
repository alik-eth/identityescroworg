// Pipeline-level integration tests for the V5.4 CLI prove dispatch
// (orchestration §1.6 fallback discipline). Targets `runCliFirstProver`
// directly so we don't need to spin up the full pipeline (which
// requires real CMS bytes for parseP7s). The pipeline imports
// runCliFirstProver verbatim, so testing the helper covers the
// pipeline's CLI-vs-browser branch byte-for-byte.
//
// What's pinned that's NOT in `proveViaCli.test.ts` (SDK):
//   - source: 'cli' | 'browser' discriminator on the result
//   - `runBrowser` callback fires iff fallback path taken
//   - `onCliFallback` callback fires for {429, 5xx, 0, -1} but NOT 4xx
//   - `cliPresent: false` skips CLI entirely (no fetch, no callback)
//   - 4xx re-throws verbatim (browser would also fail; surface to user)
//   - 403 (origin pin) treated like 4xx (config issue, not transient)
import { describe, it, expect, afterEach, vi } from 'vitest';
import { CliProveError } from '@qkb/sdk';
import type { WitnessV5_2 } from '@qkb/sdk';
import { runCliFirstProver } from '../../src/lib/cliFallbackProver';

// Opaque stub — runCliFirstProver only forwards to proveViaCli, which
// JSON-stringifies the witness without introspection.
const STUB_WITNESS = { stub: 'witness' } as unknown as WitnessV5_2;

const VALID_PROVE_RESPONSE = {
  proof: {
    pi_a: ['1', '2', '1'],
    pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
    pi_c: ['7', '8', '1'],
    protocol: 'groth16',
    curve: 'bn128',
  },
  publicSignals: Array.from({ length: 22 }, (_, i) => String(i + 1)),
  verifyOk: true,
  timings: {
    wtnsCalculateSec: 0.1,
    groth16ProveSec: 12.5,
    groth16VerifySec: 0.05,
    totalSec: 12.65,
  },
};

const STUB_BROWSER_RESULT = {
  proofRaw: {
    pi_a: ['9', '10', '1'],
    pi_b: [['11', '12'], ['13', '14'], ['1', '0']],
    pi_c: ['15', '16', '1'],
    protocol: 'groth16',
    curve: 'bn128',
  },
  publicSignalsRaw: Array.from({ length: 22 }, (_, i) => String(100 + i)),
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('runCliFirstProver — happy paths', () => {
  it('cliPresent:true + 200 → source:"cli", browser NEVER invoked', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(VALID_PROVE_RESPONSE), { status: 200 }),
    );
    const runBrowser = vi.fn();
    const onCliFallback = vi.fn();
    const result = await runCliFirstProver(STUB_WITNESS, {
      cliPresent: true,
      onCliFallback,
      runBrowser,
    });
    expect(result.source).toBe('cli');
    expect(result.publicSignalsRaw).toHaveLength(22);
    expect(runBrowser).not.toHaveBeenCalled();
    expect(onCliFallback).not.toHaveBeenCalled();
  });

  it('cliPresent:false → source:"browser", fetch never called', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const runBrowser = vi.fn().mockResolvedValue(STUB_BROWSER_RESULT);
    const onCliFallback = vi.fn();
    const result = await runCliFirstProver(STUB_WITNESS, {
      cliPresent: false,
      onCliFallback,
      runBrowser,
    });
    expect(result.source).toBe('browser');
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(runBrowser).toHaveBeenCalledTimes(1);
    expect(onCliFallback).not.toHaveBeenCalled();
  });
});

describe('runCliFirstProver — fallback discipline (orchestration §1.6)', () => {
  it('cliPresent:true + 5xx → fallback to browser, callback fires with 500', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'rapidsnark crashed' }), {
        status: 500,
      }),
    );
    const runBrowser = vi.fn().mockResolvedValue(STUB_BROWSER_RESULT);
    const onCliFallback = vi.fn();
    const result = await runCliFirstProver(STUB_WITNESS, {
      cliPresent: true,
      onCliFallback,
      runBrowser,
    });
    expect(result.source).toBe('browser');
    expect(runBrowser).toHaveBeenCalledTimes(1);
    expect(onCliFallback).toHaveBeenCalledTimes(1);
    const err = onCliFallback.mock.calls[0]![0] as CliProveError;
    expect(err).toBeInstanceOf(CliProveError);
    expect(err.status).toBe(500);
  });

  it('cliPresent:true + 429 (transient busy) → fallback, NOT verbatim', async () => {
    // 429 is the load-bearing case. Without the fix in 55bc602 the
    // user would get stuck on a "CLI busy" toast when the obvious
    // recovery (browser prove) just works.
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'CLI busy with another prove' }), {
        status: 429,
      }),
    );
    const runBrowser = vi.fn().mockResolvedValue(STUB_BROWSER_RESULT);
    const onCliFallback = vi.fn();
    const result = await runCliFirstProver(STUB_WITNESS, {
      cliPresent: true,
      onCliFallback,
      runBrowser,
    });
    expect(result.source).toBe('browser');
    expect(runBrowser).toHaveBeenCalledTimes(1);
    expect(onCliFallback).toHaveBeenCalledTimes(1);
    expect((onCliFallback.mock.calls[0]![0] as CliProveError).status).toBe(429);
  });

  it('cliPresent:true + network err → fallback, callback gets status:0', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(
      new TypeError('Failed to fetch'),
    );
    const runBrowser = vi.fn().mockResolvedValue(STUB_BROWSER_RESULT);
    const onCliFallback = vi.fn();
    const result = await runCliFirstProver(STUB_WITNESS, {
      cliPresent: true,
      onCliFallback,
      runBrowser,
    });
    expect(result.source).toBe('browser');
    expect((onCliFallback.mock.calls[0]![0] as CliProveError).status).toBe(0);
  });

  it('cliPresent:true + malformed 2xx body → fallback (status:-1)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('{"proof": "not an object"}', { status: 200 }),
    );
    const runBrowser = vi.fn().mockResolvedValue(STUB_BROWSER_RESULT);
    const onCliFallback = vi.fn();
    const result = await runCliFirstProver(STUB_WITNESS, {
      cliPresent: true,
      onCliFallback,
      runBrowser,
    });
    expect(result.source).toBe('browser');
    expect((onCliFallback.mock.calls[0]![0] as CliProveError).status).toBe(-1);
  });

  it('cliPresent:true + 4xx (witness invalid) → re-throws, NO fallback, browser NOT invoked', async () => {
    // 4xx = browser would also fail. Re-throwing avoids spending 90s
    // on a doomed browser prove just to surface the same error later.
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'witness shape invalid' }), {
        status: 400,
      }),
    );
    const runBrowser = vi.fn();
    const onCliFallback = vi.fn();
    await expect(
      runCliFirstProver(STUB_WITNESS, {
        cliPresent: true,
        onCliFallback,
        runBrowser,
      }),
    ).rejects.toMatchObject({
      name: 'CliProveError',
      status: 400,
    });
    expect(runBrowser).not.toHaveBeenCalled();
    expect(onCliFallback).not.toHaveBeenCalled();
  });

  it('cliPresent:true + 403 origin pin → re-throws, NO fallback (config issue, not transient)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          error: 'origin not allowed',
          allowed: 'https://identityescrow.org',
        }),
        { status: 403 },
      ),
    );
    const runBrowser = vi.fn();
    const onCliFallback = vi.fn();
    await expect(
      runCliFirstProver(STUB_WITNESS, {
        cliPresent: true,
        onCliFallback,
        runBrowser,
      }),
    ).rejects.toMatchObject({
      name: 'CliProveError',
      status: 403,
    });
    expect(runBrowser).not.toHaveBeenCalled();
    expect(onCliFallback).not.toHaveBeenCalled();
  });

});

describe('runCliFirstProver — onProgress callback', () => {
  it('emits "attempting CLI" → "CLI prove complete" on happy path', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(VALID_PROVE_RESPONSE), { status: 200 }),
    );
    const onProgress = vi.fn();
    const runBrowser = vi.fn();
    await runCliFirstProver(STUB_WITNESS, {
      cliPresent: true,
      runBrowser,
      onProgress,
    });
    const calls = onProgress.mock.calls.map((c) => c[0]);
    expect(calls).toContain('attempting CLI prove via localhost:9080');
    expect(calls).toContain('CLI prove complete');
  });

  it('emits "CLI fallback" on a fallback-eligible failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('error', { status: 500 }),
    );
    const onProgress = vi.fn();
    const runBrowser = vi.fn().mockResolvedValue(STUB_BROWSER_RESULT);
    await runCliFirstProver(STUB_WITNESS, {
      cliPresent: true,
      runBrowser,
      onProgress,
    });
    const calls = onProgress.mock.calls.map((c) => c[0]);
    expect(calls).toContain('CLI fallback — running browser prover');
  });
});
