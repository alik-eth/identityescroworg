// Unit tests for `proveViaCli` — the POST /prove call from browser to
// the QKB CLI server. The fallback discipline pinned in orchestration
// §1.6 is load-bearing for every other test in the V5.4 stack:
//
//   - 4xx        → throw, shouldFallback = false
//   - 429        → throw, shouldFallback = false (server busy; browser
//                  prove would compete for the same CPU)
//   - 5xx        → throw, shouldFallback = true
//   - network    → throw with status = 0, shouldFallback = true
//   - malformed  → throw with status = -1, shouldFallback = true
//   - 2xx + ok   → CliProveResult with source: 'cli'
//
// `WitnessV5_2` is opaque to `proveViaCli` (it's just JSON-stringified
// into the request body), so tests use a minimal stub instead of a
// real witness — the fixture would be 80 KB+ and out of test scope.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CliProveError, proveViaCli } from './proveViaCli.js';
import type { WitnessV5_2 } from '../witness/v5/build-witness-v5_2.js';

// Opaque stub — proveViaCli only JSON-stringifies the witness, doesn't
// introspect. The cast is OK because the runtime call only sees a
// `Record<string, unknown>` shape.
const STUB_WITNESS = { stub: 'witness' } as unknown as WitnessV5_2;

const VALID_PROVE_RESPONSE = {
  proof: {
    pi_a: ['1', '2', '1'],
    pi_b: [
      ['3', '4'],
      ['5', '6'],
      ['1', '0'],
    ],
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

afterEach(() => {
  vi.restoreAllMocks();
});

describe('proveViaCli — happy path', () => {
  it('returns CliProveResult with source:"cli" on a valid 200 response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(VALID_PROVE_RESPONSE), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const result = await proveViaCli(STUB_WITNESS);
    expect(result.source).toBe('cli');
    expect(result.publicSignals).toHaveLength(22);
    expect(result.verifyOk).toBe(true);
    expect(result.timings.totalSec).toBe(12.65);
  });

  it('POSTs JSON-stringified witness to http://127.0.0.1:9080/prove', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(VALID_PROVE_RESPONSE), { status: 200 }),
    );
    await proveViaCli(STUB_WITNESS);
    expect(fetchSpy).toHaveBeenCalledWith(
      'http://127.0.0.1:9080/prove',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
        }),
        body: JSON.stringify(STUB_WITNESS),
      }),
    );
  });
});

describe('proveViaCli — error envelope (orchestration §1.6 fallback discipline)', () => {
  it('throws CliProveError with status and message on 4xx (witness invalid)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'witness shape invalid' }), {
        status: 400,
      }),
    );
    await expect(proveViaCli(STUB_WITNESS)).rejects.toMatchObject({
      name: 'CliProveError',
      status: 400,
      message: 'witness shape invalid',
    });
  });

  it('throws on 403 (origin pin) — same shape as other 4xx', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          error: 'origin not allowed',
          allowed: 'https://identityescrow.org',
          got: 'https://evil.example',
        }),
        { status: 403 },
      ),
    );
    await expect(proveViaCli(STUB_WITNESS)).rejects.toMatchObject({
      status: 403,
    });
  });

  it('throws on 429 (server busy)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'helper busy with another prove' }), {
        status: 429,
      }),
    );
    await expect(proveViaCli(STUB_WITNESS)).rejects.toMatchObject({
      status: 429,
    });
  });

  it('throws on 5xx (rapidsnark crash, OOM)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'rapidsnark exited with SIGKILL' }), {
        status: 500,
      }),
    );
    await expect(proveViaCli(STUB_WITNESS)).rejects.toMatchObject({
      status: 500,
    });
  });

  it('throws CliProveError with status:0 on network failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(
      new TypeError('Failed to fetch'),
    );
    await expect(proveViaCli(STUB_WITNESS)).rejects.toMatchObject({
      name: 'CliProveError',
      status: 0,
    });
  });

  it('throws CliProveError with status:-1 on malformed 2xx body', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('{"proof": "not an object"}', { status: 200 }),
    );
    await expect(proveViaCli(STUB_WITNESS)).rejects.toMatchObject({
      name: 'CliProveError',
      status: -1,
    });
  });

  it('throws CliProveError with status:-1 when proof object is missing pi_a/pi_b/pi_c', async () => {
    // Tightens the malformed-body gate beyond "proof is an object" —
    // a server that returns `{ proof: {}, publicSignals: [...], ... }`
    // would otherwise slip through as success and the malformed proof
    // would reach register() where the contract reverts with a generic
    // BadProof, losing the diagnostic.
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          ...VALID_PROVE_RESPONSE,
          proof: {} /* no pi_a/pi_b/pi_c */,
        }),
        { status: 200 },
      ),
    );
    await expect(proveViaCli(STUB_WITNESS)).rejects.toMatchObject({
      name: 'CliProveError',
      status: -1,
    });
  });

  it('throws CliProveError with status:-1 when 2xx returns wrong-shape timings', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          ...VALID_PROVE_RESPONSE,
          timings: { totalSec: 'fast' /* missing other fields */ },
        }),
        { status: 200 },
      ),
    );
    await expect(proveViaCli(STUB_WITNESS)).rejects.toMatchObject({
      status: -1,
    });
  });

  it('falls through with HTTP-status message when error body is non-JSON', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('plaintext error', { status: 502 }),
    );
    await expect(proveViaCli(STUB_WITNESS)).rejects.toMatchObject({
      status: 502,
      message: 'HTTP 502',
    });
  });
});

describe('CliProveError.shouldFallback', () => {
  // The pipeline (uaProofPipelineV5_2) reads this getter to dispatch
  // fallback. Pin every interesting case so a future refactor can't
  // silently flip the discipline.
  it.each([
    [0, true, 'network failure'],
    [-1, true, 'malformed 2xx body'],
    [400, false, '4xx witness invalid — browser would fail too'],
    [403, false, '4xx origin pin — config issue'],
    [422, false, '4xx validation — browser would fail too'],
    [429, true, '4xx CLI busy — TRANSIENT, browser unblocks user'],
    [500, true, '5xx rapidsnark crash'],
    [502, true, '5xx bad gateway'],
    [503, true, '5xx unavailable'],
  ])('status %i → shouldFallback %s (%s)', (status, expected) => {
    const err = new CliProveError(status, 'test');
    expect(err.shouldFallback).toBe(expected);
  });

  it('429 explicitly: shouldFallback is TRUE so the user reaches a working prover', () => {
    // Lead's correction post-T1: 429 = transient "CLI busy" (another
    // prove in flight on the same server), NOT witness-invalid. The
    // browser prove path will succeed against the same witness; only
    // cost is wall time (~14s CLI vs ~90s browser). Surfacing 429
    // verbatim would leave the user stuck on a "CLI busy" toast.
    // Pin this discipline as a standalone test so a future refactor
    // that re-buckets 429 alongside 4xx surfaces immediately.
    const err = new CliProveError(429, 'helper busy with another prove');
    expect(err.shouldFallback).toBe(true);
    expect(err.status).toBe(429);
  });
});
