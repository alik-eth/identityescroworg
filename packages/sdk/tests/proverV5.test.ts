import { describe, expect, it } from 'vitest';
import { MockProver, proveV5, type CircuitArtifactUrls } from '../src/prover/index.js';

const V5_ARTIFACTS: CircuitArtifactUrls = {
  wasmUrl: 'https://example.test/v5.wasm',
  zkeyUrl: 'https://example.test/v5.zkey',
  zkeySha256: 'c'.repeat(64),
};

const V5_PUBLIC_SIGNALS = {
  msgSender: '1',
  timestamp: '2',
  nullifier: '3',
  ctxHashHi: '4',
  ctxHashLo: '5',
  bindingHashHi: '6',
  bindingHashLo: '7',
  signedAttrsHashHi: '8',
  signedAttrsHashLo: '9',
  leafTbsHashHi: '10',
  leafTbsHashLo: '11',
  policyLeafHash: '12',
  leafSpkiCommit: '13',
  intSpkiCommit: '14',
};

describe('proveV5 — single-circuit driver', () => {
  it('returns 14 publicSignals for a well-shaped V5 witness (mock prover)', async () => {
    const prover = new MockProver({ delayMs: 0 });
    const result = await proveV5(
      { publicSignals: V5_PUBLIC_SIGNALS } as Record<string, unknown>,
      { prover, artifacts: V5_ARTIFACTS },
    );
    expect(result.publicSignals).toEqual([
      '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14',
    ]);
  });

  it('preserves the §0.1 declared order when projecting the witness', async () => {
    // Permute the input object order — JS doesn't guarantee insertion order
    // for non-string keys, but for object-literal keys it does (ES2015+).
    // The test here is that the output is positional per §0.1, NOT the
    // witness's literal key order. Stress: msgSender / nullifier swapped
    // in input, output still positional.
    const permuted = {
      publicSignals: {
        nullifier: 'n',  // any non-numeric will be rejected — see negative test below
        msgSender: '1',
        timestamp: '2',
        ctxHashHi: '4', ctxHashLo: '5',
        bindingHashHi: '6', bindingHashLo: '7',
        signedAttrsHashHi: '8', signedAttrsHashLo: '9',
        leafTbsHashHi: '10', leafTbsHashLo: '11',
        policyLeafHash: '12', leafSpkiCommit: '13', intSpkiCommit: '14',
      },
    };
    permuted.publicSignals.nullifier = '3';  // restore valid value
    const prover = new MockProver({ delayMs: 0 });
    const result = await proveV5(permuted, {
      prover,
      artifacts: V5_ARTIFACTS,
    });
    // Output[2] is nullifier, NOT input-order-position-0.
    expect(result.publicSignals[0]).toBe('1');  // msgSender
    expect(result.publicSignals[2]).toBe('3');  // nullifier
    expect(result.publicSignals[13]).toBe('14');  // intSpkiCommit
  });

  it('passes the V5 wasm + zkey URLs through to the underlying IProver', async () => {
    let capturedWasmUrl: string | undefined;
    let capturedZkeyUrl: string | undefined;
    let capturedSide: string | undefined;
    const prover = {
      prove: async (_input: Record<string, unknown>, opts: {
        wasmUrl: string; zkeyUrl: string; side?: string;
      }) => {
        capturedWasmUrl = opts.wasmUrl;
        capturedZkeyUrl = opts.zkeyUrl;
        capturedSide = opts.side;
        return {
          proof: {
            pi_a: ['1', '2', '1'],
            pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
            pi_c: ['7', '8', '1'],
            protocol: 'groth16',
            curve: 'bn128',
          },
          publicSignals: Array.from({ length: 14 }, (_, i) => String(i + 1)),
        };
      },
    };
    await proveV5({ publicSignals: V5_PUBLIC_SIGNALS } as Record<string, unknown>, {
      prover,
      artifacts: V5_ARTIFACTS,
    });
    expect(capturedWasmUrl).toBe(V5_ARTIFACTS.wasmUrl);
    expect(capturedZkeyUrl).toBe(V5_ARTIFACTS.zkeyUrl);
    expect(capturedSide).toBe('v5');
  });

  it('admits the V5 family — 14 (V5 baseline), 19 (V5.1), 22 (V5.2)', async () => {
    // Regression guard: before this fix `proveV5` hardcoded `!== 14`,
    // which silently broke the V5.1 mock pipeline (19 signals always
    // threw witness.fieldTooLong) and would have broken the V5.2
    // pipeline the same way (22 signals). The allowlist
    // `ALLOWED_PUBLIC_SIGNAL_LENGTHS` is the named pin future readers
    // grep for when adding the next amendment (V5.3).
    for (const n of [14, 19, 22]) {
      const prover = {
        prove: async (): Promise<{ proof: unknown; publicSignals: string[] }> => ({
          proof: {
            pi_a: ['1', '2', '1'],
            pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
            pi_c: ['7', '8', '1'],
            protocol: 'groth16',
            curve: 'bn128',
          },
          publicSignals: Array.from({ length: n }, (_, i) => String(i + 1)),
        }),
      };
      const result = await proveV5({} as Record<string, unknown>, {
        prover: prover as unknown as Parameters<typeof proveV5>[1]['prover'],
        artifacts: V5_ARTIFACTS,
      });
      expect(result.publicSignals.length).toBe(n);
    }
  });

  it('rejects non-V5-family publicSignal counts (V4 leaf = 16, junk = 7)', async () => {
    // Simulate a V4 zkey emitting 16 signals where the V5 family expects
    // 14 (V5), 19 (V5.1), or 22 (V5.2). The V5 driver MUST fail loudly
    // rather than passing the malformed array to register() — the
    // contract's Gate 1 verifyProof would throw with a generic BadProof,
    // losing the diagnostic.
    //
    // We also pin "junk" lengths (7) to make the rejection envelope
    // explicit — anything not in the V5 family allowlist trips the
    // guard, not just the historically-known V4 case. This catches
    // drift from any layer that might reshape publicSignals (e.g. a
    // future SDK refactor that accidentally drops a slot).
    for (const n of [16, 7]) {
      const prover = {
        prove: async (): Promise<{ proof: unknown; publicSignals: string[] }> => ({
          proof: {} as unknown,
          publicSignals: Array.from({ length: n }, (_, i) => String(i)),
        }),
      };
      await expect(
        proveV5({} as Record<string, unknown>, {
          prover: prover as unknown as Parameters<typeof proveV5>[1]['prover'],
          artifacts: V5_ARTIFACTS,
        }),
      ).rejects.toThrow(/v5-public-signals-length/);
    }
  });

  it('forwards onProgress callbacks', async () => {
    const seen: { stage: string; pct: number }[] = [];
    const prover = new MockProver({ delayMs: 6 });
    await proveV5(
      { publicSignals: V5_PUBLIC_SIGNALS } as Record<string, unknown>,
      {
        prover,
        artifacts: V5_ARTIFACTS,
        onProgress: (p) => seen.push({ stage: p.stage, pct: p.pct }),
      },
    );
    expect(seen.length).toBeGreaterThanOrEqual(3);
    expect(seen.map((s) => s.stage)).toContain('witness');
    expect(seen.map((s) => s.stage)).toContain('prove');
    expect(seen.map((s) => s.stage)).toContain('finalize');
  });

  it('supports AbortSignal cancellation', async () => {
    const prover = new MockProver({ delayMs: 100 });
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 5);
    await expect(
      proveV5(
        { publicSignals: V5_PUBLIC_SIGNALS } as Record<string, unknown>,
        { prover, artifacts: V5_ARTIFACTS, signal: ctrl.signal },
      ),
    ).rejects.toThrow(/cancelled/);
  });
});
