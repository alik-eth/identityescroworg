import { describe, expect, it, vi } from 'vitest';
import {
  MockProver,
  SnarkjsProver,
  type ProofProgress,
  type ProveResult,
  type ProverWorkerMessage,
} from '../../src/lib/prover';

const FIXED_RESULT: ProveResult = {
  proof: {
    pi_a: ['0xa1', '0xa2', '0x1'],
    pi_b: [
      ['0xb1', '0xb2'],
      ['0xb3', '0xb4'],
      ['0x1', '0x0'],
    ],
    pi_c: ['0xc1', '0xc2', '0x1'],
    protocol: 'groth16',
    curve: 'bn128',
  },
  publicSignals: ['0x1', '0x2', '0x3'],
};

describe('MockProver', () => {
  it('resolves with the configured result and emits 3 stage progress events', async () => {
    const events: ProofProgress[] = [];
    const prover = new MockProver({ delayMs: 9, result: FIXED_RESULT });
    const out = await prover.prove({}, {
      wasmUrl: 'about:blank',
      zkeyUrl: 'about:blank',
      onProgress: (p) => events.push(p),
    });
    expect(out).toEqual(FIXED_RESULT);
    expect(events.map((e) => e.stage)).toEqual(['witness', 'prove', 'finalize']);
    expect(events.at(-1)?.pct).toBe(100);
  });

  it('honors AbortSignal mid-flight and rejects with prover.cancelled', async () => {
    const ctrl = new AbortController();
    const prover = new MockProver({ delayMs: 200 });
    const promise = prover.prove({}, {
      wasmUrl: '',
      zkeyUrl: '',
      signal: ctrl.signal,
    });
    setTimeout(() => ctrl.abort(), 10);
    await expect(promise).rejects.toMatchObject({ code: 'prover.cancelled' });
  });

  it('rejects immediately when handed an already-aborted signal', async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(
      new MockProver().prove({}, {
        wasmUrl: '',
        zkeyUrl: '',
        signal: ctrl.signal,
      }),
    ).rejects.toMatchObject({ code: 'prover.cancelled' });
  });
});

class FakeWorker implements Pick<Worker, 'postMessage' | 'terminate'> {
  private listeners: Record<string, Array<(ev: unknown) => void>> = {};
  terminated = false;
  lastRequest: unknown;
  scenario: 'success' | 'error' | 'never' = 'success';
  responseDelay = 5;

  addEventListener(type: string, fn: (ev: unknown) => void): void {
    (this.listeners[type] ??= []).push(fn);
  }
  removeEventListener(type: string, fn: (ev: unknown) => void): void {
    const arr = this.listeners[type];
    if (!arr) return;
    const i = arr.indexOf(fn);
    if (i !== -1) arr.splice(i, 1);
  }
  postMessage(msg: unknown): void {
    this.lastRequest = msg;
    const id = (msg as { id: number }).id;
    if (this.scenario === 'never') return;
    setTimeout(() => {
      if (this.terminated) return;
      this.emit('message', {
        data: { type: 'progress', id, stage: 'prove', pct: 50, elapsedMs: 1 } satisfies ProverWorkerMessage,
      });
      if (this.scenario === 'success') {
        this.emit('message', {
          data: { type: 'result', id, result: FIXED_RESULT } satisfies ProverWorkerMessage,
        });
      } else {
        this.emit('message', {
          data: { type: 'error', id, message: 'wasm OOM' } satisfies ProverWorkerMessage,
        });
      }
    }, this.responseDelay);
  }
  terminate(): void {
    this.terminated = true;
  }
  private emit(type: string, ev: unknown): void {
    for (const fn of this.listeners[type] ?? []) fn(ev);
  }
}

describe('SnarkjsProver (fake worker)', () => {
  it('resolves with the worker result and forwards progress events', async () => {
    const fake = new FakeWorker();
    const prover = new SnarkjsProver(() => fake as unknown as Worker);
    const events: ProofProgress[] = [];
    const out = await prover.prove(
      { foo: 'bar' },
      { wasmUrl: '/w.wasm', zkeyUrl: '/k.zkey', onProgress: (p) => events.push(p) },
    );
    expect(out).toEqual(FIXED_RESULT);
    expect(events.length).toBeGreaterThan(0);
    expect(fake.terminated).toBe(true);
    expect((fake.lastRequest as { wasmUrl: string }).wasmUrl).toBe('/w.wasm');
  });

  it('maps a worker error into prover.wasmOOM and terminates the worker', async () => {
    const fake = new FakeWorker();
    fake.scenario = 'error';
    const prover = new SnarkjsProver(() => fake as unknown as Worker);
    await expect(
      prover.prove({}, { wasmUrl: '', zkeyUrl: '' }),
    ).rejects.toMatchObject({ code: 'prover.wasmOOM' });
    expect(fake.terminated).toBe(true);
  });

  it('cancellation via AbortSignal terminates the worker and rejects with prover.cancelled', async () => {
    const fake = new FakeWorker();
    fake.scenario = 'never';
    const prover = new SnarkjsProver(() => fake as unknown as Worker);
    const ctrl = new AbortController();
    const p = prover.prove({}, {
      wasmUrl: '',
      zkeyUrl: '',
      signal: ctrl.signal,
    });
    setTimeout(() => ctrl.abort(), 5);
    await expect(p).rejects.toMatchObject({ code: 'prover.cancelled' });
    expect(fake.terminated).toBe(true);
  });

  it('rejects immediately when the signal is already aborted', async () => {
    const fake = new FakeWorker();
    const prover = new SnarkjsProver(() => fake as unknown as Worker);
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(
      prover.prove({}, { wasmUrl: '', zkeyUrl: '', signal: ctrl.signal }),
    ).rejects.toMatchObject({ code: 'prover.cancelled' });
    expect(fake.terminated).toBe(true);
  });

  it('runs two concurrent proves with distinct worker instances', async () => {
    const factory = vi.fn(() => new FakeWorker() as unknown as Worker);
    const prover = new SnarkjsProver(factory);
    const [a, b] = await Promise.all([
      prover.prove({}, { wasmUrl: '', zkeyUrl: '' }),
      prover.prove({}, { wasmUrl: '', zkeyUrl: '' }),
    ]);
    expect(a).toEqual(FIXED_RESULT);
    expect(b).toEqual(FIXED_RESULT);
    expect(factory).toHaveBeenCalledTimes(2);
  });
});
