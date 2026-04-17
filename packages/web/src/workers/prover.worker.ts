/// <reference lib="webworker" />
/**
 * snarkjs Web Worker — wraps groth16.fullProve.
 *
 * Lives in its own module so the SnarkjsProver in lib/prover.ts can spawn it
 * via `new Worker(new URL('../workers/prover.worker.ts', import.meta.url))`.
 * Vite's `worker.format: 'es'` gives us native ESM imports inside the worker.
 *
 * snarkjs has no fine-grained progress callback, so we emit a heartbeat every
 * 2 seconds during the `prove` phase to keep the UI honest about elapsed time.
 */

interface ProveRequest {
  type: 'prove';
  id: number;
  input: Record<string, unknown>;
  wasmUrl: string;
  zkeyUrl: string;
}

const ctx = self as unknown as DedicatedWorkerGlobalScope;

ctx.addEventListener('message', (ev: MessageEvent<ProveRequest>) => {
  const msg = ev.data;
  if (msg?.type !== 'prove') return;
  void runProve(msg);
});

async function runProve(req: ProveRequest): Promise<void> {
  const start = Date.now();
  const post = (
    stage: 'witness' | 'prove' | 'finalize',
    pct: number,
  ): void => {
    ctx.postMessage({
      type: 'progress',
      id: req.id,
      stage,
      pct,
      elapsedMs: Date.now() - start,
    });
  };

  let heartbeat: ReturnType<typeof setInterval> | undefined;
  try {
    post('witness', 5);
    const snarkjs = await import(/* @vite-ignore */ 'snarkjs');
    post('witness', 20);
    post('prove', 25);
    heartbeat = setInterval(() => {
      const elapsed = Date.now() - start;
      const pct = Math.min(95, 25 + Math.log10(elapsed / 1000 + 1) * 25);
      ctx.postMessage({
        type: 'progress',
        id: req.id,
        stage: 'prove',
        pct,
        elapsedMs: elapsed,
      });
    }, 2_000);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      req.input,
      req.wasmUrl,
      req.zkeyUrl,
    );
    clearInterval(heartbeat);
    heartbeat = undefined;
    post('finalize', 99);
    ctx.postMessage({
      type: 'result',
      id: req.id,
      result: { proof, publicSignals },
    });
  } catch (e) {
    if (heartbeat) clearInterval(heartbeat);
    const message = e instanceof Error ? e.message : String(e);
    ctx.postMessage({ type: 'error', id: req.id, message });
  }
}
