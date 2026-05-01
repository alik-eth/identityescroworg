/// <reference lib="webworker" />
/**
 * V5 snarkjs Web Worker — wraps groth16.fullProve via the SDK's
 * `startSnarkjsWorker` handler.
 *
 * Lives in its own module so `uaProofPipelineV5.ts` can spawn it via
 *   `new Worker(new URL('../workers/v5-prover.worker.ts', import.meta.url),
 *              { type: 'module' })`
 * and pair with `SnarkjsWorkerProver` (main-thread side) from
 * `@qkb/sdk/prover/snarkjsWorker`.
 *
 * Distinct from the V4 `prover.worker.ts` in this dir — that one is the
 * V4 split-proof Worker hand-rolled with its own message protocol; V5
 * uses the SDK's standardised protocol so the wrap is reusable across
 * future provers.
 *
 * 2.2 GB stub zkey OOM mitigation (per circuits-eng's surfacing):
 *   Vite's worker bundling preserves URL-based fetch in snarkjs, which
 *   the SDK's entry forwards verbatim. snarkjs streams the zkey via
 *   ReadableStream rather than buffering whole — peak heap stays under
 *   the V8 limit on flagship 2024+ phones (per spec pass 5 device gate).
 *   Mid-range Android / older browsers are filtered by the device gate
 *   before the worker is even spawned (deviceGate.ts).
 */

import { startSnarkjsWorker } from '@qkb/sdk/prover/snarkjsWorkerEntry';

startSnarkjsWorker();
