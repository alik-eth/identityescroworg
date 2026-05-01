// Off-circuit reference for `PoseidonChunkHashVar(MAX_BYTES)`. Verbatim
// port of arch-circuits f0d5a73's `src/poseidon-chunk-hash.ts`. circomlibjs
// is browser-safe (no Node-only APIs).

// Browser patch: arch-circuits uses `require('circomlibjs')` (works under
// ts-node) but a literal require() leaks into the browser bundle and
// throws `require is not defined`. We use the ES import — same module,
// same export shape, browser-safe.
import { buildPoseidon } from 'circomlibjs';

interface Poseidon {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
  (inputs: unknown[]): unknown;
}

let poseidonP: Promise<Poseidon> | null = null;
function getPoseidon(): Promise<Poseidon> {
  poseidonP ??= buildPoseidon() as unknown as Promise<Poseidon>;
  return poseidonP;
}

const CHUNK = 31;
const RATE = 15;

/**
 * Compute `PoseidonChunkHashVar(data, len)` off-circuit. Byte-identical
 * to the circom template's output for any `data: Uint8Array, len ≤ data.length`.
 */
export async function poseidonChunkHashVar(data: Uint8Array): Promise<bigint> {
  const p = await getPoseidon();
  const F = p.F;
  const chunks: bigint[] = [];
  for (let i = 0; i < data.length; i += CHUNK) {
    const end = Math.min(i + CHUNK, data.length);
    let v = 0n;
    for (let j = i; j < end; j++) v = (v << 8n) | BigInt(data[j]!);
    chunks.push(v);
  }
  chunks.push(BigInt(data.length));
  let state: unknown = F.e(0n);
  for (let i = 0; i < chunks.length; i += RATE) {
    const window: unknown[] = new Array(RATE + 1);
    window[0] = state;
    for (let j = 0; j < RATE; j++) {
      const c = chunks[i + j];
      window[j + 1] = F.e(c === undefined ? 0n : c);
    }
    state = p(window);
  }
  return F.toObject(state);
}

/** Convenience: Poseidon-2 over (a, b). Used for NullifierDerive's outer
 *  step `Poseidon(secret, ctxHash)`. */
export async function poseidon2(a: bigint, b: bigint): Promise<bigint> {
  const p = await getPoseidon();
  return p.F.toObject(p([p.F.e(a), p.F.e(b)]));
}

/** Convenience: Poseidon-5 over (limbs[0..3], len). Used for
 *  NullifierDerive's inner step `secret = Poseidon(serialLimbs ‖ serialLen)`. */
export async function poseidon5(inputs: bigint[]): Promise<bigint> {
  if (inputs.length !== 5) {
    throw new Error(`poseidon5: expected exactly 5 inputs, got ${inputs.length}`);
  }
  const p = await getPoseidon();
  return p.F.toObject(p(inputs.map((v) => p.F.e(v))));
}
