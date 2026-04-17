// Canonical Poseidon hash over a DER-encoded certificate.
//
// This function MUST be mirrored byte-for-byte in the circuit
// (`packages/circuits/circuits/CertCanonHash.circom`). The exact procedure:
//
//   1. Input: arbitrary-length DER byte sequence `der`.
//   2. Pack into field elements, 31 bytes per element, BIG-ENDIAN within
//      each chunk: the first byte of the slice becomes the highest-order
//      byte of the field element. The final chunk is padded implicitly by
//      stopping at the actual byte count (no trailing zero padding inside
//      the packed integer — short last chunks have a smaller numeric value).
//   3. After the data chunks, append ONE additional field element whose
//      value is `BigInt(der.length)` — the length-domain separator.
//   4. Absorb into a Poseidon sponge with width 16 (rate = 15, capacity = 1)
//      operating in BN254. State is initialized to zeros. Each round consumes
//      up to 15 chunks: state = Poseidon( [state[0], ...nextWindow,
//      pad_zeros_if_needed] ). The capacity slot is the previous state[0];
//      the 15 rate slots are the next 15 input field elements (zero-padded
//      if the last window is partial).
//   5. Output: state[0] after the final round, returned as a `bigint` in
//      [0, p) where p is the BN254 scalar field modulus.
//
// Determinism: `circomlibjs.buildPoseidon()` is cached at module level so
// repeated calls reuse the same Poseidon instance.

import { buildPoseidon } from 'circomlibjs';

export const CHUNK_SIZE = 31;
export const SPONGE_WIDTH = 16;
export const SPONGE_RATE = SPONGE_WIDTH - 1;

type Poseidon = ((inputs: unknown[]) => unknown) & {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
};

let poseidonP: Promise<Poseidon> | null = null;
const getPoseidon = (): Promise<Poseidon> => {
  if (poseidonP === null) poseidonP = buildPoseidon() as unknown as Promise<Poseidon>;
  return poseidonP;
};

const packChunks = (der: Uint8Array): bigint[] => {
  const chunks: bigint[] = [];
  for (let i = 0; i < der.length; i += CHUNK_SIZE) {
    const end = Math.min(i + CHUNK_SIZE, der.length);
    let v = 0n;
    for (let j = i; j < end; j++) {
      v = (v << 8n) | BigInt(der[j]!);
    }
    chunks.push(v);
  }
  chunks.push(BigInt(der.length));
  return chunks;
};

export async function canonicalizeCertHash(der: Uint8Array): Promise<bigint> {
  const p = await getPoseidon();
  const F = p.F;
  const chunks = packChunks(der);

  let state: unknown = F.e(0n);
  for (let i = 0; i < chunks.length; i += SPONGE_RATE) {
    const window: unknown[] = new Array(SPONGE_WIDTH);
    window[0] = state;
    for (let j = 0; j < SPONGE_RATE; j++) {
      const c = chunks[i + j];
      window[j + 1] = F.e(c === undefined ? 0n : c);
    }
    state = p(window);
  }
  return F.toObject(state);
}
