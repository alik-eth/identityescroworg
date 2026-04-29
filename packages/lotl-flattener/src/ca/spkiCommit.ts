import { buildPoseidon } from 'circomlibjs';

/**
 * SpkiCommit — V5 trust-list Merkle leaf primitive.
 *
 * Byte-equivalent with circuits-eng's reference at
 * `packages/circuits/scripts/spki-commit-ref.ts` and contracts-eng's
 * Solidity `P256Verify.spkiCommit`. All three impls produce the same
 * decimal string for the same 91-byte SPKI input — asserted in the
 * §9.1 parity gate (`tests/ca/spkiCommit.test.ts`).
 *
 * Construction (per V5 spec §0.2):
 *   1. Validate input is exactly 91 bytes (canonical ECDSA-P256 SPKI).
 *   2. Slice X = spki[27..58], Y = spki[59..90] (32 bytes BE each).
 *   3. Decompose each coordinate into 6 × 43-bit little-endian limbs.
 *   4. X_hash = Poseidon₆(X_limbs); Y_hash = Poseidon₆(Y_limbs).
 *   5. SpkiCommit = Poseidon₂(X_hash, Y_hash).
 *
 * Reference values pinned in `fixtures/spki-commit/v5-parity.json`.
 */

interface PoseidonHasher {
  F: { e: (v: bigint) => unknown; toObject: (v: unknown) => bigint };
  (inputs: unknown[]): unknown;
}

let poseidonInstance: PoseidonHasher | null = null;
async function getPoseidon(): Promise<PoseidonHasher> {
  if (poseidonInstance === null) {
    poseidonInstance = (await buildPoseidon()) as unknown as PoseidonHasher;
  }
  return poseidonInstance;
}

async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const p = await getPoseidon();
  return p.F.toObject(p(inputs.map((v) => p.F.e(v))));
}

/**
 * Decompose a 32-byte big-endian integer into 6 × 43-bit little-endian limbs.
 *
 * limbs[0] is the LEAST-significant 43 bits. 6 × 43 = 258 bits of capacity
 * > 256 bits of input — the top limb has at most 41 significant bits.
 */
export function decomposeTo643Limbs(coord: Uint8Array): bigint[] {
  if (coord.length !== 32) {
    throw new Error(`decomposeTo643Limbs: expected 32 bytes, got ${coord.length}`);
  }
  let v = 0n;
  for (let i = 0; i < coord.length; i++) {
    v = (v << 8n) | BigInt(coord[i]!);
  }
  const mask = (1n << 43n) - 1n;
  const limbs: bigint[] = new Array(6);
  for (let i = 0; i < 6; i++) {
    limbs[i] = (v >> BigInt(43 * i)) & mask;
  }
  return limbs;
}

const SPKI_LEN = 91;

export async function spkiCommit(spki: Uint8Array): Promise<bigint> {
  if (spki.length !== SPKI_LEN) {
    throw new Error(
      `spkiCommit: unexpected SPKI length ${spki.length}, expected ${SPKI_LEN}`,
    );
  }
  const x = spki.subarray(27, 59);
  const y = spki.subarray(59, 91);
  const xLimbs = decomposeTo643Limbs(x);
  const yLimbs = decomposeTo643Limbs(y);
  const xHash = await poseidonHash(xLimbs);
  const yHash = await poseidonHash(yLimbs);
  return poseidonHash([xHash, yHash]);
}
