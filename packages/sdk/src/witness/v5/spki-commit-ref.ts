// Pure-TypeScript reference implementation of the canonical SpkiCommit
// function defined in V5 spec §0.2 / orchestration §2.2. Verbatim port of
// arch-circuits f0d5a73's `scripts/spki-commit-ref.ts`. circomlibjs is
// browser-safe; Buffer is polyfilled in arch-web.
//
// Construction (per §0.2):
//   1. Parse 91-byte named-curve P-256 DER SubjectPublicKeyInfo → X, Y (32B each).
//   2. Decompose each coordinate into 6×43-bit little-endian limbs.
//   3. SpkiCommit = Poseidon₂( Poseidon₆(X_limbs), Poseidon₆(Y_limbs) ).

import { Buffer } from './_buffer-global';
import { buildPoseidon } from 'circomlibjs';

export interface ParsedSpki {
  x: Buffer; // 32 bytes, big-endian P-256 X coordinate
  y: Buffer; // 32 bytes, big-endian P-256 Y coordinate
}

// Canonical 27-byte DER prefix for a 91-byte named-curve P-256
// SubjectPublicKeyInfo per RFC 5480 + SEC 1 §2.2.
const SPKI_PREFIX = Buffer.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
  0x03, 0x42, 0x00, 0x04,
]);

export function parseP256Spki(spki: Buffer): ParsedSpki {
  if (spki.length !== 91) {
    throw new Error(`SPKI parse: expected 91 bytes, got ${spki.length}`);
  }
  if (!spki.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX)) {
    throw new Error(
      'SPKI parse: invalid DER prefix — outer SEQUENCE length, AlgorithmIdentifier OID ' +
        '(id-ecPublicKey + secp256r1), and BIT STRING uncompressed-point header must ' +
        'match the canonical named-curve P-256 SubjectPublicKeyInfo layout. ' +
        `Got: 0x${spki.subarray(0, SPKI_PREFIX.length).toString('hex')}`,
    );
  }
  return {
    x: Buffer.from(spki.subarray(27, 59)),
    y: Buffer.from(spki.subarray(59, 91)),
  };
}

// Decompose a 32-byte big-endian value into 6 little-endian limbs of 43 bits
// each — the limb encoding the V5 circuit consumes (matches V4's
// `Bytes32ToLimbs643`). 6 × 43 = 258 bits of capacity > 256 bits of input,
// so the top limb has at most 41 significant bits.
export function decomposeTo643Limbs(value: Buffer): bigint[] {
  if (value.length !== 32) {
    throw new Error(`decomposeTo643Limbs: expected 32 bytes, got ${value.length}`);
  }
  const valueAsBigInt = BigInt(`0x${value.toString('hex')}`);
  const mask = (1n << 43n) - 1n;
  const limbs: bigint[] = [];
  for (let i = 0; i < 6; i++) {
    limbs.push((valueAsBigInt >> BigInt(43 * i)) & mask);
  }
  return limbs;
}

// circomlibjs ships no type defs at v0.1.7. The cast captures only the surface
// the witness builder exercises.
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

// SpkiCommit(spki) := Poseidon₂(Poseidon₆(X_limbs), Poseidon₆(Y_limbs)).
export async function spkiCommit(spki: Buffer): Promise<bigint> {
  const { x, y } = parseP256Spki(spki);
  const xLimbs = decomposeTo643Limbs(x);
  const yLimbs = decomposeTo643Limbs(y);
  const xHash = await poseidonHash(xLimbs);
  const yHash = await poseidonHash(yLimbs);
  return poseidonHash([xHash, yHash]);
}
