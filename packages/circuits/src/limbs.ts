// Limb-packing helpers shared between the witness builder and the
// integration tests.
//
// Two packing conventions live here:
//   - secp256k1 coordinates → 4 × uint64 limbs (LE across, BE within),
//     matching Secp256k1PkMatch.circom's `pkX[4]/pkY[4]` layout.
//   - X509 subject-serial bytes → 4 × uint64 limbs (LE within limb,
//     LE across), matching X509SubjectSerial.circom's packing.
//
// Both helpers are pure — no fixture I/O, no async; the witness builder
// composes them around fixture-supplied byte buffers.

import type { Buffer } from 'node:buffer';

/**
 * Pack a 32-byte big-endian secp256k1 coordinate into 4 × uint64 limbs.
 *
 *   limb[3] = bytes[0..7]   BE   (most-significant 64 bits)
 *   limb[2] = bytes[8..15]  BE
 *   limb[1] = bytes[16..23] BE
 *   limb[0] = bytes[24..31] BE   (least-significant 64 bits)
 *
 * Each limb is the BE concatenation of 8 bytes packed into a single
 * uint64. Convention matches `Secp256k1PkMatch.circom`'s pkX/pkY decoding.
 */
export function pkCoordToLimbs(bytes32: Buffer): bigint[] {
  if (bytes32.length !== 32) {
    throw new Error(`pkCoordToLimbs: expected 32-byte coordinate, got ${bytes32.length}`);
  }
  const limbs: bigint[] = [0n, 0n, 0n, 0n];
  for (let l = 0; l < 4; l++) {
    const off = (3 - l) * 8;
    let acc = 0n;
    for (let j = 0; j < 8; j++) {
      acc = (acc << 8n) | BigInt(bytes32[off + j] as number);
    }
    limbs[l] = acc;
  }
  return limbs;
}

/**
 * Pack up to 32 subject-serial content bytes into 4 × uint64 limbs.
 *
 * Within each limb the bytes are LE: byte[l*8 + 0] is the LOW byte of
 * limb[l]. Positions ≥ length are forced to zero so DER-tail bytes
 * cannot leak into the limbs (matching `X509SubjectSerial.circom`'s
 * mask-then-pack semantics).
 */
export function subjectSerialBytesToLimbs(bytes: Buffer): bigint[] {
  if (bytes.length > 32) {
    throw new Error(`subjectSerialBytesToLimbs: serial > 32 bytes (got ${bytes.length})`);
  }
  const limbs: bigint[] = [0n, 0n, 0n, 0n];
  for (let l = 0; l < 4; l++) {
    let acc = 0n;
    for (let b = 7; b >= 0; b--) {
      const idx = l * 8 + b;
      const byte = idx < bytes.length ? BigInt(bytes[idx] as number) : 0n;
      acc = acc * 256n + byte;
    }
    limbs[l] = acc;
  }
  return limbs;
}

/**
 * Decompose a 256-bit big-endian secp256k1/P-256 coordinate into 6 × 43-bit
 * little-endian limbs (n=43, k=6 — the SpkiCommit / circom-ecdsa-p256
 * convention).
 *
 * Used by spkiCommit-ref.ts (already exists) — mirrored here only for
 * type imports if a downstream caller wants to combine multiple limb
 * packings without re-importing from scripts/.
 */
export function decomposeTo643LimbsBE(bytes32: Buffer): bigint[] {
  if (bytes32.length !== 32) {
    throw new Error(`decomposeTo643LimbsBE: expected 32-byte coord, got ${bytes32.length}`);
  }
  let big = 0n;
  for (const b of bytes32) big = (big << 8n) | BigInt(b);
  const MASK = (1n << 43n) - 1n;
  const limbs: bigint[] = [];
  for (let i = 0; i < 6; i++) {
    limbs.push(big & MASK);
    big >>= 43n;
  }
  return limbs;
}
