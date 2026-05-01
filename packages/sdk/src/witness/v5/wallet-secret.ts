// V5.1 wallet-secret reduction helpers — browser-safe port.
//
// Cross-read from arch-circuits `7d07536`'s `src/wallet-secret.ts`.
// Browser patch: `import { Buffer } from 'node:buffer'` → `_buffer-global`
// (same pattern as build-witness-v5.ts and all other SDK vendor files).
// All other code is verbatim — this module is isomorphic by design (no
// node:crypto, no ethers).
//
// Spec: docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md
// (v0.6, user-approved at df203b8). Orchestration §1.2 (FROZEN interface).
//
// This file is a VENDOR SYNC — any amendment by circuits-eng MUST be
// re-ported here (with the `node:buffer` → `_buffer-global` patch).

import { Buffer } from './_buffer-global';

// FINGERPRINT_DOMAIN — fixed compile-time constant for identity-fingerprint
// domain separation. Big-endian-pack of ASCII "qkb-id-fingerprint-v1" (21 bytes,
// 168 bits, well below the BN254 scalar field ~254 bits).
//
// MUST byte-equal the constant in QKBPresentationV5.circom:
//   var FINGERPRINT_DOMAIN = 0x716b622d69642d66696e6765727072696e742d7631;
export const FINGERPRINT_DOMAIN: bigint =
  0x716b622d69642d66696e6765727072696e742d7631n;

// BN254 scalar field order (= prime r, the modulus of the proving system's
// scalar field). 254 bits. snarkjs's curve.r matches this.
export const BN254_SCALAR_FIELD: bigint =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Reduce a 32-byte buffer to a canonical BN254 scalar-field element.
 *
 * Strategy: interpret the buffer big-endian as a uint256, then reduce
 * **modulo BN254_SCALAR_FIELD**. Result is in [0, p) ⊂ [0, 2^254). The
 * circuit's `walletSecret` Num2Bits(254) range-check still passes (since
 * p < 2^254), AND the off-circuit value is canonical — no two distinct
 * 32-byte inputs produce the same field element except via genuine 256-bit
 * mod-p collisions (which would also collide in-circuit).
 *
 * **Why not just mask top 2 bits?** [v0.4.1 fix — codex review pass 1 P1]
 * The naive `value & ((1<<254)-1)` strategy leaves results in [0, 2^254),
 * but BN254's scalar field `p ≈ 0.756 × 2^254` < 2^254. Values in [p, 2^254)
 * silently wrap mod p inside the circuit, so two distinct masked secrets
 * `x` and `x + p` (both in [0, 2^254)) collide on `identityCommitment` and
 * `nullifier` while still passing Num2Bits(254). That breaks the
 * wallet-uniqueness invariant. Reducing mod p eliminates the alias entirely.
 */
export function reduceTo254(buf: Uint8Array | Buffer): bigint {
  if (buf.length !== 32) {
    throw new Error(`reduceTo254: expected 32-byte input, got ${buf.length}`);
  }
  const u256 = BigInt('0x' + Buffer.from(buf).toString('hex'));
  return u256 % BN254_SCALAR_FIELD;
}

/**
 * Pack a `subjectSerialPacked` field element to a 32-byte buffer (big-endian).
 *
 * `subjectSerialPacked` is the off-circuit value of
 * `Poseidon₅(subjectSerialLimbs[0..3], subjectSerialLen)`. Web-eng's HKDF
 * input message includes these bytes for cross-identity walletSecret separation
 * (per spec Q6 resolution: yes, include subjectSerial in the HKDF input domain).
 */
export function packFieldToBytes32(field: bigint): Buffer {
  if (field < 0n || field >= 1n << 256n) {
    throw new Error(`packFieldToBytes32: out of range`);
  }
  const hex = field.toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}
