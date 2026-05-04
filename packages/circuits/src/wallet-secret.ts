// V5.1 wallet-secret derivation + reduction helpers.
//
// Per spec docs/superpowers/specs/2026-04-30-wallet-bound-nullifier-amendment.md
// (v0.6, user-approved at df203b8) and orchestration plan §1.2:
//
//   EOA path: walletSecret = HKDF-SHA256(
//                              ikm:  personal_sign(walletPriv,
//                                                  "qkb-personal-secret-v1" ‖ subjectSerial),
//                                        // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
//                              salt: "qkb-walletsecret-v1",
//                                    // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
//                              info: subjectSerial,
//                              L:    32 bytes)
//
//   SCW path: walletSecret = Argon2id(passphrase, salt="qkb-walletsecret-v1" ‖ walletAddress,
//                                     // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
//                                     m=64MiB, t=3, p=1, output=32 bytes)
//
// Then reduce/truncate mod the BN254 scalar field (~254-bit cap; mask top 2 bits)
// before packing into the circuit's `walletSecret` field-element input.
//
// **This module ships the reduction helper + a TEST-ONLY EOA-derivation helper.**
// Production EOA derivation lives in web-eng's SDK (`@zkqes/sdk`); this is for
// circuit unit tests + CLI fixture generation.
//
// Browser-isomorphic: `@noble/hashes` v2 only — no node:crypto, no ethers. Web-eng
// imports this module directly for parity. Per CLAUDE.md V5.10, the SHA-256
// fingerprint of this file gates a drift-check.

import { Buffer } from 'node:buffer';

// FINGERPRINT_DOMAIN — fixed compile-time constant for identity-fingerprint
// domain separation. Big-endian-pack of ASCII "qkb-id-fingerprint-v1" (21 bytes,
// frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
// 168 bits, well below the BN254 scalar field ~254 bits).
//
// MUST byte-equal the constant in ZkqesPresentationV5.circom:
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
 *
 * Bias note: any reduction of a 256-bit input to a ~254-bit field has
 * a small bias toward the low end (about 2× chance for [0, 2^256 − k·p)
 * vs uniform). For HKDF-derived secrets at 256 bits this bias is
 * cryptographically negligible (~2^-2 over the field, well below the
 * security parameter). For genuinely-uniform 32-byte inputs the field
 * element is effectively uniform mod p.
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

// NOTE: A test-only `deriveWalletSecretTest` helper was considered (per
// the A6.1 plan Task 2 Step 3) but removed in v0.4.1 (codex review pass 2)
// as dead code — no test calls it; tests pass a static `Buffer.alloc(32, 0x42)`
// directly. Production EOA derivation lives in web-eng's @zkqes/sdk:
//   walletSecret = HKDF-SHA256(
//     ikm:  personal_sign(walletPriv, "qkb-personal-secret-v1" ‖ subjectSerial),
//           // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
//     salt: "qkb-walletsecret-v1",
//           // frozen protocol byte string; see specs/2026-05-03-zkqes-rename-design.md §3
//     info: subjectSerial,
//     L:    32 bytes)
// then `reduceTo254()` on the result. Web-eng owns this code path; circuit
// tests don't need parity with it (they only need a 32-byte deterministic
// secret). Re-introducing a test helper later is fine, but it should be
// clearly named (e.g. `deriveWalletSecretFixture`) and NOT claim production-
// parity unless it actually mirrors the EOA `personal_sign` path byte-for-byte.
