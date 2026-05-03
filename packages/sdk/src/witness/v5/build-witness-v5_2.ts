// V5.2 witness builder — keccak-on-chain amendment.
//
// Spec ref: docs/superpowers/specs/2026-05-01-keccak-on-chain-amendment.md
// (commit 5ba064e on feat/v5_2arch-circuits, v0.4 + contracts-eng review).
//
// Core delta vs V5.1 (`build-witness-v5.ts`):
//   - Drop `msgSender` from the witness JSON (no longer a circuit input).
//     The on-chain contract derives msg.sender via keccak256 of the
//     uncompressed pubkey limbs, so circuit no longer carries it.
//   - Add `bindingPkXHi/Lo + bindingPkYHi/Lo` — 4 × 128-bit big-endian
//     limbs of the binding's claimed wallet pk (the 64 bytes of
//     `parser.pkBytes[1..65]`, dropping the 0x04 SEC1 prefix). Each
//     limb is exactly 16 bytes packed BE per spec §"Construction delta"
//     Bits2Num formula:
//
//       pkXHi = sum_{i=0..15}  pkBytes[i+1]  * 256^(15-i)   // BE
//       pkXLo = sum_{i=16..31} pkBytes[i+1]  * 256^(31-i)   // BE
//       pkYHi = sum_{i=0..15}  pkBytes[i+33] * 256^(15-i)   // BE
//       pkYLo = sum_{i=16..31} pkBytes[i+33] * 256^(31-i)   // BE
//
// Public-signal layout (FROZEN per spec §"Public-signal layout V5.1
// → V5.2"): 22 entries, V5.1 slots 1-18 shifted down by 1 (msgSender
// removal frees slot 0), bindingPkXHi/Lo + bindingPkYHi/Lo appended at
// 18-21.
//
// Cross-package "byte-identical witness" contract: if circuits-eng
// amends `build-witness-v5_2.ts` upstream, this copy MUST be re-synced.
// The sibling helper extracted here (`extractBindingPkBytes`) is the
// shared piece both V5.1 and V5.2 use; no logic divergence on the
// pk-parsing step.
import { Buffer } from './_buffer-global';
import { extractBindingOffsets } from './binding-offsets';
import {
  buildWitnessV5,
} from './build-witness-v5';
import type {
  BuildWitnessV5Input,
  V2CoreBindingOffsets,
  WitnessV5,
} from './types';

/**
 * V5.2 witness — same shape as `WitnessV5` but with `msgSender` dropped
 * and four `bindingPk*` limbs appended. Snarkjs witness JSON contract:
 * fields with public-signal slot mappings must be exactly the 22 names
 * the V5.2 circuit declares as `signal input` (in canonical order).
 */
export type WitnessV5_2 = Omit<WitnessV5, 'msgSender'> & {
  readonly bindingPkXHi: string;
  readonly bindingPkXLo: string;
  readonly bindingPkYHi: string;
  readonly bindingPkYLo: string;
};

/** V5.2 builder input. Identical shape to V5.1 — the divergence is on
 *  the OUTPUT side (witness JSON layout), not on the input artifacts. */
export type BuildWitnessV5_2Input = BuildWitnessV5Input;

/**
 * Extract the 65-byte SEC1-uncompressed wallet pk from the binding bytes,
 * verify the 0x04 prefix, return the 64 raw bytes (drop prefix).
 *
 * This duplicates the small parsing block at the top of
 * `buildWitnessV5`'s §6.8 section (the one that computes msgSender via
 * keccak). V5.2 doesn't compute msgSender from these bytes (the contract
 * does that), but it still needs the same 64 bytes split into 4 × 16-byte
 * limbs for the new `bindingPk*` public signals.
 *
 * Kept as a private helper rather than exported because the only V5.2
 * caller is `buildWitnessV5_2`; if a future amendment needs it from
 * outside, promote at that point.
 */
function extractBindingPkBytes(
  bindingBytes: Buffer,
  offsets: V2CoreBindingOffsets,
): Buffer {
  const start = offsets.pkValueOffset + 2; // skip "0x" leadIn
  const hex = bindingBytes
    .subarray(start, start + 130)
    .toString('utf8');
  const buf = Buffer.from(hex, 'hex');
  if (buf.length !== 65 || buf[0] !== 0x04) {
    throw new Error(
      `binding.pk must be 65-byte SEC1 uncompressed (0x04 || X || Y); got ${buf.length} bytes`,
    );
  }
  return buf;
}

/**
 * Big-endian byte slice → bigint.
 *
 * V5.2 packs 16 raw bytes per limb in big-endian order (matching
 * Ethereum's natural pk serialization). The inverse — limb → 16 bytes
 * — happens contract-side via Solidity's `bytes16(uint128(limb))`
 * cast, which is also big-endian. Therefore the byte-string fed to
 * `keccak256` on-chain is identical to `pkBytes[1..65]`, preserving
 * the V5.1 in-circuit keccak's input bytes exactly.
 */
function bytesToBigIntBE(bytes: Uint8Array | Buffer): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

/**
 * Build a V5.2-main witness from pre-extracted CMS + fixture artifacts.
 *
 * Implementation strategy: delegate the entire computation to
 * `buildWitnessV5` (which produces the V5.1 witness shape + msgSender),
 * then reshape the output to V5.2:
 *   1. Drop `msgSender` (the circuit's `signal input` for it is gone).
 *   2. Compute the four `bindingPk*` limbs from the same pkBytes.
 *   3. Append them in spec-§"Public-signal layout" order.
 *
 * This avoids a 400-line copy-paste while keeping the V5.1 builder
 * unmodified (V5.1 ceremony stub fixtures still verify against the
 * V5.1 witness JSON shape — see `ceremony-stub-v5_1.test.ts`).
 *
 * Performance: the binding bytes are parsed twice (once inside
 * `buildWitnessV5` for msgSender derivation, once here for the limbs).
 * The parse is O(small) and runs once per registration; not worth
 * deduping at this layer.
 */
export async function buildWitnessV5_2(
  input: BuildWitnessV5_2Input,
): Promise<WitnessV5_2> {
  // Reuse the full V5.1 computation. msgSender will be in the result;
  // we drop it below.
  const v51Witness = await buildWitnessV5(input);

  // Re-extract pkBytes for the limb computation. Cheap (<1ms typical
  // binding size). The offsets came from the same source as V5.1's
  // computation, so the bytes are guaranteed byte-identical to what
  // V5.1 fed to keccak.
  const offsets: V2CoreBindingOffsets =
    input.bindingOffsets ?? extractBindingOffsets(input.bindingBytes);
  const pkBytes = extractBindingPkBytes(input.bindingBytes, offsets);

  // 4 × 16-byte big-endian uint128 limbs. Spec §"Construction delta"
  // Bits2Num formula. pkBytes[0] is the SEC1 0x04 prefix (skip);
  // pkBytes[1..33] is X (32 bytes), pkBytes[33..65] is Y (32 bytes).
  const pkXHi = bytesToBigIntBE(pkBytes.subarray(1, 17));
  const pkXLo = bytesToBigIntBE(pkBytes.subarray(17, 33));
  const pkYHi = bytesToBigIntBE(pkBytes.subarray(33, 49));
  const pkYLo = bytesToBigIntBE(pkBytes.subarray(49, 65));

  // Strip msgSender from the V5.1 witness (V5.2 circuit doesn't have it).
  // The other 18 V5.1 fields carry forward unchanged; we just append the
  // 4 new pkPK* limbs.
  // Use a destructure rather than property delete so the resulting object
  // has predictable iteration order (matters for snarkjs which serializes
  // witness JSON in property order).
  const { msgSender: _omitted, ...rest } = v51Witness;
  void _omitted;

  return {
    ...rest,
    bindingPkXHi: pkXHi.toString(),
    bindingPkXLo: pkXLo.toString(),
    bindingPkYHi: pkYHi.toString(),
    bindingPkYLo: pkYLo.toString(),
  };
}
