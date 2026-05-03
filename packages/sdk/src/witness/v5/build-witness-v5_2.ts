// V5.2 witness builder — keccak-on-chain amendment.
// V5.3 layered amendment — F1 OID-anchor for subject-serial offset.
//
// V5.2 spec ref: docs/superpowers/specs/2026-05-01-keccak-on-chain-amendment.md
// V5.3 spec ref: docs/superpowers/specs/2026-05-03-v5_3-oid-anchor-amendment.md
// (V5.3 v0.1, founder-approved minimal F1.2; circuits-eng T1 commit 25bf103
//  on feat/v5_3-circuits.)
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
// V5.3 delta (F1 OID-anchor, private input only):
//   - Emit `subjectSerialOidOffsetInTbs` = `subjectSerialValueOffsetInTbs - 7`.
//     The V5.3 circuit (commit 25bf103) constrains:
//
//       leafTbs[oid+0..oid+4] === [0x06, 0x03, 0x55, 0x04, 0x05]   // OID 2.5.4.5
//       leafTbs[oid+5]        ∈ {0x13 PrintableString, 0x0c UTF8String}
//       leafTbs[oid+6]        === subjectSerialValueLength
//       subjectSerialValueOffsetInTbs === subjectSerialOidOffsetInTbs + 7
//
//     This closes the V5.2 Sybil vector where a prover could pick any
//     32-byte window in the signed TBS that "looks like" a serial-number
//     value. After F1 the OID prefix anchors the chosen offset to a real
//     `AttributeTypeAndValue { type=2.5.4.5 }` ASN.1 frame, and the
//     value-offset is fully determined by the OID-offset.
//
// Public-signal layout (FROZEN per V5.2 spec §"Public-signal layout V5.1
// → V5.2"): 22 entries, V5.1 slots 1-18 shifted down by 1 (msgSender
// removal frees slot 0), bindingPkXHi/Lo + bindingPkYHi/Lo appended at
// 18-21. **V5.3 does NOT change the public layout** — `subjectSerialOidOffsetInTbs`
// is a PRIVATE input (not a public signal), so verifyProof(uint[22])
// keeps its signature and no SDK ABI re-pump is needed.
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
 *
 * V5.3 layered: one additional PRIVATE input (`subjectSerialOidOffsetInTbs`)
 * is emitted alongside the V5.2 fields. snarkjs treats it as a private
 * witness input that doesn't affect the 22 public-signal layout; the
 * V5.3 circuit's §6.9b OID-anchor block consumes it.
 */
export type WitnessV5_2 = Omit<WitnessV5, 'msgSender'> & {
  readonly bindingPkXHi: string;
  readonly bindingPkXLo: string;
  readonly bindingPkYHi: string;
  readonly bindingPkYLo: string;
  /**
   * V5.3 F1 OID-anchor — byte offset (inside `leafTbsBytes`) of the
   * `AttributeTypeAndValue { type=OID 2.5.4.5 (id-at-serialNumber),
   * value=DirectoryString }` ASN.1 frame. Equals
   * `subjectSerialValueOffsetInTbs - 7` (5 OID bytes + 1 string-tag +
   * 1 length-byte). Consumed by the V5.3 circuit's §6.9b block.
   *
   * Emitted as a string per snarkjs's witness JSON convention (all
   * numeric inputs are decimal strings); the V5.3 circuit reads it as
   * `signal input subjectSerialOidOffsetInTbs`.
   */
  readonly subjectSerialOidOffsetInTbs: string;
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

  // V5.3 F1 OID-anchor — derive the OID-offset from the value-offset.
  //
  // The V5.1 builder (delegated above) emits `subjectSerialValueOffsetInTbs`
  // (TBS-relative offset of the DirectoryString value bytes) and
  // `subjectSerialValueOffset` (absolute offset in leafCertDer). The
  // V5.3 circuit needs `subjectSerialOidOffsetInTbs` such that
  // `subjectSerialValueOffsetInTbs === subjectSerialOidOffsetInTbs + 7`.
  // The 7-byte gap covers: 5 bytes OID prefix + 1 byte string-tag + 1
  // byte length. Subtraction is the inverse.
  //
  // Defense-in-depth self-check: re-read the 7 OID-anchor bytes from
  // the absolute cert DER and verify they match the expected ASN.1
  // frame (`06 03 55 04 05 <13|0c> NN`). If the offset is wrong, this
  // surfaces a clear SDK-side error at build time rather than a
  // cryptic constraint failure ~10 s into the prove. Same condition
  // the circuit's §6.9b block enforces; we duplicate at the SDK layer
  // so misconfigurations fail fast.
  const valueOffsetInTbsRaw = (v51Witness as Record<string, unknown>)
    .subjectSerialValueOffsetInTbs;
  if (typeof valueOffsetInTbsRaw !== 'number') {
    throw new Error(
      'V5.3 OID-anchor: V5.1 builder did not emit ' +
        '`subjectSerialValueOffsetInTbs` as a number — V5.1 contract drift?',
    );
  }
  const valueOffsetAbsRaw = (v51Witness as Record<string, unknown>)
    .subjectSerialValueOffset;
  if (typeof valueOffsetAbsRaw !== 'number') {
    throw new Error(
      'V5.3 OID-anchor: V5.1 builder did not emit ' +
        '`subjectSerialValueOffset` as a number — V5.1 contract drift?',
    );
  }
  if (valueOffsetInTbsRaw < 7) {
    throw new Error(
      `V5.3 OID-anchor: subjectSerialValueOffsetInTbs=${valueOffsetInTbsRaw} ` +
        '< 7; cannot derive OID-offset (would underflow into TBS header).',
    );
  }
  const oidOffsetInTbs = valueOffsetInTbsRaw - 7;
  const oidOffsetAbs = valueOffsetAbsRaw - 7;

  // Bounds guard: the 7-byte OID-anchor frame at oidOffsetAbs must fit
  // entirely inside the cert DER. A short slice would silently
  // compare-against-undefined in the loop below; fail fast with a
  // pointed message instead.
  if (oidOffsetAbs < 0 || oidOffsetAbs + 7 > input.leafCertDer.length) {
    throw new Error(
      `V5.3 OID-anchor: derived oidOffsetAbs=${oidOffsetAbs} (+7) out of ` +
        `range for leafCertDer.length=${input.leafCertDer.length}; ` +
        'subjectSerial parser produced an inconsistent value-offset.',
    );
  }

  // ASN.1 self-check: leafCertDer[oidAbs..oidAbs+5] must equal
  // `06 03 55 04 05` (DER-encoded OID 2.5.4.5 = id-at-serialNumber).
  // The bounds guard above ensures the slice has the full 5 bytes, so
  // the indexed accesses below are not actually `undefined`; we cast
  // through `Uint8Array` once to satisfy `noUncheckedIndexedAccess`
  // without scattering `!` assertions through the hot loop.
  const oidPrefix = Uint8Array.from(
    input.leafCertDer.subarray(oidOffsetAbs, oidOffsetAbs + 5),
  );
  const expectedPrefix = [0x06, 0x03, 0x55, 0x04, 0x05] as const;
  for (let i = 0; i < 5; i++) {
    if (oidPrefix[i] !== expectedPrefix[i]) {
      const got = Array.from(oidPrefix, (b) =>
        b.toString(16).padStart(2, '0'),
      ).join(' ');
      throw new Error(
        `V5.3 OID-anchor: leafCertDer[${oidOffsetAbs}..${oidOffsetAbs + 5}] = ${got}; ` +
          'expected `06 03 55 04 05` (DER OID 2.5.4.5 id-at-serialNumber). ' +
          'subjectSerial parser may be off, or the cert lacks an explicit ' +
          'subject.serialNumber RDN.',
      );
    }
  }

  // String-tag check: leafCertDer[oidAbs+5] must be 0x13 (PrintableString)
  // or 0x0c (UTF8String). Other DirectoryString choices (BMPString 0x1e,
  // UniversalString 0x1c, TeletexString 0x14) are theoretically valid
  // X.520 but the V5.3 circuit only accepts the two QTSP-canonical tags
  // per spec §F1.2. Surface as a build-time error so the user gets a
  // clear "your cert encodes serialNumber as <foo>; only PrintableString
  // and UTF8String are accepted by the QKB v5 verifier" message.
  //
  // The bounds guard (oidOffsetAbs + 7 ≤ length) guarantees this byte
  // exists, but `noUncheckedIndexedAccess` types it as
  // `number | undefined`; the explicit `=== undefined` branch satisfies
  // both TS and a defence-in-depth narrative.
  const stringTag = input.leafCertDer[oidOffsetAbs + 5];
  if (stringTag === undefined || (stringTag !== 0x13 && stringTag !== 0x0c)) {
    const tagDisplay =
      stringTag === undefined
        ? '<missing>'
        : `0x${stringTag.toString(16).padStart(2, '0')}`;
    throw new Error(
      `V5.3 OID-anchor: subject.serialNumber DirectoryString tag at ` +
        `offset ${oidOffsetAbs + 5} is ${tagDisplay}; ` +
        'V5.3 circuit accepts only 0x13 (PrintableString) or 0x0c (UTF8String). ' +
        'Spec §F1.2.',
    );
  }

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
    // V5.3 F1 — emit as decimal string per snarkjs's witness JSON
    // numeric convention.
    subjectSerialOidOffsetInTbs: oidOffsetInTbs.toString(),
  };
}
