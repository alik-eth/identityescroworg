/**
 * Big-endian 32-byte → (hi, lo) split as two uint128s.
 *
 * V5 hi/lo convention — must be byte-equivalent across:
 *   - circuits-eng's `Bytes32ToHiLo` circom primitive
 *   - contracts-eng's calldata-binding gate (Gate 2a, sha256(signedAttrs))
 *   - this TS helper, used to derive PublicSignals.{...}HashHi/Lo from the
 *     witness builder's SHA-256 outputs.
 *
 * `hi` = top 16 bytes interpreted as big-endian uint128.
 * `lo` = bottom 16 bytes interpreted as big-endian uint128.
 *
 * This is NOT a little-endian split, NOT a field-reduced split, and NOT
 * keyed by any hash-of-hash. Just a pure big-endian byte split — the
 * simplest convention and the one all three impls agreed on.
 */
export function bytes32ToHiLo(bytes: Uint8Array): { hi: bigint; lo: bigint } {
  if (bytes.length !== 32) {
    throw new Error(`bytes32ToHiLo: expected 32 bytes, got ${bytes.length}`);
  }
  let hi = 0n;
  let lo = 0n;
  for (let i = 0; i < 16; i++) hi = (hi << 8n) | BigInt(bytes[i]!);
  for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(bytes[i]!);
  return { hi, lo };
}

/**
 * Inverse of `bytes32ToHiLo`. Round-trip property: for any 32-byte input
 * `b`, `hiLoToBytes32(hi, lo)` reconstructs `b` byte-for-byte.
 */
export function hiLoToBytes32(hi: bigint, lo: bigint): Uint8Array {
  if (hi < 0n || hi >= 1n << 128n) {
    throw new Error(`hiLoToBytes32: hi out of uint128 range`);
  }
  if (lo < 0n || lo >= 1n << 128n) {
    throw new Error(`hiLoToBytes32: lo out of uint128 range`);
  }
  const out = new Uint8Array(32);
  let h = hi;
  let l = lo;
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(h & 0xffn);
    h >>= 8n;
  }
  for (let i = 31; i >= 16; i--) {
    out[i] = Number(l & 0xffn);
    l >>= 8n;
  }
  return out;
}
