/**
 * SHA-256 byte padding per FIPS 180-4 §5.1.1.
 *
 * Returns the message followed by 0x80, zero-padding, and the original
 * message length in bits encoded big-endian over the final 8 bytes.
 * The output length is a multiple of 64 bytes.
 *
 * Used by tests to pre-pad inputs the way @qkb/web's witness builder will
 * eventually pre-pad them in production.
 */
export function shaPad(msg: Uint8Array): Uint8Array {
  const bitLen = BigInt(msg.length) * 8n;
  // 1 byte for 0x80, 8 bytes for length, plus message → round up to 64.
  const padded = new Uint8Array(Math.ceil((msg.length + 1 + 8) / 64) * 64);
  padded.set(msg, 0);
  padded[msg.length] = 0x80;
  // length BE in last 8 bytes
  const view = new DataView(padded.buffer);
  view.setBigUint64(padded.length - 8, bitLen, false);
  return padded;
}

/**
 * Right-pads a Uint8Array with zeros to length `target`.
 */
export function rightPadZero(buf: Uint8Array, target: number): number[] {
  if (buf.length > target) {
    throw new Error(`buffer length ${buf.length} exceeds target ${target}`);
  }
  const out = new Array<number>(target).fill(0);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i]!;
  return out;
}

/**
 * Decodes a 256-bit hash from a circom witness slice (256 individual bit
 * signals, MSB-first within each 32-bit word as emitted by Sha256Bytes) into
 * the canonical 32-byte SHA-256 digest.
 */
export function hashFromWitnessBits(bits: bigint[]): Uint8Array {
  if (bits.length !== 256) {
    throw new Error(`expected 256 bits, got ${bits.length}`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | Number(bits[i * 8 + j]!);
    }
    out[i] = byte;
  }
  return out;
}
