// Unit coverage for the ECDSA-Sig-Value SEQUENCE decoder.
// Mirrors arch-circuits f0d5a73's `build-admin-ecdsa-fixture.ts:123`
// reference impl on the cases that matter for V5 register calldata:
// 32-byte INTEGERs, sign-bit-padded 33-byte INTEGERs, short INTEGERs.
import { describe, expect, it } from 'vitest';
import { Buffer } from './_buffer-global';
import { decodeEcdsaSigSequence, bytes32ToHex } from './ecdsa-sig';

function buildSeq(r: number[], s: number[]): Uint8Array {
  // SEQUENCE { INTEGER r, INTEGER s }
  // Outer tag 0x30 + length + INT tag 0x02 + length + r + INT tag 0x02 +
  // length + s.
  const inner = Buffer.concat([
    Buffer.from([0x02, r.length]),
    Buffer.from(r),
    Buffer.from([0x02, s.length]),
    Buffer.from(s),
  ]);
  return Uint8Array.from([0x30, inner.length, ...inner]);
}

describe('decodeEcdsaSigSequence', () => {
  it('decodes plain 32-byte r and s without padding', () => {
    const r = Array.from({ length: 32 }, (_, i) => (i + 1) & 0xff);
    const s = Array.from({ length: 32 }, (_, i) => (i + 100) & 0xff);
    const result = decodeEcdsaSigSequence(buildSeq(r, s));
    expect(result.r.length).toBe(32);
    expect(result.s.length).toBe(32);
    expect(result.r.toString('hex')).toBe(Buffer.from(r).toString('hex'));
    expect(result.s.toString('hex')).toBe(Buffer.from(s).toString('hex'));
  });

  it('strips the leading 0x00 sign byte from 33-byte INTEGERs', () => {
    // High bit set on the first content byte (0x80) → DER prepends a 0x00
    // sign-byte to keep the INTEGER positive. Decoder strips it.
    const r33 = [0x00, 0x80, ...Array.from({ length: 31 }, () => 0x11)];
    const s33 = [0x00, 0xff, ...Array.from({ length: 31 }, () => 0x22)];
    const result = decodeEcdsaSigSequence(buildSeq(r33, s33));
    expect(result.r.length).toBe(32);
    expect(result.s.length).toBe(32);
    expect(result.r[0]).toBe(0x80);
    expect(result.s[0]).toBe(0xff);
  });

  it('left-pads short INTEGERs to 32 bytes', () => {
    // Real ECDSA r/s can be < 32 bytes when the high bytes happen to be 0.
    const rShort = [0x42, 0x42];
    const sShort = [0x99];
    const result = decodeEcdsaSigSequence(buildSeq(rShort, sShort));
    expect(result.r.length).toBe(32);
    expect(result.s.length).toBe(32);
    expect(result.r.subarray(0, 30).every((b) => b === 0)).toBe(true);
    expect(result.r.subarray(30, 32).toString('hex')).toBe('4242');
    expect(result.s.subarray(0, 31).every((b) => b === 0)).toBe(true);
    expect(result.s[31]).toBe(0x99);
  });

  it('rejects non-SEQUENCE input', () => {
    expect(() => decodeEcdsaSigSequence(Uint8Array.from([0x02, 0x01, 0x00])))
      .toThrow(/not a SEQUENCE/);
  });

  it('rejects INTEGER tag mismatch', () => {
    // Outer tag is right but inner tag isn't 0x02.
    const bad = Uint8Array.from([0x30, 0x04, 0x04, 0x01, 0x42, 0x02, 0x01, 0x00]);
    expect(() => decodeEcdsaSigSequence(bad)).toThrow(/expected INTEGER tag/);
  });
});

describe('bytes32ToHex', () => {
  it('emits 0x-prefixed 64-char hex', () => {
    const b = Buffer.alloc(32, 0xab);
    expect(bytes32ToHex(b)).toBe(`0x${'ab'.repeat(32)}`);
  });
});
