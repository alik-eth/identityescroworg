import { describe, expect, it } from 'vitest';
import { bytes32ToHiLo, hiLoToBytes32 } from './bytes32ToHiLo.js';

describe('bytes32ToHiLo (V5 convention: top-16 / bottom-16, big-endian)', () => {
  it('splits a deterministic 32-byte BE value into hi=top16 + lo=bot16', () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = i + 1;  // 0x01, 0x02, ..., 0x20
    const { hi, lo } = bytes32ToHiLo(bytes);
    // top 16 bytes interpreted big-endian: 0x0102...0x10
    expect(hi).toBe(0x0102030405060708090a0b0c0d0e0f10n);
    // bottom 16 bytes interpreted big-endian: 0x1112...0x20
    expect(lo).toBe(0x1112131415161718191a1b1c1d1e1f20n);
  });

  it('handles all-zero input', () => {
    const { hi, lo } = bytes32ToHiLo(new Uint8Array(32));
    expect(hi).toBe(0n);
    expect(lo).toBe(0n);
  });

  it('handles all-0xff input (max uint128 in each half)', () => {
    const bytes = new Uint8Array(32).fill(0xff);
    const { hi, lo } = bytes32ToHiLo(bytes);
    expect(hi).toBe((1n << 128n) - 1n);
    expect(lo).toBe((1n << 128n) - 1n);
  });

  it('round-trips random 32-byte inputs through hiLoToBytes32', () => {
    for (let trial = 0; trial < 16; trial++) {
      const bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);
      const { hi, lo } = bytes32ToHiLo(bytes);
      expect(hiLoToBytes32(hi, lo)).toEqual(bytes);
    }
  });

  it('rejects non-32-byte input', () => {
    expect(() => bytes32ToHiLo(new Uint8Array(31))).toThrow(/32/);
    expect(() => bytes32ToHiLo(new Uint8Array(33))).toThrow(/32/);
    expect(() => bytes32ToHiLo(new Uint8Array(0))).toThrow(/32/);
  });

  it('hiLoToBytes32 rejects out-of-range hi/lo', () => {
    expect(() => hiLoToBytes32(1n << 128n, 0n)).toThrow(/hi/);
    expect(() => hiLoToBytes32(0n, 1n << 128n)).toThrow(/lo/);
    expect(() => hiLoToBytes32(-1n, 0n)).toThrow(/hi/);
    expect(() => hiLoToBytes32(0n, -1n)).toThrow(/lo/);
  });

  it('matches the canonical V5 SHA-256 hi/lo example: sha256("") split', () => {
    // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    // Top 16 bytes: e3b0c44298fc1c149afbf4c8996fb924
    // Bot 16 bytes: 27ae41e4649b934ca495991b7852b855
    const sha256EmptyHex =
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(sha256EmptyHex.slice(i * 2, i * 2 + 2), 16);
    }
    const { hi, lo } = bytes32ToHiLo(bytes);
    expect(hi.toString(16)).toBe('e3b0c44298fc1c149afbf4c8996fb924');
    expect(lo.toString(16)).toBe('27ae41e4649b934ca495991b7852b855');
  });
});
