import { describe, expect, it } from 'vitest';
import {
  ALGORITHM_TAG_ECDSA_STR,
  ALGORITHM_TAG_RSA_STR,
  MAX_BCANON,
  MAX_CERT,
  MAX_CTX,
  MAX_DECL,
  MAX_SA,
  MERKLE_DEPTH,
  bytes32ToLimbs643,
  digestToField,
  findJcsKeyValueOffset,
  packProof,
  pkCoordToLimbs,
  sha256Pad,
  subjectSerialToLimbs,
  zeroPadTo,
} from '../src/core/index.js';
import { QkbError } from '../src/errors/index.js';

describe('core constants', () => {
  it('matches the circuit-side compile-time caps', () => {
    expect(MAX_BCANON).toBe(1024);
    expect(MAX_SA).toBe(1536);
    expect(MAX_CERT).toBe(1536);
    expect(MAX_CTX).toBe(256);
    expect(MAX_DECL).toBe(960);
    expect(MERKLE_DEPTH).toBe(16);
    expect(ALGORITHM_TAG_RSA_STR).toBe('0');
    expect(ALGORITHM_TAG_ECDSA_STR).toBe('1');
  });
});

describe('sha256Pad', () => {
  it('produces a multiple-of-64 length with the FIPS 180-4 trailer', () => {
    const out = sha256Pad(new Uint8Array(0));
    expect(out.length % 64).toBe(0);
    expect(out[0]).toBe(0x80);
    expect(out[out.length - 1]).toBe(0); // bit length 0
  });

  it('encodes message bit length in the last 8 bytes BE', () => {
    const msg = new Uint8Array(3); // 24 bits
    const out = sha256Pad(msg);
    const bits = out.slice(-8);
    expect(Array.from(bits)).toEqual([0, 0, 0, 0, 0, 0, 0, 24]);
    expect(out[3]).toBe(0x80);
  });
});

describe('zeroPadTo', () => {
  it('right-pads with zeros to the requested length', () => {
    const out = zeroPadTo(new Uint8Array([1, 2, 3]), 8);
    expect(out).toEqual([1, 2, 3, 0, 0, 0, 0, 0]);
  });

  it('throws witness.fieldTooLong when input exceeds the cap', () => {
    expect(() => zeroPadTo(new Uint8Array(10), 4)).toThrow(QkbError);
  });
});

describe('pkCoordToLimbs', () => {
  it('packs 32 BE bytes into 4×64-bit LE limbs', () => {
    const bytes = new Uint8Array(32).map((_, i) => i + 1);
    const limbs = pkCoordToLimbs(bytes);
    expect(limbs).toHaveLength(4);
    // First limb is bytes[24..32] BE.
    expect(BigInt(limbs[0]!)).toBe(0x191a1b1c1d1e1f20n);
    // Last limb is bytes[0..8] BE.
    expect(BigInt(limbs[3]!)).toBe(0x0102030405060708n);
  });

  it('rejects non-32-byte inputs', () => {
    expect(() => pkCoordToLimbs(new Uint8Array(16))).toThrow(QkbError);
  });
});

describe('bytes32ToLimbs643', () => {
  it('packs 32 BE bytes into 6×43-bit LE limbs and round-trips', () => {
    const bytes = new Uint8Array(32).fill(0);
    bytes[31] = 1;
    const limbs = bytes32ToLimbs643(bytes);
    expect(limbs).toHaveLength(6);
    expect(limbs[0]).toBe('1');
    let recombined = 0n;
    for (let i = 5; i >= 0; i--) recombined = (recombined << 43n) | BigInt(limbs[i]!);
    expect(recombined).toBe(1n);
  });
});

describe('digestToField', () => {
  it('reduces a 32-byte BE blob mod BN254 p', () => {
    const bytes = new Uint8Array(32).fill(0xff);
    const v = digestToField(bytes);
    expect(BigInt(v) < 21888242871839275222246405745257275088548364400416034343698204186575808495617n).toBe(true);
  });
});

describe('findJcsKeyValueOffset', () => {
  it('returns the offset of the opening quote of the key', () => {
    const json = new TextEncoder().encode('{"a":1,"b":2}');
    expect(findJcsKeyValueOffset(json, 'a')).toBe(1);
    expect(findJcsKeyValueOffset(json, 'b')).toBe(7);
  });

  it('throws on duplicate keys', () => {
    const dup = new TextEncoder().encode('{"a":1,"a":2}');
    expect(() => findJcsKeyValueOffset(dup, 'a')).toThrow(QkbError);
  });

  it('throws when the key is missing', () => {
    const json = new TextEncoder().encode('{"a":1}');
    expect(() => findJcsKeyValueOffset(json, 'missing')).toThrow(QkbError);
  });
});

describe('subjectSerialToLimbs', () => {
  it('packs PrintableString bytes into 4×64-bit limbs, LSB-first within each group', () => {
    const ascii = new TextEncoder().encode('TEST');
    const limbs = subjectSerialToLimbs(ascii);
    expect(limbs).toHaveLength(4);
    // 'TEST' is 'T','E','S','T' = 0x54, 0x45, 0x53, 0x54.
    // First limb LSB-first: bytes[0]=0x54 ends up as low byte.
    expect(BigInt(limbs[0]!) & 0xffn).toBe(0x54n);
  });

  it('rejects empty or oversized inputs', () => {
    expect(() => subjectSerialToLimbs(new Uint8Array(0))).toThrow(QkbError);
    expect(() => subjectSerialToLimbs(new Uint8Array(33))).toThrow(QkbError);
  });
});

describe('packProof', () => {
  it('swaps pi_b coordinates for the BN254 verifier convention', () => {
    const proof = {
      pi_a: ['1', '2'],
      pi_b: [
        ['10', '11'],
        ['20', '21'],
      ],
      pi_c: ['3', '4'],
    };
    const packed = packProof(proof);
    expect(packed.a).toEqual(['1', '2']);
    expect(packed.c).toEqual(['3', '4']);
    expect(packed.b).toEqual([
      ['11', '10'],
      ['21', '20'],
    ]);
  });
});
