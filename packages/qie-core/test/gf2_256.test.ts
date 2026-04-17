import { describe, it, expect } from "vitest";
import { gfAdd, gfMul, gfInv, gfPow } from "../src/gf2_256";

const ONE = new Uint8Array(32); ONE[31] = 1;
const TWO = new Uint8Array(32); TWO[31] = 2;

describe("GF(2^256) arithmetic", () => {
  it("add is xor", () => {
    const a = new Uint8Array(32).fill(0xab);
    const b = new Uint8Array(32).fill(0xcd);
    const r = gfAdd(a, b);
    expect(r.every(x => x === (0xab ^ 0xcd))).toBe(true);
  });
  it("1 * x = x", () => {
    const x = new Uint8Array(32); x[0] = 0x55; x[15] = 0xaa;
    expect(gfMul(ONE, x)).toEqual(x);
  });
  it("x * x^-1 = 1 (nonzero)", () => {
    const x = new Uint8Array(32); x[31] = 7;
    const inv = gfInv(x);
    expect(gfMul(x, inv)).toEqual(ONE);
  });
  it("gfPow(2, 256) = reduction poly applied", () => {
    // 2^256 mod (x^256 + x^10 + x^5 + x^2 + 1) = x^10 + x^5 + x^2 + 1
    const r = gfPow(TWO, 256n);
    const expected = new Uint8Array(32);
    // bit positions 10,5,2,0 → byte 31 bit 0 = 1<<0 | 1<<2 | 1<<5 = 0x25; byte 30 bit 10%8=2 → 0x04
    expected[31] = 0x25; expected[30] = 0x04;
    expect(r).toEqual(expected);
  });
});
