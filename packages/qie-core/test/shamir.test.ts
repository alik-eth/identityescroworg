import { describe, it, expect } from "vitest";
import { splitShares, reconstructShares } from "../src/shamir.js";
import { randomBytes } from "@noble/hashes/utils";

describe("Shamir GF(2^256)", () => {
  it("round-trip t=2 of n=3", () => {
    const secret = randomBytes(32);
    const shares = splitShares(secret, 3, 2);
    expect(shares).toHaveLength(3);
    const recovered = reconstructShares([shares[0]!, shares[2]!]);
    expect(recovered).toEqual(secret);
  });

  it("round-trip every (t,n) combo up to n=8", () => {
    const secret = randomBytes(32);
    for (let n = 2; n <= 8; n++) {
      for (let t = 1; t <= n; t++) {
        const shares = splitShares(secret, n, t);
        const pick = shares.slice(0, t);
        expect(reconstructShares(pick)).toEqual(secret);
      }
    }
  });

  it("t-1 shares do not reveal secret", () => {
    const secret = randomBytes(32);
    const shares = splitShares(secret, 3, 3);
    const wrong = reconstructShares(shares.slice(0, 2));
    expect(wrong).not.toEqual(secret);
  });

  it("duplicate indices throw", () => {
    const a = { index: 1, value: new Uint8Array(32) };
    const b = { index: 1, value: new Uint8Array(32) };
    expect(() => reconstructShares([a, b])).toThrow(/duplicate/i);
  });

  it("threshold 1 returns secret verbatim", () => {
    const secret = randomBytes(32);
    const shares = splitShares(secret, 3, 1);
    for (const s of shares) expect(s.value).toEqual(secret);
  });
});
