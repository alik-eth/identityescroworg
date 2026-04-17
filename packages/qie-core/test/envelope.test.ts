import { describe, it, expect } from "vitest";
import { wrapShare, unwrapShare, encryptRecovery, decryptRecovery } from "../src/envelope.js";
import { randomBytes } from "@noble/hashes/utils";

const AAD = new TextEncoder().encode("test-aad");

describe("envelope", () => {
  it("wrap/unwrap share round-trip", () => {
    const ss = randomBytes(32);
    const share = { index: 3, value: randomBytes(32) };
    const w = wrapShare(ss, share, AAD);
    expect(w.length).toBeGreaterThan(0);
    const got = unwrapShare(ss, w, AAD);
    expect(got).toEqual(share);
  });

  it("tampered tag fails unwrap", () => {
    const ss = randomBytes(32);
    const share = { index: 1, value: randomBytes(32) };
    const w = wrapShare(ss, share, AAD);
    w[w.length - 1] = (w[w.length - 1]! ^ 1) & 0xff;
    expect(() => unwrapShare(ss, w, AAD)).toThrow();
  });

  it("different aad fails unwrap", () => {
    const ss = randomBytes(32);
    const share = { index: 1, value: randomBytes(32) };
    const w = wrapShare(ss, share, AAD);
    expect(() => unwrapShare(ss, w, new TextEncoder().encode("other"))).toThrow();
  });

  it("encR round-trip", () => {
    const k = randomBytes(32);
    const R = randomBytes(2048);
    const escrowId = `0x${Buffer.from(randomBytes(32)).toString("hex")}` as `0x${string}`;
    const encR = encryptRecovery(k, R, escrowId);
    expect(encR.length).toBe(12 + R.length + 16);
    const got = decryptRecovery(k, encR, escrowId);
    expect(got).toEqual(R);
  });

  it("encR with wrong escrowId fails", () => {
    const k = randomBytes(32);
    const R = randomBytes(100);
    const id1 = `0x${"a".repeat(64)}` as `0x${string}`;
    const id2 = `0x${"b".repeat(64)}` as `0x${string}`;
    const encR = encryptRecovery(k, R, id1);
    expect(() => decryptRecovery(k, encR, id2)).toThrow();
  });
});
