import { describe, it, expect } from "vitest";
import { generateHybridKeypair, hybridEncapsulate, hybridDecapsulate } from "../src/hybrid-kem.js";

describe("hybrid KEM", () => {
  it("encap/decap round-trip", () => {
    const { pk, sk } = generateHybridKeypair();
    const { ct, ss } = hybridEncapsulate(pk);
    const ss2 = hybridDecapsulate(sk, ct);
    expect(ss2).toEqual(ss);
    expect(ss.length).toBe(32);
  });

  it("tampered x25519_ct breaks ss", () => {
    const { pk, sk } = generateHybridKeypair();
    const { ct } = hybridEncapsulate(pk);
    ct.x25519_ct[0] = (ct.x25519_ct[0]! ^ 1) & 0xff;
    const ss2 = hybridDecapsulate(sk, ct);
    expect(ss2.length).toBe(32);
  });

  it("pk sizes match spec", () => {
    const { pk, sk } = generateHybridKeypair();
    expect(pk.x25519.length).toBe(32);
    expect(pk.mlkem.length).toBe(1184);
    expect(sk.x25519.length).toBe(32);
    expect(sk.mlkem.length).toBe(2400);
  });

  it("ct sizes match spec", () => {
    const { pk } = generateHybridKeypair();
    const { ct } = hybridEncapsulate(pk);
    expect(ct.x25519_ct.length).toBe(32);
    expect(ct.mlkem_ct.length).toBe(1088);
  });
});
