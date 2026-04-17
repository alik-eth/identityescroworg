import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { hybridDecapsulate } from "../src/hybrid-kem.js";

const KAT_PATH = join(import.meta.dirname, "../../..", "fixtures/qie/hybrid-kat.json");

function hex(s: string): Uint8Array {
  const x = s.startsWith("0x") ? s.slice(2) : s;
  return new Uint8Array(Buffer.from(x, "hex"));
}

describe("hybrid KAT", () => {
  it("each frozen vector decapsulates to the recorded ss", () => {
    const payload = JSON.parse(readFileSync(KAT_PATH, "utf8")) as {
      version: string;
      vectors: Array<{
        label: string;
        sk: { x25519: string; mlkem: string };
        ct: { x25519_ct: string; mlkem_ct: string };
        ss: string;
      }>;
    };
    expect(payload.version).toBe("QIE/hybrid-kat/v1");
    expect(payload.vectors.length).toBeGreaterThan(0);
    for (const v of payload.vectors) {
      const sk = { x25519: hex(v.sk.x25519), mlkem: hex(v.sk.mlkem) };
      const ct = { x25519_ct: hex(v.ct.x25519_ct), mlkem_ct: hex(v.ct.mlkem_ct) };
      const got = hybridDecapsulate(sk, ct);
      const gotHex = "0x" + Buffer.from(got).toString("hex");
      expect(gotHex).toBe(v.ss);
    }
  });
});
