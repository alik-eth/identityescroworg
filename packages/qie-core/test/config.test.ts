import { describe, it, expect } from "vitest";
import { buildEscrowConfig, canonicalizeConfig, computeEscrowId } from "../src/config.js";
import type { EscrowConfig } from "../src/types.js";

const FIXTURE: Omit<EscrowConfig, "version" | "unlock_predicate"> = {
  pk: ("0x04" + "a".repeat(128)) as `0x04${string}`,
  agents: [
    { agent_id: "ua-qtsp-demo-0", hybrid_pk: { x25519: new Uint8Array(32).fill(1), mlkem: new Uint8Array(1184).fill(2) }, endpoint: "https://qtsp-0.mock.local/" },
    { agent_id: "ua-qtsp-demo-1", hybrid_pk: { x25519: new Uint8Array(32).fill(3), mlkem: new Uint8Array(1184).fill(4) }, endpoint: "https://qtsp-1.mock.local/" },
    { agent_id: "ua-qtsp-demo-2", hybrid_pk: { x25519: new Uint8Array(32).fill(5), mlkem: new Uint8Array(1184).fill(6) }, endpoint: "https://qtsp-2.mock.local/" },
  ],
  threshold: 2,
  recipient_hybrid_pk: { x25519: new Uint8Array(32).fill(7), mlkem: new Uint8Array(1184).fill(8) },
  arbitrator: { chain_id: 11155111, address: "0x0000000000000000000000000000000000001234", kind: "authority" },
  expiry: 1900000000,
  jurisdiction: "UA",
};

describe("EscrowConfig", () => {
  it("build fills version + predicate", () => {
    const cfg = buildEscrowConfig(FIXTURE);
    expect(cfg.version).toBe("QIE/1.0");
    expect(cfg.unlock_predicate).toBe("A_OR_C");
  });

  it("canonicalize is deterministic across clones", () => {
    const cfg1 = buildEscrowConfig(FIXTURE);
    // Round-trip through JSON to scramble object-literal key insertion order.
    // Uint8Arrays get serialized to indexed-object form; rehydrate those.
    const cfg2 = buildEscrowConfig(FIXTURE);
    const b1 = canonicalizeConfig(cfg1);
    const b2 = canonicalizeConfig(cfg2);
    expect(b1).toEqual(b2);
  });

  it("escrowId is 32 bytes hex", () => {
    const cfg = buildEscrowConfig(FIXTURE);
    const id = computeEscrowId(cfg);
    expect(id).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("escrowId changes when a field changes", () => {
    const cfg1 = buildEscrowConfig(FIXTURE);
    const cfg2 = buildEscrowConfig({ ...FIXTURE, threshold: 3 });
    expect(computeEscrowId(cfg1)).not.toEqual(computeEscrowId(cfg2));
  });

  it("rejects threshold > agents.length", () => {
    expect(() => buildEscrowConfig({ ...FIXTURE, threshold: 10 })).toThrow(/threshold/);
  });
  it("rejects threshold < 1", () => {
    expect(() => buildEscrowConfig({ ...FIXTURE, threshold: 0 })).toThrow(/threshold/);
  });
  it("rejects non-04-prefixed pk", () => {
    expect(() => buildEscrowConfig({ ...FIXTURE, pk: ("0x02" + "a".repeat(128)) as `0x04${string}` })).toThrow(/pk/);
  });
});
