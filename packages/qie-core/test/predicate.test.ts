import { describe, it, expect } from "vitest";
import { evaluatePredicate } from "../src/predicate.js";
import { buildEscrowConfig } from "../src/config.js";
import { generateHybridKeypair } from "../src/hybrid-kem.js";
import type { Evidence } from "../src/types.js";
import { keccak_256 } from "@noble/hashes/sha3";

function cfgFixture() {
  const rec = generateHybridKeypair();
  return buildEscrowConfig({
    pk: ("0x04" + "a".repeat(128)) as `0x04${string}`,
    agents: [{ agent_id: "a0", hybrid_pk: generateHybridKeypair().pk, endpoint: "https://a0/" }],
    threshold: 1,
    recipient_hybrid_pk: rec.pk,
    arbitrator: { chain_id: 11155111, address: "0x000000000000000000000000000000000000aAaA", kind: "authority" },
    expiry: 2000000000, jurisdiction: "UA",
  });
}

const UNLOCK_TOPIC = "0x" + Buffer.from(keccak_256(new TextEncoder().encode("Unlock(bytes32,bytes)"))).toString("hex");

describe("predicate", () => {
  it("A-path: valid matching event → ok", async () => {
    const cfg = cfgFixture();
    const escrowId = "0x" + "a".repeat(64);
    const evidence: Evidence = { kind: "A", chainId: 11155111, txHash: ("0x" + "b".repeat(64)) as `0x${string}`, logIndex: 0 };
    // Force topics[1] to match this cfg's actual escrowId
    const { computeEscrowId } = await import("../src/config.js");
    const realId = computeEscrowId(cfg);
    const rpc = (_id: number) => ({
      getLog: async (_tx: `0x${string}`, _idx: number) => ({
        address: cfg.arbitrator.address.toLowerCase(),
        topics: [UNLOCK_TOPIC, realId],
        data: "0x" + "cc".repeat(65),
      }),
    });
    void escrowId;
    const r = await evaluatePredicate(evidence, cfg, { rpc, qesVerify: async () => false });
    expect(r.ok).toBe(true);
  });

  it("A-path: wrong arbitrator address → EVIDENCE_ARBITRATOR_MISMATCH", async () => {
    const cfg = cfgFixture();
    const rpc = (_id: number) => ({
      getLog: async () => ({ address: "0x0000000000000000000000000000000000000000", topics: [UNLOCK_TOPIC], data: "0x" }),
    });
    const r = await evaluatePredicate(
      { kind: "A", chainId: 11155111, txHash: ("0x" + "0".repeat(64)) as `0x${string}`, logIndex: 0 },
      cfg, { rpc, qesVerify: async () => false });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("EVIDENCE_ARBITRATOR_MISMATCH");
  });

  it("A-path: event not found → EVIDENCE_EVENT_NOT_FOUND", async () => {
    const cfg = cfgFixture();
    const rpc = (_id: number) => ({ getLog: async () => null });
    const r = await evaluatePredicate(
      { kind: "A", chainId: 11155111, txHash: ("0x" + "0".repeat(64)) as `0x${string}`, logIndex: 0 },
      cfg, { rpc, qesVerify: async () => false });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("EVIDENCE_EVENT_NOT_FOUND");
  });

  it("C-path: valid QES countersig → ok", async () => {
    const cfg = cfgFixture();
    const r = await evaluatePredicate(
      { kind: "C", countersig: { p7s: new Uint8Array([1, 2]), cert: new Uint8Array([3, 4]) } },
      cfg,
      { rpc: () => ({ getLog: async () => null }), qesVerify: async () => true },
    );
    expect(r.ok).toBe(true);
  });

  it("C-path: invalid QES → EVIDENCE_SIG_INVALID", async () => {
    const cfg = cfgFixture();
    const r = await evaluatePredicate(
      { kind: "C", countersig: { p7s: new Uint8Array([1, 2]), cert: new Uint8Array([3, 4]) } },
      cfg,
      { rpc: () => ({ getLog: async () => null }), qesVerify: async () => false },
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("EVIDENCE_SIG_INVALID");
  });
});
