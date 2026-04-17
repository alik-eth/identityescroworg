// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from "vitest";
import { makeBrowserAgent } from "../../src/browser/agent.js";

describe("makeBrowserAgent", () => {
  beforeEach(() => globalThis.localStorage.clear());

  it("generates and persists a hybrid keypair on first boot", async () => {
    const a1 = await makeBrowserAgent({ agentId: "agent-a" });
    const a2 = await makeBrowserAgent({ agentId: "agent-a" });
    expect(a1.hybridPublicKey.x25519).toEqual(a2.hybridPublicKey.x25519);
    expect(a1.hybridPublicKey.mlkem).toEqual(a2.hybridPublicKey.mlkem);
  });

  it("onEscrowReceived stores the ciphertext and returns an ack", async () => {
    const a = await makeBrowserAgent({ agentId: "agent-a" });
    const escrowId = ("0x" + "ab".repeat(32)) as `0x${string}`;

    // Build a minimal valid config whose computeEscrowId matches `escrowId`.
    // We mint the config, compute the id, and assert using THAT id — the
    // D1 plan's literal `escrowId` is illustrative, not a hash preimage.
    const aPk = a.hybridPublicKey;
    const minimalConfig = {
      version: "QIE/1.0" as const,
      pk: ("0x04" + "aa".repeat(64)) as `0x04${string}`,
      agents: [{
        agent_id: "agent-a",
        hybrid_pk: {
          x25519: "0x" + Buffer.from(aPk.x25519).toString("hex"),
          mlkem: "0x" + Buffer.from(aPk.mlkem).toString("hex"),
        },
        endpoint: "browser://agent-a",
      }],
      threshold: 1,
      recipient_hybrid_pk: {
        x25519: "0x" + "11".repeat(32),
        mlkem: "0x" + "22".repeat(1184),
      },
      arbitrator: { chain_id: 31337, address: ("0x" + "cc".repeat(20)) as `0x${string}`, kind: "authority" as const },
      expiry: Math.floor(Date.now() / 1000) + 3600,
      jurisdiction: "UA",
      unlock_predicate: "A_OR_C" as const,
    };
    const { computeEscrowId } = await import("@qkb/qie-core");
    const { hydrateConfig } = await import("../../src/wire.js");
    const realId = computeEscrowId(hydrateConfig(minimalConfig));

    const ack = await a.onEscrowReceived({
      escrowId: realId,
      config: minimalConfig,
      ct: {
        kem_ct: {
          x25519_ct: "0x" + "dd".repeat(32),
          mlkem_ct: "0x" + "ee".repeat(1088),
        },
        wrap: "0x" + "ff".repeat(45),
      },
      encR: "0x" + "99".repeat(64),
    });
    expect(ack.ackSig).toMatch(/^0x[0-9a-f]+$/);
    const inbox = a.listInbox();
    expect(inbox).toHaveLength(1);
    expect(inbox[0]!.escrowId).toBe(realId);
    // Silence unused guard
    void escrowId;
  });
});
