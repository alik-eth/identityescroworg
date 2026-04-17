import { describe, it, expect } from "vitest";
import { buildEnvelope, reconstructRecovery } from "../src/build.js";
import { buildEscrowConfig } from "../src/config.js";
import { generateHybridKeypair, hybridDecapsulate } from "../src/hybrid-kem.js";
import { unwrapShare } from "../src/envelope.js";
import { randomBytes } from "@noble/hashes/utils";

function makeAgents(n: number) {
  const keys = Array.from({ length: n }, () => generateHybridKeypair());
  const agents = keys.map((k, i) => ({
    agent_id: `agent-${i}`,
    hybrid_pk: k.pk,
    endpoint: `https://agent-${i}/`,
  }));
  return { agents, sks: keys.map(k => k.sk) };
}

describe("envelope build + recover", () => {
  it("3-of-3 round-trip", () => {
    const { agents, sks } = makeAgents(3);
    const recipient = generateHybridKeypair();
    const cfg = buildEscrowConfig({
      pk: ("0x04" + "a".repeat(128)) as `0x04${string}`,
      agents,
      threshold: 3,
      recipient_hybrid_pk: recipient.pk,
      arbitrator: { chain_id: 31337, address: "0x0000000000000000000000000000000000000001", kind: "authority" },
      expiry: 2000000000,
      jurisdiction: "UA",
    });
    const R = new TextEncoder().encode("recovery-material-here");
    const env = buildEnvelope(cfg, R);
    expect(env.wrappedShares).toHaveLength(3);
    expect(env.escrowId).toMatch(/^0x[0-9a-f]{64}$/);
    const aad = new TextEncoder().encode(env.escrowId);
    const shares = env.wrappedShares.map((ws, i) => {
      const ss = hybridDecapsulate(sks[i]!, ws.ct.kem_ct);
      const aadI = new Uint8Array(aad.length + agents[i]!.agent_id.length);
      aadI.set(aad); aadI.set(new TextEncoder().encode(agents[i]!.agent_id), aad.length);
      return unwrapShare(ss, ws.ct.wrap, aadI);
    });
    const got = reconstructRecovery({ config: env.config, encR: env.encR }, shares);
    expect(new TextDecoder().decode(got)).toBe("recovery-material-here");
  });

  it("2-of-3: any 2 suffice", () => {
    const { agents, sks } = makeAgents(3);
    const recipient = generateHybridKeypair();
    const cfg = buildEscrowConfig({
      pk: ("0x04" + "b".repeat(128)) as `0x04${string}`,
      agents, threshold: 2,
      recipient_hybrid_pk: recipient.pk,
      arbitrator: { chain_id: 31337, address: "0x0000000000000000000000000000000000000002", kind: "timelock" },
      expiry: 2000000000, jurisdiction: "UA",
    });
    const R = randomBytes(512);
    const env = buildEnvelope(cfg, R);
    const aad = new TextEncoder().encode(env.escrowId);
    const pick = [0, 2];
    const shares = pick.map(i => {
      const ws = env.wrappedShares[i]!;
      const ss = hybridDecapsulate(sks[i]!, ws.ct.kem_ct);
      const aadI = new Uint8Array(aad.length + agents[i]!.agent_id.length);
      aadI.set(aad); aadI.set(new TextEncoder().encode(agents[i]!.agent_id), aad.length);
      return unwrapShare(ss, ws.ct.wrap, aadI);
    });
    const got = reconstructRecovery({ config: env.config, encR: env.encR }, shares);
    expect(got).toEqual(R);
  });
});
