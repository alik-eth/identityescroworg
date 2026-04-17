import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "../src/server.js";
import { dehydrateConfig, bytes2hex } from "../src/wire.js";
import {
  buildEnvelope, buildEscrowConfig, generateHybridKeypair,
  type EscrowConfig, type HybridPublicKey,
} from "@qkb/qie-core";
import { keccak_256 } from "@noble/hashes/sha3";

const UNLOCK_TOPIC = bytes2hex(keccak_256(new TextEncoder().encode("Unlock(bytes32,bytes)")));

function mkCfg(agentPk: HybridPublicKey): EscrowConfig {
  return buildEscrowConfig({
    pk: ("0x04" + "a".repeat(128)) as `0x04${string}`,
    agents: [{ agent_id: "a0", hybrid_pk: agentPk, endpoint: "http://localhost/" }],
    threshold: 1,
    recipient_hybrid_pk: generateHybridKeypair().pk,
    arbitrator: { chain_id: 31337, address: "0x0000000000000000000000000000000000000001", kind: "authority" },
    expiry: 2000000000, jurisdiction: "UA",
  });
}

function wirePostBody(env: ReturnType<typeof buildEnvelope>) {
  const ws = env.wrappedShares[0]!;
  return {
    escrowId: env.escrowId,
    config: dehydrateConfig(env.config),
    ct: {
      kem_ct: { x25519_ct: bytes2hex(ws.ct.kem_ct.x25519_ct), mlkem_ct: bytes2hex(ws.ct.kem_ct.mlkem_ct) },
      wrap: bytes2hex(ws.ct.wrap),
    },
    encR: bytes2hex(env.encR),
  };
}

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "qie-state-")); });
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("release registry-state gate (Q3)", () => {
  for (const badState of ["NONE", "ACTIVE", "REVOKED"] as const) {
    it(`rejects release when on-chain state is ${badState} (409 QIE_ESCROW_WRONG_STATE)`, async () => {
      const agentKp = generateHybridKeypair();
      const cfg = mkCfg(agentKp.pk);
      const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
      const fakeRpc = () => ({
        getLog: async () => ({ address: cfg.arbitrator.address.toLowerCase(), topics: [UNLOCK_TOPIC, env.escrowId], data: "0x" }),
      });
      const app = await buildServer({
        agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(1),
        hybridPk: agentKp.pk, chainRpcByChainId: { 31337: fakeRpc },
        escrowStateReader: async () => badState,
      });
      try {
        await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
        const r = await app.inject({
          method: "POST", url: `/escrow/${env.escrowId}/release`,
          payload: {
            evidence: { kind: "A", chainId: 31337, txHash: "0x" + "1".repeat(64), logIndex: 0 },
            recipient_nonce: "0x" + "a".repeat(64),
          },
        });
        expect(r.statusCode).toBe(409);
        expect(r.json().error.code).toBe("QIE_ESCROW_WRONG_STATE");
      } finally { await app.close(); }
    });
  }

  for (const goodState of ["RELEASE_PENDING", "RELEASED"] as const) {
    it(`accepts release when on-chain state is ${goodState}`, async () => {
      const agentKp = generateHybridKeypair();
      const cfg = mkCfg(agentKp.pk);
      const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
      const fakeRpc = () => ({
        getLog: async () => ({ address: cfg.arbitrator.address.toLowerCase(), topics: [UNLOCK_TOPIC, env.escrowId], data: "0x" }),
      });
      const app = await buildServer({
        agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(2),
        hybridPk: agentKp.pk, chainRpcByChainId: { 31337: fakeRpc },
        escrowStateReader: async () => goodState,
      });
      try {
        await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
        const r = await app.inject({
          method: "POST", url: `/escrow/${env.escrowId}/release`,
          payload: {
            evidence: { kind: "A", chainId: 31337, txHash: "0x" + "1".repeat(64), logIndex: 0 },
            recipient_nonce: "0x" + "b".repeat(64),
          },
        });
        expect(r.statusCode).toBe(200);
      } finally { await app.close(); }
    });
  }

  it("no escrowStateReader wired → legacy behavior (no gate check)", async () => {
    const agentKp = generateHybridKeypair();
    const cfg = mkCfg(agentKp.pk);
    const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
    const fakeRpc = () => ({
      getLog: async () => ({ address: cfg.arbitrator.address.toLowerCase(), topics: [UNLOCK_TOPIC, env.escrowId], data: "0x" }),
    });
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(3),
      hybridPk: agentKp.pk, chainRpcByChainId: { 31337: fakeRpc },
      // no escrowStateReader — legacy path (preserves Phase 1 contract behavior)
    });
    try {
      await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      const r = await app.inject({
        method: "POST", url: `/escrow/${env.escrowId}/release`,
        payload: {
          evidence: { kind: "A", chainId: 31337, txHash: "0x" + "1".repeat(64), logIndex: 0 },
          recipient_nonce: "0x" + "c".repeat(64),
        },
      });
      expect(r.statusCode).toBe(200);
    } finally { await app.close(); }
  });
});
