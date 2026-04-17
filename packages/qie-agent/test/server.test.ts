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
      kem_ct: {
        x25519_ct: bytes2hex(ws.ct.kem_ct.x25519_ct),
        mlkem_ct: bytes2hex(ws.ct.kem_ct.mlkem_ct),
      },
      wrap: bytes2hex(ws.ct.wrap),
    },
    encR: bytes2hex(env.encR),
  };
}

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "qie-srv-")); });
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("agent server", () => {
  it("POST /escrow stores and returns ack; GET /config + /status work", async () => {
    const agentKp = generateHybridKeypair();
    const ackSeed = new Uint8Array(32).fill(7);
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed,
      hybridSk: agentKp.sk, hybridPk: agentKp.pk,
      chainRpcByChainId: {},
    });
    try {
      const cfg = mkCfg(agentKp.pk);
      const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
      const r = await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      expect(r.statusCode).toBe(200);
      const body = r.json();
      expect(body.agent_id).toBe("a0");
      expect(body.ack_sig).toMatch(/^0x[0-9a-f]+$/);

      const r2 = await app.inject({ method: "GET", url: `/escrow/${env.escrowId}/config` });
      expect(r2.statusCode).toBe(200);
      expect(r2.json().config.version).toBe("QIE/1.0");

      const r3 = await app.inject({ method: "GET", url: `/escrow/${env.escrowId}/status` });
      expect(r3.json().status).toBe("active");

      const r4 = await app.inject({ method: "GET", url: "/.well-known/qie-agent.json" });
      const w = r4.json();
      expect(w.agent_id).toBe("a0");
      expect(w.hybrid_pk.x25519).toMatch(/^0x[0-9a-f]{64}$/);
      expect(w.ack_pk).toMatch(/^0x[0-9a-f]{64}$/);
    } finally { await app.close(); }
  });

  it("POST /escrow rejects mismatched escrowId", async () => {
    const agentKp = generateHybridKeypair();
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(1),
      hybridPk: agentKp.pk, chainRpcByChainId: {},
    });
    try {
      const env = buildEnvelope(mkCfg(agentKp.pk), new TextEncoder().encode("R"));
      const body = wirePostBody(env);
      body.escrowId = ("0x" + "ff".repeat(32)) as `0x${string}`;
      const r = await app.inject({ method: "POST", url: "/escrow", payload: body });
      expect(r.statusCode).toBe(400);
      expect(r.json().error.code).toBe("QIE_CONFIG_MISMATCH");
    } finally { await app.close(); }
  });

  it("POST /escrow rejects when agent_id not in config", async () => {
    const agentKp = generateHybridKeypair();
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(2),
      chainRpcByChainId: {},
    });
    try {
      // Config names agent "different", but we're running as "a0"
      const otherAgent = { agent_id: "different", hybrid_pk: agentKp.pk, endpoint: "http://x/" };
      const cfg = buildEscrowConfig({
        pk: ("0x04" + "a".repeat(128)) as `0x04${string}`,
        agents: [otherAgent], threshold: 1,
        recipient_hybrid_pk: generateHybridKeypair().pk,
        arbitrator: { chain_id: 31337, address: "0x0000000000000000000000000000000000000001", kind: "authority" },
        expiry: 2000000000, jurisdiction: "UA",
      });
      const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
      const r = await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      expect(r.statusCode).toBe(400);
      expect(r.json().error.message).toMatch(/agent_id/);
    } finally { await app.close(); }
  });

  it("release A-path: valid event → ct + encR", async () => {
    const agentKp = generateHybridKeypair();
    const cfg = mkCfg(agentKp.pk);
    const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
    const fakeRpc = () => ({
      getLog: async () => ({
        address: cfg.arbitrator.address.toLowerCase(),
        topics: [UNLOCK_TOPIC, env.escrowId],
        data: "0x",
      }),
    });
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(9),
      hybridPk: agentKp.pk, chainRpcByChainId: { 31337: fakeRpc },
    });
    try {
      await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      const r = await app.inject({
        method: "POST", url: `/escrow/${env.escrowId}/release`,
        payload: {
          evidence: { kind: "A", chainId: 31337, txHash: "0x" + "f".repeat(64), logIndex: 0 },
          recipient_nonce: "0x" + "1".repeat(64),
        },
      });
      expect(r.statusCode).toBe(200);
      const body = r.json();
      expect(body.ct).toBeTruthy();
      expect(body.ct.wrap).toMatch(/^0x/);
      expect(body.encR).toMatch(/^0x/);
    } finally { await app.close(); }
  });

  it("release: replay of same nonce returns 409 REPLAY_DETECTED", async () => {
    const agentKp = generateHybridKeypair();
    const cfg = mkCfg(agentKp.pk);
    const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
    const fakeRpc = () => ({
      getLog: async () => ({ address: cfg.arbitrator.address.toLowerCase(), topics: [UNLOCK_TOPIC, env.escrowId], data: "0x" }),
    });
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(3),
      chainRpcByChainId: { 31337: fakeRpc },
    });
    try {
      await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      const nonce = "0x" + "2".repeat(64);
      const payload = {
        evidence: { kind: "A", chainId: 31337, txHash: "0x" + "e".repeat(64), logIndex: 0 },
        recipient_nonce: nonce,
      };
      const r1 = await app.inject({ method: "POST", url: `/escrow/${env.escrowId}/release`, payload });
      expect(r1.statusCode).toBe(200);
      const r2 = await app.inject({ method: "POST", url: `/escrow/${env.escrowId}/release`, payload });
      expect(r2.statusCode).toBe(409);
      expect(r2.json().error.code).toBe("QIE_REPLAY_DETECTED");
    } finally { await app.close(); }
  });

  it("release: missing escrow → 404 ESCROW_NOT_FOUND", async () => {
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(4),
      chainRpcByChainId: {},
    });
    try {
      const r = await app.inject({
        method: "POST", url: `/escrow/0x${"a".repeat(64)}/release`,
        payload: {
          evidence: { kind: "A", chainId: 31337, txHash: "0x" + "0".repeat(64), logIndex: 0 },
          recipient_nonce: "0x" + "5".repeat(64),
        },
      });
      expect(r.statusCode).toBe(404);
      expect(r.json().error.code).toBe("QIE_ESCROW_NOT_FOUND");
    } finally { await app.close(); }
  });

  it("sets Cache-Control: no-store on sensitive endpoints", async () => {
    const agentKp = generateHybridKeypair();
    const cfg = mkCfg(agentKp.pk);
    const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(11),
      hybridPk: agentKp.pk, chainRpcByChainId: {},
    });
    try {
      const r1 = await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      expect(r1.headers["cache-control"]).toMatch(/no-store/);
      const r2 = await app.inject({ method: "GET", url: `/escrow/${env.escrowId}/config` });
      expect(r2.headers["cache-control"]).toMatch(/no-store/);
      // well-known is publicly cacheable (discovery metadata) — no header set
      const r3 = await app.inject({ method: "GET", url: "/.well-known/qie-agent.json" });
      expect(r3.headers["cache-control"]).toBeUndefined();
    } finally { await app.close(); }
  });

  it("revocationSubscribe: event flips stored record to revoked", async () => {
    const agentKp = generateHybridKeypair();
    const cfg = mkCfg(agentKp.pk);
    const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
    let emit: (log: { escrowId: string }) => void = () => {};
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(12),
      hybridPk: agentKp.pk, chainRpcByChainId: {},
      registryAddr: "0x0000000000000000000000000000000000000099",
      revocationSubscribe: (cb) => { emit = cb; return () => {}; },
    });
    try {
      await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      emit({ escrowId: env.escrowId });
      await new Promise(r => setTimeout(r, 30));
      const r = await app.inject({ method: "GET", url: `/escrow/${env.escrowId}/status` });
      expect(r.json().status).toBe("revoked");
    } finally { await app.close(); }
  });

  it("release: C-path with valid qesVerify → ct + encR", async () => {
    const agentKp = generateHybridKeypair();
    const cfg = mkCfg(agentKp.pk);
    const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(5),
      chainRpcByChainId: {}, qesVerify: async () => true,
    });
    try {
      await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      const r = await app.inject({
        method: "POST", url: `/escrow/${env.escrowId}/release`,
        payload: {
          evidence: { kind: "C", countersig: { p7s: "0x1234", cert: "0xabcd" } },
          recipient_nonce: "0x" + "7".repeat(64),
        },
      });
      expect(r.statusCode).toBe(200);
      expect(r.json().ct).toBeTruthy();
    } finally { await app.close(); }
  });
});
