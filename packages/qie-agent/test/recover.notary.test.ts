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
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "qie-notary-")); });
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("release /escrow/:id/release on_behalf_of notary attestation (Q2)", () => {
  it("rejects on_behalf_of with untrusted notary chain (403 QIE_NOTARY_CHAIN_UNTRUSTED)", async () => {
    const agentKp = generateHybridKeypair();
    const cfg = mkCfg(agentKp.pk);
    const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(1),
      hybridPk: agentKp.pk, chainRpcByChainId: {},
      notaryVerify: async () => ({ chain: "untrusted", sigValid: false }),
    });
    try {
      await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      const r = await app.inject({
        method: "POST", url: `/escrow/${env.escrowId}/release`,
        payload: {
          recipient_pk: "0xabc",
          evidence: { kind: "A", chainId: 31337, txHash: "0x" + "1".repeat(64), logIndex: 0 },
          recipient_nonce: "0x" + "a".repeat(64),
          on_behalf_of: {
            recipient_pk: "0xabc",
            notary_cert: "0xdead",
            notary_sig: "0xbeef",
          },
        },
      });
      expect(r.statusCode).toBe(403);
      expect(r.json().error.code).toBe("QIE_NOTARY_CHAIN_UNTRUSTED");
    } finally { await app.close(); }
  });

  it("rejects on_behalf_of with mismatched recipient_pk (400 QIE_NOTARY_MISMATCH)", async () => {
    const agentKp = generateHybridKeypair();
    const cfg = mkCfg(agentKp.pk);
    const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(2),
      hybridPk: agentKp.pk, chainRpcByChainId: {},
      notaryVerify: async () => ({ chain: "trusted", sigValid: true, subject: "CN=Notary" }),
    });
    try {
      await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      const r = await app.inject({
        method: "POST", url: `/escrow/${env.escrowId}/release`,
        payload: {
          recipient_pk: "0xabc",
          evidence: { kind: "A", chainId: 31337, txHash: "0x" + "2".repeat(64), logIndex: 0 },
          recipient_nonce: "0x" + "b".repeat(64),
          on_behalf_of: {
            recipient_pk: "0xdifferent",
            notary_cert: "0xdead",
            notary_sig: "0xbeef",
          },
        },
      });
      expect(r.statusCode).toBe(400);
      expect(r.json().error.code).toBe("QIE_NOTARY_MISMATCH");
    } finally { await app.close(); }
  });

  it("rejects on_behalf_of with bad signature (403 QIE_NOTARY_SIG_BAD)", async () => {
    const agentKp = generateHybridKeypair();
    const cfg = mkCfg(agentKp.pk);
    const env = buildEnvelope(cfg, new TextEncoder().encode("R"));
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(3),
      hybridPk: agentKp.pk, chainRpcByChainId: {},
      notaryVerify: async () => ({ chain: "trusted", sigValid: false }),
    });
    try {
      await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      const r = await app.inject({
        method: "POST", url: `/escrow/${env.escrowId}/release`,
        payload: {
          recipient_pk: "0xabc",
          evidence: { kind: "A", chainId: 31337, txHash: "0x" + "3".repeat(64), logIndex: 0 },
          recipient_nonce: "0x" + "c".repeat(64),
          on_behalf_of: {
            recipient_pk: "0xabc",
            notary_cert: "0xdead",
            notary_sig: "0xbeef",
          },
        },
      });
      expect(r.statusCode).toBe(403);
      expect(r.json().error.code).toBe("QIE_NOTARY_SIG_BAD");
    } finally { await app.close(); }
  });

  it("accepts on_behalf_of when chain is trusted, sig valid, recipient matches", async () => {
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
    let verifiedPayload: Uint8Array | null = null;
    const app = await buildServer({
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(4),
      hybridPk: agentKp.pk, chainRpcByChainId: { 31337: fakeRpc },
      notaryVerify: async (_sig, _cert, payload) => {
        verifiedPayload = payload;
        return { chain: "trusted", sigValid: true, subject: "CN=Notary" };
      },
    });
    try {
      await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      const r = await app.inject({
        method: "POST", url: `/escrow/${env.escrowId}/release`,
        payload: {
          recipient_pk: "0xabc",
          evidence: { kind: "A", chainId: 31337, txHash: "0x" + "4".repeat(64), logIndex: 0 },
          recipient_nonce: "0x" + "d".repeat(64),
          on_behalf_of: {
            recipient_pk: "0xabc",
            notary_cert: "0xdead",
            notary_sig: "0xbeef",
          },
        },
      });
      expect(r.statusCode).toBe(200);
      expect(r.json().ct).toBeTruthy();
      // Payload is JCS of {domain,escrowId,recipient_pk} — key order alphabetical.
      const decoded = new TextDecoder().decode(verifiedPayload!);
      expect(decoded).toBe(
        `{"domain":"qie-notary-recover/v1","escrowId":"${env.escrowId}","recipient_pk":"0xabc"}`,
      );
    } finally { await app.close(); }
  });

  it("release without on_behalf_of is unaffected (self-recovery)", async () => {
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
      agentId: "a0", storageDir: dir, ackSeed: new Uint8Array(32).fill(5),
      hybridPk: agentKp.pk, chainRpcByChainId: { 31337: fakeRpc },
    });
    try {
      await app.inject({ method: "POST", url: "/escrow", payload: wirePostBody(env) });
      const r = await app.inject({
        method: "POST", url: `/escrow/${env.escrowId}/release`,
        payload: {
          evidence: { kind: "A", chainId: 31337, txHash: "0x" + "5".repeat(64), logIndex: 0 },
          recipient_nonce: "0x" + "e".repeat(64),
        },
      });
      expect(r.statusCode).toBe(200);
    } finally { await app.close(); }
  });
});
