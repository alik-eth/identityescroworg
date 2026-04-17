#!/usr/bin/env node
// qie-agent CLI: reads an agent key file + env config, starts the Fastify server.
// Key file shape (matches fixtures/qie/agents/<id>.keys.json — gitignored):
// {
//   "agent_id": "ua-qtsp-demo-0",
//   "ack_sk": "0x<32B ed25519 seed>",
//   "hybrid_sk": { "x25519": "0x<32B>", "mlkem": "0x<2400B>" },
//   "hybrid_pk": { "x25519": "0x<32B>", "mlkem": "0x<1184B>" }
// }
// Env vars:
//   QIE_AGENT_KEYS_PATH       — required, path to the key file above
//   QIE_AGENT_STORAGE         — optional, default /data/escrow
//   QIE_AGENT_HOST            — optional, default 0.0.0.0
//   QIE_AGENT_PORT            — optional, default 8080
//   QIE_RPC_URL               — optional, viem RPC for EscrowStateReader
//   QIE_REGISTRY_ADDRESS      — optional, QKBRegistry deployment addr
//   QIE_TRUSTED_CAS_PATH      — optional, path to pumped trusted-cas.json
//   STATE_READER_DISABLED     — optional, set to "1" to skip the state gate
//                                (legacy Phase 1 behaviour; integration tests)
import { readFileSync } from "node:fs";
import { buildServer } from "../server.js";
import { makeEscrowStateReader } from "../escrow-state-reader.js";
import { makeCadesVerifiers } from "../qes-verify.js";
import type { Address } from "viem";

interface KeyFile {
  agent_id: string;
  ack_sk: string;
  hybrid_sk: { x25519: string; mlkem: string };
  hybrid_pk: { x25519: string; mlkem: string };
}

function env(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined) throw new Error(`missing env: ${name}`);
  return v;
}

function envOpt(name: string): string | undefined {
  return process.env[name];
}

function hexToBytes(h: string): Uint8Array {
  return Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
}

async function main(): Promise<void> {
  const keysPath = env("QIE_AGENT_KEYS_PATH");
  const keys = JSON.parse(readFileSync(keysPath, "utf8")) as KeyFile;

  // Optional CAdES verifier wiring — both qesVerify and notaryVerify share
  // the same LOTL snapshot. If QIE_TRUSTED_CAS_PATH isn't set, we fall
  // back to the safe default (qesVerify returns false; notary attestations
  // are rejected as QIE_NOTARY_CHAIN_UNTRUSTED).
  const trustedCasPath = envOpt("QIE_TRUSTED_CAS_PATH");
  const cadesHooks = trustedCasPath ? makeCadesVerifiers(trustedCasPath) : undefined;

  // Optional on-chain state reader. Production MUST wire this; tests/dev
  // can set STATE_READER_DISABLED=1 to preserve the legacy Phase-1 path.
  const stateDisabled = envOpt("STATE_READER_DISABLED") === "1";
  const rpcUrl = envOpt("QIE_RPC_URL");
  const registryAddress = envOpt("QIE_REGISTRY_ADDRESS") as Address | undefined;
  let escrowStateReader;
  if (!stateDisabled && rpcUrl && registryAddress) {
    escrowStateReader = makeEscrowStateReader({ rpcUrl, registryAddress });
  }

  const app = await buildServer({
    agentId: keys.agent_id,
    storageDir: env("QIE_AGENT_STORAGE", "/data/escrow"),
    ackSeed: hexToBytes(keys.ack_sk),
    hybridSk: { x25519: hexToBytes(keys.hybrid_sk.x25519), mlkem: hexToBytes(keys.hybrid_sk.mlkem) },
    hybridPk: { x25519: hexToBytes(keys.hybrid_pk.x25519), mlkem: hexToBytes(keys.hybrid_pk.mlkem) },
    chainRpcByChainId: {},
    ...(cadesHooks ? { qesVerify: cadesHooks.qesVerify, notaryVerify: cadesHooks.notaryVerify } : {}),
    ...(escrowStateReader ? { escrowStateReader } : {}),
  });

  const host = env("QIE_AGENT_HOST", "0.0.0.0");
  const port = Number(env("QIE_AGENT_PORT", "8080"));
  await app.listen({ host, port });
  const gateInfo = escrowStateReader ? "state-gate=on" : (stateDisabled ? "state-gate=disabled" : "state-gate=unwired");
  const cadesInfo = cadesHooks ? "cades=on" : "cades=off";
  console.error(`qie-agent ${keys.agent_id} listening on ${host}:${port} [${gateInfo}] [${cadesInfo}]`);
}

main().catch((e: unknown) => { console.error(e); process.exit(1); });
