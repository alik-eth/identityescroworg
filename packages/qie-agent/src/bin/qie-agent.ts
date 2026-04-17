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
//   QIE_AGENT_KEYS_PATH  — required, path to the key file above
//   QIE_AGENT_STORAGE    — optional, default /data/escrow
//   QIE_AGENT_HOST       — optional, default 0.0.0.0
//   QIE_AGENT_PORT       — optional, default 8080
import { readFileSync } from "node:fs";
import { buildServer } from "../server.js";

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

function hexToBytes(h: string): Uint8Array {
  return Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
}

async function main(): Promise<void> {
  const keysPath = env("QIE_AGENT_KEYS_PATH");
  const keys = JSON.parse(readFileSync(keysPath, "utf8")) as KeyFile;

  const app = await buildServer({
    agentId: keys.agent_id,
    storageDir: env("QIE_AGENT_STORAGE", "/data/escrow"),
    ackSeed: hexToBytes(keys.ack_sk),
    hybridSk: { x25519: hexToBytes(keys.hybrid_sk.x25519), mlkem: hexToBytes(keys.hybrid_sk.mlkem) },
    hybridPk: { x25519: hexToBytes(keys.hybrid_pk.x25519), mlkem: hexToBytes(keys.hybrid_pk.mlkem) },
    chainRpcByChainId: {},
  });

  const host = env("QIE_AGENT_HOST", "0.0.0.0");
  const port = Number(env("QIE_AGENT_PORT", "8080"));
  await app.listen({ host, port });
  console.error(`qie-agent ${keys.agent_id} listening on ${host}:${port}`);
}

main().catch((e: unknown) => { console.error(e); process.exit(1); });
