#!/usr/bin/env node
/*
 * keygen.mjs — generate mock-QTSP agent key files for the docker-compose
 * harness. Produces six files (three agents × {keys.json, keys.pub.json}).
 *
 *   node deploy/mock-qtsps/agents/keygen.mjs
 *
 * The `.keys.json` variant carries the ed25519 ack seed + hybrid KEM sk
 * and is GITIGNORED (see root .gitignore → fixtures/qie/agents/*.keys.json
 * pattern extended to this directory). The `.keys.pub.json` variant is
 * committed so reviewers can sanity-check which agents the compose harness
 * will talk to.
 */
import { writeFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

// Resolve @qkb/qie-core via the workspace dist without requiring a
// package context — this script runs out-of-workspace.
const coreEntry = resolve(here, "../../../packages/qie-core/dist/index.js");
const { generateHybridKeypair } = await import(coreEntry);

function hex(b) {
  return "0x" + Buffer.from(b).toString("hex");
}

const agents = ["agent-a", "agent-b", "agent-c"];

for (const id of agents) {
  const privPath = resolve(here, `${id}.keys.json`);
  const pubPath = resolve(here, `${id}.keys.pub.json`);
  if (existsSync(privPath)) {
    console.error(`[keygen] ${privPath} already exists, skipping`);
    continue;
  }

  const ackSeed = randomBytes(32);
  const { pk, sk } = generateHybridKeypair();

  const priv = {
    agent_id: id,
    ack_sk: hex(ackSeed),
    hybrid_sk: { x25519: hex(sk.x25519), mlkem: hex(sk.mlkem) },
    hybrid_pk: { x25519: hex(pk.x25519), mlkem: hex(pk.mlkem) },
  };
  const pub = {
    agent_id: id,
    hybrid_pk: priv.hybrid_pk,
  };

  writeFileSync(privPath, JSON.stringify(priv, null, 2));
  writeFileSync(pubPath, JSON.stringify(pub, null, 2));
  console.error(`[keygen] wrote ${id}.keys.json (gitignored) + ${id}.keys.pub.json`);
}
