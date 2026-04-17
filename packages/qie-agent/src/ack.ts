import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

// Ack format: Ed25519 signature over sha256("<escrowId>|<agentId>|stored").
// Holder verifies with the agent's published ackPk (from fixtures/qie/qie-agents.json).

export function signAck(skSeed: Uint8Array, escrowId: string, agentId: string): Uint8Array {
  const msg = sha256(new TextEncoder().encode(`${escrowId}|${agentId}|stored`));
  return ed25519.sign(msg, skSeed);
}

export function ackPublicKey(skSeed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(skSeed);
}
