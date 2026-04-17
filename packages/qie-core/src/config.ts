import { sha256 } from "@noble/hashes/sha256";
import { jcsCanonicalize } from "./jcs.js";
import type { EscrowConfig, HybridPublicKey } from "./types.js";

function bytesToHex(b: Uint8Array): string {
  return "0x" + Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
}

function hybridPkToJson(pk: HybridPublicKey) {
  return { x25519: bytesToHex(pk.x25519), mlkem: bytesToHex(pk.mlkem) };
}

export function buildEscrowConfig(
  input: Omit<EscrowConfig, "version" | "unlock_predicate">,
): EscrowConfig {
  if (!input.pk.startsWith("0x04")) throw new Error("pk must be 0x04-prefixed uncompressed secp256k1");
  if (input.pk.length !== 2 + 2 + 128) throw new Error(`pk must be 65 bytes (got ${(input.pk.length - 2) / 2})`);
  if (input.agents.length < 1 || input.agents.length > 16) throw new Error("agents count out of range [1..16]");
  if (input.threshold < 1 || input.threshold > input.agents.length) {
    throw new Error(`threshold ${input.threshold} invalid for ${input.agents.length} agents`);
  }
  return { version: "QIE/1.0", ...input, unlock_predicate: "A_OR_C" };
}

function cfgToJsonable(cfg: EscrowConfig): unknown {
  return {
    version: cfg.version,
    pk: cfg.pk,
    agents: cfg.agents.map(a => ({
      agent_id: a.agent_id,
      hybrid_pk: hybridPkToJson(a.hybrid_pk),
      endpoint: a.endpoint,
    })),
    threshold: cfg.threshold,
    recipient_hybrid_pk: hybridPkToJson(cfg.recipient_hybrid_pk),
    arbitrator: cfg.arbitrator,
    expiry: cfg.expiry,
    jurisdiction: cfg.jurisdiction,
    unlock_predicate: cfg.unlock_predicate,
  };
}

export function canonicalizeConfig(cfg: EscrowConfig): Uint8Array {
  return new TextEncoder().encode(jcsCanonicalize(cfgToJsonable(cfg)));
}

export function computeEscrowId(cfg: EscrowConfig): `0x${string}` {
  const bytes = canonicalizeConfig(cfg);
  return bytesToHex(sha256(bytes)) as `0x${string}`;
}
