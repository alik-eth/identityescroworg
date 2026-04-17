// Wire-format ⇄ in-memory conversion. The HTTP API speaks JSON (hex strings for
// byte fields); qie-core speaks Uint8Array. Centralise the mapping.

import type { EscrowConfig, HybridPublicKey } from "@qkb/qie-core";

export function hex2bytes(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  if (s.length % 2 !== 0) throw new Error("odd-length hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytes2hex(b: Uint8Array): string {
  return "0x" + Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
}

export interface WireHybridPk { x25519: string; mlkem: string; }
export interface WireAgentEntry { agent_id: string; hybrid_pk: WireHybridPk; endpoint: string; }
export interface WireEscrowConfig {
  version: "QIE/1.0";
  pk: `0x04${string}`;
  agents: WireAgentEntry[];
  threshold: number;
  recipient_hybrid_pk: WireHybridPk;
  arbitrator: { chain_id: number; address: `0x${string}`; kind: "authority" | "timelock" };
  expiry: number;
  jurisdiction: string;
  unlock_predicate: "A_OR_C";
}

export interface WireWrappedCt {
  kem_ct: { x25519_ct: string; mlkem_ct: string };
  wrap: string;
}

function wireHybrid(w: WireHybridPk): HybridPublicKey {
  return { x25519: hex2bytes(w.x25519), mlkem: hex2bytes(w.mlkem) };
}

export function hydrateConfig(w: WireEscrowConfig): EscrowConfig {
  return {
    version: w.version,
    pk: w.pk,
    agents: w.agents.map(a => ({
      agent_id: a.agent_id,
      hybrid_pk: wireHybrid(a.hybrid_pk),
      endpoint: a.endpoint,
    })),
    threshold: w.threshold,
    recipient_hybrid_pk: wireHybrid(w.recipient_hybrid_pk),
    arbitrator: w.arbitrator,
    expiry: w.expiry,
    jurisdiction: w.jurisdiction,
    unlock_predicate: w.unlock_predicate,
  };
}

export function dehydrateConfig(cfg: EscrowConfig): WireEscrowConfig {
  return {
    version: cfg.version,
    pk: cfg.pk,
    agents: cfg.agents.map(a => ({
      agent_id: a.agent_id,
      hybrid_pk: { x25519: bytes2hex(a.hybrid_pk.x25519), mlkem: bytes2hex(a.hybrid_pk.mlkem) },
      endpoint: a.endpoint,
    })),
    threshold: cfg.threshold,
    recipient_hybrid_pk: {
      x25519: bytes2hex(cfg.recipient_hybrid_pk.x25519),
      mlkem: bytes2hex(cfg.recipient_hybrid_pk.mlkem),
    },
    arbitrator: cfg.arbitrator,
    expiry: cfg.expiry,
    jurisdiction: cfg.jurisdiction,
    unlock_predicate: cfg.unlock_predicate,
  };
}
