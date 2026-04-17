import type { HybridPublicKey } from "./types.js";

const DOMAIN_UNLOCK = new TextEncoder().encode("QIE/1.0/unlock");
const DOMAIN_REVOKE = new TextEncoder().encode("QIE/1.0/revoke");
const DOMAIN_DELETE = new TextEncoder().encode("QIE/1.0/delete");

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  const r = new Uint8Array(s.length / 2);
  for (let i = 0; i < r.length; i++) r[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return r;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function buildUnlockMessage(escrowId: `0x${string}`, recipientPk: HybridPublicKey): Uint8Array {
  return concat(DOMAIN_UNLOCK, new Uint8Array([0]), hexToBytes(escrowId), new Uint8Array([0]), recipientPk.x25519, recipientPk.mlkem);
}

export function buildRevokeMessage(escrowId: `0x${string}`, reasonHash: `0x${string}`): Uint8Array {
  return concat(DOMAIN_REVOKE, new Uint8Array([0]), hexToBytes(escrowId), new Uint8Array([0]), hexToBytes(reasonHash));
}

export function buildDeleteMessage(escrowId: `0x${string}`): Uint8Array {
  return concat(DOMAIN_DELETE, new Uint8Array([0]), hexToBytes(escrowId));
}
