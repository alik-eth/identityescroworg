import { gcm } from "@noble/ciphers/aes";
import { randomBytes } from "@noble/hashes/utils";
import type { Share } from "./types.js";

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const r = new Uint8Array(h.length / 2);
  for (let i = 0; i < r.length; i++) r[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return r;
}

export function wrapShare(ss: Uint8Array, share: Share, aad: Uint8Array): Uint8Array {
  if (ss.length !== 32) throw new Error("ss must be 32 bytes");
  if (share.value.length !== 32) throw new Error("share.value must be 32 bytes");
  const iv = randomBytes(12);
  const pt = new Uint8Array(33);
  pt[0] = share.index;
  pt.set(share.value, 1);
  const ct = gcm(ss, iv, aad).encrypt(pt);
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  return out;
}

export function unwrapShare(ss: Uint8Array, wrap: Uint8Array, aad: Uint8Array): Share {
  const iv = wrap.subarray(0, 12);
  const ct = wrap.subarray(12);
  const pt = gcm(ss, iv, aad).decrypt(ct);
  if (pt.length !== 33) throw new Error("invalid share plaintext length");
  return { index: pt[0]!, value: pt.slice(1) };
}

export function encryptRecovery(k_esc: Uint8Array, R: Uint8Array, escrowId: `0x${string}`): Uint8Array {
  const iv = randomBytes(12);
  const aad = hexToBytes(escrowId);
  const ct = gcm(k_esc, iv, aad).encrypt(R);
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  return out;
}

export function decryptRecovery(k_esc: Uint8Array, encR: Uint8Array, escrowId: `0x${string}`): Uint8Array {
  const iv = encR.subarray(0, 12);
  const ct = encR.subarray(12);
  const aad = hexToBytes(escrowId);
  return gcm(k_esc, iv, aad).decrypt(ct);
}
