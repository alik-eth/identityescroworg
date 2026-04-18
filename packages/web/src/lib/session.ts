/**
 * Route-scoped session state shared across /generate → /sign → /upload →
 * /register. The SPA is pure client-side, so state lives in
 * `sessionStorage` under a single key. Binary values are base64-encoded
 * for JSON compatibility; bigints (timestamps) stay as plain numbers.
 *
 * This is intentionally a thin layer — no React context, no Zustand — so
 * every route can rehydrate on direct-link navigation (e.g. a user
 * refreshes /upload) and the happy-path Playwright spec can seed state via
 * `page.addInitScript` without having to click through every screen.
 */
import type { Binding } from './binding';
import type { Groth16Proof } from './prover';

const KEY = 'qkb.session.v1';

export interface Session {
  // From /generate
  privkeyHex?: string;
  pubkeyUncompressedHex?: string; // 65-byte SEC1 uncompressed
  locale?: 'en' | 'uk';

  // Built on /generate → carried to /sign
  binding?: Binding;
  bcanonB64?: string; // RFC 8785 JCS bytes

  // From /upload
  cadesB64?: string;
  /** @deprecated Phase-1 single-proof field. Split-proof pivot uses
   *  proofLeaf / proofChain; keep for one release so older sessions don't
   *  clobber new ones. */
  proof?: Groth16Proof;
  /** @deprecated Phase-1 single publicSignals (14 elements). Split-proof
   *  pivot uses publicLeaf (13) / publicChain (3). */
  publicSignals?: string[];
  // Split-proof (2026-04-18 pivot) — both proofs are submitted together
  // to V3 register(). publicLeaf / publicChain match the orchestration
  // §2.1 + §2.2 public-signal layouts.
  proofLeaf?: Groth16Proof;
  publicLeaf?: string[];
  proofChain?: Groth16Proof;
  publicChain?: string[];
  leafCertDerB64?: string;
  intCertDerB64?: string;
  trustedListRoot?: string;
  circuitVersion?: string;
  algorithmTag?: 0 | 1;
}

export function loadSession(): Session {
  if (typeof sessionStorage === 'undefined') return {};
  const raw = sessionStorage.getItem(KEY);
  if (!raw) return {};
  try {
    return JSON.parse(raw) as Session;
  } catch {
    return {};
  }
}

export function saveSession(patch: Partial<Session>): Session {
  const current = loadSession();
  const next = { ...current, ...patch };
  if (typeof sessionStorage !== 'undefined') {
    sessionStorage.setItem(KEY, JSON.stringify(next));
  }
  return next;
}

export function clearSession(): void {
  if (typeof sessionStorage !== 'undefined') sessionStorage.removeItem(KEY);
}

export function bytesToB64(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

export function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function hexToBytes(h: string): Uint8Array {
  const clean = h.startsWith('0x') || h.startsWith('0X') ? h.slice(2) : h;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
