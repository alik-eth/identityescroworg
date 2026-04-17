/**
 * Sprint 0 S0.5 — context input UX semantics.
 *
 * Verifies the transformation pipeline the /generate route performs on the
 * user's context text:
 *   - empty string  ⇒ binding.context = "0x"            (global proof)
 *   - "dao.x#drop"  ⇒ binding.context = "0x<utf8-hex>"  (Sybil-resistant per-app)
 *
 * The spec/§14.4 circuit derives ctxHash = Poseidon(ctxBytes) when ctxBytes is
 * non-empty and 0 otherwise; this test only covers the byte-level encoding
 * in the binding (circuits-eng owns Poseidon correctness).
 */
import { describe, expect, it } from 'vitest';
import * as secp from '@noble/secp256k1';
import { buildBinding, canonicalizeBinding } from '../../src/lib/binding';

function freshPk(): Uint8Array {
  return secp.getPublicKey(secp.utils.randomPrivateKey(), false);
}

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

describe('context input → binding encoding', () => {
  const pk = freshPk();
  const nonce = new Uint8Array(32);
  const timestamp = 1_730_000_000;

  it('empty context trim → "0x" (global identity proof)', () => {
    const b = buildBinding({ pk, timestamp, nonce, locale: 'en' });
    expect(b.context).toBe('0x');
    const bytes = canonicalizeBinding(b);
    const s = new TextDecoder().decode(bytes);
    expect(s.includes('"context":"0x"')).toBe(true);
  });

  it('non-empty context → "0x<utf8-hex>" (per-app Sybil-resistance)', () => {
    const ctxText = 'dao.example.org#airdrop';
    const ctxBytes = new TextEncoder().encode(ctxText);
    const b = buildBinding({ pk, timestamp, nonce, locale: 'en', context: ctxBytes });
    expect(b.context).toBe('0x' + hex(ctxBytes));
    const roundtrip = new TextDecoder().decode(
      Uint8Array.from(
        b.context
          .slice(2)
          .match(/.{2}/g)!
          .map((h) => parseInt(h, 16)),
      ),
    );
    expect(roundtrip).toBe(ctxText);
  });

  it('unicode (Ukrainian) context is UTF-8 encoded', () => {
    const ctxText = 'ДАО.приклад#дроп';
    const ctxBytes = new TextEncoder().encode(ctxText);
    const b = buildBinding({ pk, timestamp, nonce, locale: 'uk', context: ctxBytes });
    expect(b.context).toBe('0x' + hex(ctxBytes));
    // UTF-8 multi-byte ⇒ hex body length > ctxText.length
    expect(b.context.length - 2).toBeGreaterThan(ctxText.length);
  });

  it('same pk + different context → different canonical bytes (ctxHash will differ)', () => {
    const a = buildBinding({ pk, timestamp, nonce, locale: 'en' });
    const c = buildBinding({
      pk,
      timestamp,
      nonce,
      locale: 'en',
      context: new TextEncoder().encode('x'),
    });
    const ab = new TextDecoder().decode(canonicalizeBinding(a));
    const cb = new TextDecoder().decode(canonicalizeBinding(c));
    expect(ab).not.toBe(cb);
  });
});
