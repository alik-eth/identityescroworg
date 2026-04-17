import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import * as secp from '@noble/secp256k1';
import {
  BINDING_FIELD_ORDER,
  buildBinding,
  canonicalizeBinding,
  declarationDigestHex,
} from '../../src/lib/binding';
import digests from '../../../../fixtures/declarations/digests.json';
import enText from '../../../../fixtures/declarations/en.txt?raw';
import ukText from '../../../../fixtures/declarations/uk.txt?raw';

const VALID_PK_HEX =
  '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';
const VALID_PK = hexToBytes(VALID_PK_HEX);
const NONCE = new Uint8Array(32).map((_, i) => i + 1);
const TIMESTAMP = 1_750_000_000;

describe('binding', () => {
  it('embeds the EN declaration verbatim and its hash matches the fixture digest', () => {
    const b = buildBinding({
      pk: VALID_PK,
      timestamp: TIMESTAMP,
      nonce: NONCE,
      locale: 'en',
    });
    expect(b.declaration).toBe(enText);
    const want = digests.declarations.en.sha256.replace(/^0x/, '');
    expect(declarationDigestHex(b.declaration)).toBe(want);
    const recomputed = bytesToHex(sha256(new TextEncoder().encode(b.declaration)));
    expect(recomputed).toBe(want);
  });

  it('embeds the UK declaration when locale=uk and matches its fixture digest', () => {
    const b = buildBinding({
      pk: VALID_PK,
      timestamp: TIMESTAMP,
      nonce: NONCE,
      locale: 'uk',
    });
    expect(b.declaration).toBe(ukText);
    const want = digests.declarations.uk.sha256.replace(/^0x/, '');
    expect(declarationDigestHex(b.declaration)).toBe(want);
  });

  it('produces stable JCS bytes (deterministic across calls with same inputs)', () => {
    const a = canonicalizeBinding(
      buildBinding({ pk: VALID_PK, timestamp: TIMESTAMP, nonce: NONCE, locale: 'en' }),
    );
    const b = canonicalizeBinding(
      buildBinding({ pk: VALID_PK, timestamp: TIMESTAMP, nonce: NONCE, locale: 'en' }),
    );
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  it('canonical JSON keys appear in lexicographic order (RFC 8785)', () => {
    const ctx = new TextEncoder().encode('ctx');
    const bytes = canonicalizeBinding(
      buildBinding({
        pk: VALID_PK,
        timestamp: TIMESTAMP,
        nonce: NONCE,
        locale: 'en',
        context: ctx,
      }),
    );
    const text = new TextDecoder().decode(bytes);
    const sorted = [...BINDING_FIELD_ORDER].sort();
    let cursor = 0;
    for (const key of sorted) {
      const idx = text.indexOf(`"${key}"`, cursor);
      expect(idx, `key ${key} present and after cursor`).toBeGreaterThanOrEqual(0);
      cursor = idx;
    }
  });

  it('rejects pk not on the secp256k1 curve with binding.field', () => {
    const bad = new Uint8Array(33);
    bad[0] = 0x02;
    expect(() =>
      buildBinding({ pk: bad, timestamp: TIMESTAMP, nonce: NONCE, locale: 'en' }),
    ).toThrowError(
      expect.objectContaining({ code: 'binding.field' }) as unknown as Error,
    );
  });

  it('rejects pk with an unsupported prefix byte', () => {
    const bad = new Uint8Array(33);
    bad[0] = 0x05;
    expect(() =>
      buildBinding({ pk: bad, timestamp: TIMESTAMP, nonce: NONCE, locale: 'en' }),
    ).toThrowError(expect.objectContaining({ code: 'binding.field' }) as unknown as Error);
  });

  it('rejects nonce that is not exactly 32 bytes with binding.field', () => {
    expect(() =>
      buildBinding({
        pk: VALID_PK,
        timestamp: TIMESTAMP,
        nonce: new Uint8Array(16),
        locale: 'en',
      }),
    ).toThrowError(expect.objectContaining({ code: 'binding.field' }) as unknown as Error);
  });

  it('accepts a freshly generated pk (round-trip)', () => {
    const sk = secp.utils.randomPrivateKey();
    const pk = secp.getPublicKey(sk, true);
    const b = buildBinding({ pk, timestamp: TIMESTAMP, nonce: NONCE, locale: 'en' });
    expect(b.pk).toBe(`0x${bytesToHex(pk)}`);
    expect(b.scheme).toBe('secp256k1');
    expect(b.escrow_commitment).toBeNull();
    expect(b.version).toBe('QKB/1.0');
  });

  it('omits optional context when not provided; includes it when provided', () => {
    const without = buildBinding({
      pk: VALID_PK,
      timestamp: TIMESTAMP,
      nonce: NONCE,
      locale: 'en',
    });
    expect(without.context).toBeUndefined();
    const ctx = new TextEncoder().encode('hello');
    const withCtx = buildBinding({
      pk: VALID_PK,
      timestamp: TIMESTAMP,
      nonce: NONCE,
      locale: 'en',
      context: ctx,
    });
    expect(withCtx.context).toBe(`0x${bytesToHex(ctx)}`);
  });
});

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
