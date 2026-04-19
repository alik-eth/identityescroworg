/**
 * Regression: canonical binding bytes must fit within the circuit's
 * `MAX_BCANON` buffer for BOTH supported declaration locales.
 *
 * This test was missing through Phase 1 + Phase 2 split-proof. On
 * 2026-04-19 the live Sepolia V3 E2E tripped the circuit's
 * `fieldTooLong` guard at /upload because the Ukrainian locale pushed
 * the canonical JSON to ~1244 bytes vs MAX_BCANON=1024. The fixed
 * scaffold overhead (pk 130 hex + nonce 64 hex + other fields +
 * structural chars) is ~339 bytes; that leaves only ~685 bytes for the
 * declaration, while uk.txt is 905 bytes. Adding it here now so the
 * mismatch is caught at CI instead of after a user has signed with Diia.
 *
 * Currently the UK assertion fails by design — the circuit cannot
 * accept UK until a leaf re-ceremony raises MAX_BCANON. `it.fails`
 * documents the gap: the moment the re-ceremony lands with a bigger
 * buffer, this test turns the other direction and we must flip it back
 * to a normal `it`.
 */
import { describe, expect, it } from 'vitest';
import * as secp from '@noble/secp256k1';
import { buildBinding, canonicalizeBinding, type Locale } from '../../src/lib/binding';
import { MAX_BCANON } from '../../src/lib/witness';

// Realistic sample: privkey = 1 ⇒ uncompressed pk (130 hex after 04),
// max-width nonce (32 bytes), 10-digit timestamp. Any combination of
// pk + nonce + timestamp produced by `/generate` will have the same
// number of canonical bytes outside the declaration field.
const PK = secp.getPublicKey(
  new Uint8Array(32).fill(0).map((_, i) => (i === 31 ? 1 : 0)),
  false,
);
const NONCE = new Uint8Array(32).map((_, i) => (i * 7 + 1) & 0xff);
const TIMESTAMP = 1_776_000_000;

function bcanonSize(locale: Locale): number {
  const b = buildBinding({ pk: PK, timestamp: TIMESTAMP, nonce: NONCE, locale });
  return canonicalizeBinding(b).length;
}

describe('binding size vs circuit MAX_BCANON', () => {
  it('EN declaration + realistic pk/nonce fits MAX_BCANON', () => {
    const size = bcanonSize('en');
    expect(size, `EN canonical binding is ${size} bytes, limit ${MAX_BCANON}`)
      .toBeLessThanOrEqual(MAX_BCANON);
  });

  // UK currently overflows because uk.txt is 905 bytes of Cyrillic
  // (2 bytes per char in UTF-8). `it.fails` means "this SHOULD fail today
  // — if it stops failing, CI turns red so we notice and flip it to
  // a real assertion". Convert this to `it(...)` once the re-ceremony
  // with a larger MAX_BCANON ships.
  it.fails('UK declaration + realistic pk/nonce overflows MAX_BCANON (pending re-ceremony)', () => {
    const size = bcanonSize('uk');
    expect(size, `UK canonical binding is ${size} bytes, limit ${MAX_BCANON}`)
      .toBeLessThanOrEqual(MAX_BCANON);
  });

  it('measures the margin for visibility in CI output', () => {
    const enSize = bcanonSize('en');
    const ukSize = bcanonSize('uk');
    // Log (via throw-on-mismatch if present) the margin so a future
    // reviewer sees the actual numbers when this file runs.
    // Not assertions — just carries the observation.
    expect(enSize).toBeGreaterThan(0);
    expect(ukSize).toBeGreaterThan(0);
    // eslint-disable-next-line no-console
    console.info(
      `bcanon sizes — MAX_BCANON=${MAX_BCANON}  EN=${enSize} (margin ${MAX_BCANON - enSize})  UK=${ukSize} (over by ${ukSize - MAX_BCANON})`,
    );
  });
});
