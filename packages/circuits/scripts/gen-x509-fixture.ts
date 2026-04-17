/**
 * Reads the openssl-generated leaf.der from fixtures/x509-samples/, locates
 * the two GeneralizedTime tags inside the validity SEQUENCE, and emits a
 * companion JSON describing offsets for tests.
 *
 * Re-run with: `npx ts-node scripts/gen-x509-fixture.ts`.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const fixturesDir = resolve(__dirname, '..', 'fixtures', 'x509-samples');
const der = readFileSync(resolve(fixturesDir, 'leaf.der'));

// Locate every GeneralizedTime TLV header (tag 0x18, short-form len 0x0F).
const offsets: { contentOffset: number; ascii: string }[] = [];
for (let i = 0; i < der.length - 16; i++) {
  if (der[i] === 0x18 && der[i + 1] === 0x0f) {
    const start = i + 2;
    const slice = der.subarray(start, start + 15);
    // Ascii-only sanity: 14 digits + 'Z'.
    let ok = slice[14] === 0x5a;
    for (let j = 0; j < 14 && ok; j++) {
      if (slice[j] < 0x30 || slice[j] > 0x39) ok = false;
    }
    if (ok) {
      offsets.push({ contentOffset: start, ascii: slice.toString('ascii') });
    }
  }
}

if (offsets.length < 2) {
  throw new Error(
    `expected ≥ 2 GeneralizedTime fields in leaf.der, found ${offsets.length}`,
  );
}

const fixture = {
  derPath: 'leaf.der',
  derLength: der.length,
  generalizedTimes: offsets,
  notBefore: offsets[0],
  notAfter: offsets[1],
};

const outPath = resolve(fixturesDir, 'leaf.fixture.json');
writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');
console.log(`Wrote ${outPath}`);
console.log(fixture);
