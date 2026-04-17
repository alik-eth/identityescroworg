import { describe, it, expect } from 'vitest';
import en from '../../src/i18n/en.json';
import uk from '../../src/i18n/uk.json';

type Json = string | number | boolean | null | { [k: string]: Json } | Json[];

function walk(obj: Json, prefix = ''): string[] {
  const out: string[] = [];
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return out;
  for (const [k, v] of Object.entries(obj)) {
    const next = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      out.push(...walk(v as Json, next));
    } else {
      out.push(next);
    }
  }
  return out;
}

describe('i18n parity', () => {
  it('EN and UK share the same key set', () => {
    const enKeys = walk(en as unknown as Json).sort();
    const ukKeys = walk(uk as unknown as Json).sort();
    const missingInUk = enKeys.filter((k) => !ukKeys.includes(k));
    const extraInUk = ukKeys.filter((k) => !enKeys.includes(k));
    expect(missingInUk).toEqual([]);
    expect(extraInUk).toEqual([]);
  });

  it('includes the new escrow.* namespace', () => {
    const enKeys = walk(en as unknown as Json);
    expect(enKeys).toContain('escrow.setup.title');
    expect(enKeys).toContain('escrow.recover.title');
    expect(enKeys).toContain('escrow.notary.title');
  });
});
