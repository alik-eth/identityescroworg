import { describe, it, expect } from 'vitest';
import en from '../../src/i18n/en.json';
import uk from '../../src/i18n/uk.json';

function flatten(obj: Record<string, unknown>, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([k, v]) => {
    const key = prefix ? `${prefix}.${k}` : k;
    return v && typeof v === 'object' ? flatten(v as Record<string, unknown>, key) : [key];
  });
}

describe('i18n coverage', () => {
  it('en and uk have identical key sets', () => {
    const enKeys = flatten(en).sort();
    const ukKeys = flatten(uk).sort();
    expect(ukKeys).toEqual(enKeys);
  });

  it('no key value is empty', () => {
    const flatVals = (obj: Record<string, unknown>): string[] =>
      Object.values(obj).flatMap((v) =>
        v && typeof v === 'object' ? flatVals(v as Record<string, unknown>) : [v as string],
      );
    expect(flatVals(en).every((s) => s.length > 0)).toBe(true);
    expect(flatVals(uk).every((s) => s.length > 0)).toBe(true);
  });
});
