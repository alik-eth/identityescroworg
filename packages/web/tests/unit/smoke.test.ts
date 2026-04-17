import { describe, expect, it } from 'vitest';
import i18n from '../../src/lib/i18n';

describe('i18n smoke', () => {
  it('has identical key sets across en and uk', () => {
    const en = i18n.getResourceBundle('en', 'translation') as Record<string, unknown>;
    const uk = i18n.getResourceBundle('uk', 'translation') as Record<string, unknown>;
    const flatten = (obj: Record<string, unknown>, prefix = ''): string[] =>
      Object.entries(obj).flatMap(([k, v]) =>
        typeof v === 'object' && v !== null
          ? flatten(v as Record<string, unknown>, `${prefix}${k}.`)
          : [`${prefix}${k}`],
      );
    expect(flatten(en).sort()).toEqual(flatten(uk).sort());
  });

  it('resolves the app title', () => {
    expect(i18n.t('app.title')).toBe('QKB');
  });
});
