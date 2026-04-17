import { describe, expect, it } from 'vitest';
import i18n, { LANGUAGE_STORAGE_KEY, SUPPORTED_LANGUAGES } from '../../src/lib/i18n';

const flatten = (obj: Record<string, unknown>, prefix = ''): string[] =>
  Object.entries(obj).flatMap(([k, v]) =>
    typeof v === 'object' && v !== null
      ? flatten(v as Record<string, unknown>, `${prefix}${k}.`)
      : [`${prefix}${k}`],
  );

describe('i18n smoke', () => {
  it('has identical key sets across en and uk (full nested path coverage)', () => {
    const en = i18n.getResourceBundle('en', 'translation') as Record<string, unknown>;
    const uk = i18n.getResourceBundle('uk', 'translation') as Record<string, unknown>;
    const enKeys = flatten(en).sort();
    const ukKeys = flatten(uk).sort();
    expect(ukKeys).toEqual(enKeys);
    expect(enKeys.length).toBeGreaterThan(20);
  });

  it('every key resolves to a non-empty string in both locales', () => {
    const en = i18n.getResourceBundle('en', 'translation') as Record<string, unknown>;
    const keys = flatten(en);
    for (const lng of SUPPORTED_LANGUAGES) {
      for (const key of keys) {
        const v = i18n.getResource(lng, 'translation', key);
        expect(typeof v, `${lng}:${key} must be a string`).toBe('string');
        expect((v as string).length, `${lng}:${key} must be non-empty`).toBeGreaterThan(0);
      }
    }
  });

  it('resolves the app title', () => {
    expect(i18n.t('app.title')).toBe('QKB');
  });

  it('persists language choice to localStorage on changeLanguage', async () => {
    const prev = i18n.language;
    await i18n.changeLanguage('uk');
    expect(globalThis.localStorage.getItem(LANGUAGE_STORAGE_KEY)).toBe('uk');
    await i18n.changeLanguage('en');
    expect(globalThis.localStorage.getItem(LANGUAGE_STORAGE_KEY)).toBe('en');
    await i18n.changeLanguage(prev);
  });
});
