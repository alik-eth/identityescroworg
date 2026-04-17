import { describe, expect, it } from 'vitest';
import {
  ALL_ERROR_CODES,
  BundleError,
  QkbError,
  localizeError,
} from '../../src/lib/errors';
import i18n from '../../src/lib/i18n';

describe('errors taxonomy', () => {
  it('every code has a constructor and an EN + UK message', () => {
    for (const code of ALL_ERROR_CODES) {
      const e = new QkbError(code);
      expect(e.code).toBe(code);
      expect(e.messageKey).toBe(`errors.${code}`);
      const en = i18n.getResource('en', 'translation', e.messageKey);
      const uk = i18n.getResource('uk', 'translation', e.messageKey);
      expect(typeof en).toBe('string');
      expect(typeof uk).toBe('string');
      expect((en as string).length).toBeGreaterThan(0);
      expect((uk as string).length).toBeGreaterThan(0);
    }
  });

  it('localizeError returns the EN translation', () => {
    const e = new QkbError('qes.sigInvalid');
    const msg = localizeError(e, i18n);
    expect(msg).toBe('The qualified electronic signature is not valid.');
  });

  it('localizeError returns the UK translation when active', async () => {
    const prev = i18n.language;
    await i18n.changeLanguage('uk');
    const msg = localizeError(new QkbError('qes.sigInvalid'), i18n);
    expect(msg).toBe('Кваліфікований електронний підпис недійсний.');
    await i18n.changeLanguage(prev);
  });

  it('localizeError falls back to the code when key is missing', () => {
    const stub = { t: (k: string) => k };
    const out = localizeError(new QkbError('bundle.malformed'), stub);
    expect(out).toBe('bundle.malformed');
  });

  it('BundleError inherits from QkbError and exposes BundleError name', () => {
    const e = new BundleError('bundle.malformed', { reason: 'x' });
    expect(e).toBeInstanceOf(QkbError);
    expect(e.name).toBe('BundleError');
    expect(e.details).toEqual({ reason: 'x' });
  });
});
