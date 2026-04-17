import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import en from '../i18n/en.json';
import uk from '../i18n/uk.json';

export const SUPPORTED_LANGUAGES = ['en', 'uk'] as const;
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];

export const LANGUAGE_STORAGE_KEY = 'qkb.lang';

function isSupported(v: string | null | undefined): v is SupportedLanguage {
  return v === 'en' || v === 'uk';
}

function detectInitialLanguage(): SupportedLanguage {
  try {
    const stored = globalThis.localStorage?.getItem(LANGUAGE_STORAGE_KEY);
    if (isSupported(stored)) return stored;
  } catch {
    // localStorage may be blocked (Safari private mode, file://) — fall through.
  }
  const nav = (globalThis.navigator?.language ?? '').toLowerCase();
  if (nav.startsWith('uk')) return 'uk';
  return 'en';
}

const initial = detectInitialLanguage();

void i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    uk: { translation: uk },
  },
  lng: initial,
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
});

i18n.on('languageChanged', (lng) => {
  if (!isSupported(lng)) return;
  try {
    globalThis.localStorage?.setItem(LANGUAGE_STORAGE_KEY, lng);
  } catch {
    // ignore quota / blocked storage
  }
});

export default i18n;
