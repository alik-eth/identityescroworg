import { useTranslation } from 'react-i18next';
import { SUPPORTED_LANGUAGES, type SupportedLanguage } from '../lib/i18n';

export function LanguageSwitch() {
  const { i18n, t } = useTranslation();
  return (
    <label className="flex items-center gap-2 text-xs font-mono text-slate-500 uppercase tracking-widest">
      <span className="hidden sm:inline">{t('lang.label')}</span>
      <select
        value={i18n.language}
        onChange={(e) => {
          void i18n.changeLanguage(e.target.value as SupportedLanguage);
        }}
        data-testid="language-switch"
        className="bg-slate-800/60 border border-slate-700/60 rounded-md px-2 py-1 text-slate-200 font-sans text-xs focus:outline-none focus:ring-1 focus:ring-emerald-500/40"
      >
        {SUPPORTED_LANGUAGES.map((lng) => (
          <option key={lng} value={lng}>
            {t(`lang.${lng}`)}
          </option>
        ))}
      </select>
    </label>
  );
}
