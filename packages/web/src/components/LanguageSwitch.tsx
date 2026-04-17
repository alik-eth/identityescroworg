import { useTranslation } from 'react-i18next';
import { SUPPORTED_LANGUAGES, type SupportedLanguage } from '../lib/i18n';

export function LanguageSwitch() {
  const { i18n, t } = useTranslation();
  return (
    <label>
      {t('lang.label')}{': '}
      <select
        value={i18n.language}
        onChange={(e) => {
          void i18n.changeLanguage(e.target.value as SupportedLanguage);
        }}
        data-testid="language-switch"
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
