import { useTranslation } from 'react-i18next';
import { useCountry } from '../../components/CountryScope';

export function UaProveAgeScreen() {
  const { t } = useTranslation();
  const { config } = useCountry();
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6">
      <h2 className="text-xl font-serif italic text-slate-100">
        {t('ua.proveAge.heading')}
      </h2>
      <p className="mt-2 text-sm text-slate-400">{t('ua.proveAge.comingSoon')}</p>
      <p className="mt-4 text-xs font-mono text-slate-500 break-all">
        ageVerifier: {config.ageVerifier}
      </p>
    </div>
  );
}
