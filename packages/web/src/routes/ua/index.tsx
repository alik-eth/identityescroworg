import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { useCountry } from '../../components/CountryScope';

export function UaIndex() {
  const { t } = useTranslation();
  const { config } = useCountry();
  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6">
        <h2 className="text-xl font-serif italic text-slate-100">
          {t('ua.landing.heading')}
        </h2>
        <p className="mt-2 text-sm text-slate-400">{t('ua.landing.intro')}</p>
        <dl className="mt-4 grid grid-cols-1 gap-2 text-xs font-mono text-slate-500 sm:grid-cols-2">
          <div>
            <dt className="uppercase tracking-widest text-[10px] text-slate-600">
              {t('ua.landing.registry')}
            </dt>
            <dd className="break-all text-slate-300">{config.registry}</dd>
          </div>
          <div>
            <dt className="uppercase tracking-widest text-[10px] text-slate-600">
              {t('ua.landing.policyRoot')}
            </dt>
            <dd className="break-all text-slate-300">{config.policyRoot}</dd>
          </div>
          <div>
            <dt className="uppercase tracking-widest text-[10px] text-slate-600">
              {t('ua.landing.trustedListRoot')}
            </dt>
            <dd className="break-all text-slate-300">{config.trustedListRoot}</dd>
          </div>
          <div>
            <dt className="uppercase tracking-widest text-[10px] text-slate-600">
              {t('ua.landing.deployedAt')}
            </dt>
            <dd className="text-slate-300">{config.deployedAt}</dd>
          </div>
        </dl>
      </div>
      <div className="flex flex-wrap gap-2">
        <Link
          to="/ua/generate"
          className="px-4 py-2 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20 transition-colors text-sm"
        >
          {t('nav.generate')}
        </Link>
        <Link
          to="/ua/prove-age"
          className="px-4 py-2 rounded-xl bg-slate-800/60 border border-slate-700 text-slate-300 hover:bg-slate-800 transition-colors text-sm"
        >
          {t('nav.proveAge')}
        </Link>
      </div>
    </div>
  );
}
