import { Link, Outlet } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { CountryProvider } from '../../components/CountryScope';

const UA_STEPS = [
  { to: '/ua/generate', key: 'nav.generate' },
  { to: '/ua/sign', key: 'nav.sign' },
  { to: '/ua/upload', key: 'nav.upload' },
  { to: '/ua/register', key: 'nav.register' },
  { to: '/ua/prove-age', key: 'nav.proveAge' },
] as const;

export function UaLayout() {
  const { t } = useTranslation();
  return (
    <CountryProvider country="UA">
      <section className="space-y-6">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-baseline gap-3">
            <span className="font-mono text-[10px] tracking-widest text-emerald-400/90 uppercase">
              {t('ua.scopeLabel')}
            </span>
            <h2 className="text-lg font-serif italic text-slate-100">
              {t('ua.scopeTitle')}
            </h2>
          </div>
          <nav className="flex flex-wrap gap-1 text-xs">
            {UA_STEPS.map((step, i) => (
              <Link
                key={step.to}
                to={step.to}
                className="px-2.5 py-1 rounded-full text-slate-500 hover:text-slate-200 hover:bg-slate-800/60 transition-colors"
                activeProps={{
                  className:
                    'px-2.5 py-1 rounded-full text-emerald-300 bg-emerald-500/10 border border-emerald-500/30',
                }}
              >
                <span className="font-mono text-[10px] text-slate-600 mr-1">
                  {String(i + 1).padStart(2, '0')}
                </span>
                {t(step.key)}
              </Link>
            ))}
          </nav>
        </header>
        <Outlet />
      </section>
    </CountryProvider>
  );
}
