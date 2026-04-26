import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';

export function IndexScreen() {
  const { t } = useTranslation();
  return (
    <section className="hero-mesh animate-fade-in rounded-2xl border border-slate-800/80 px-8 py-16 text-center">
      <p className="font-mono text-[11px] tracking-widest text-emerald-400/90 uppercase mb-6">
        {t('app.tagline')}
      </p>
      <h2 className="font-serif italic text-5xl md:text-6xl text-slate-100 leading-tight">
        {t('index.heading')}
      </h2>
      <p className="mt-6 text-slate-400 max-w-xl mx-auto">{t('index.subheading')}</p>
      <div className="mt-10 flex justify-center">
        <Link
          to="/ua"
          className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg transition-colors text-sm"
        >
          {t('index.start')}
        </Link>
      </div>
    </section>
  );
}
