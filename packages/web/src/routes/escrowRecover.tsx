import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

/**
 * QIE `/escrow/recover` — recovery flow for the original holder.
 *
 * MVP refinement: without `?mode=self`, this route redirects into the
 * notary-assisted flow at `/escrow/notary`. Power users and tests can
 * still reach the self-recovery UI via `?mode=self`.
 */
export function EscrowRecoverScreen() {
  const { t } = useTranslation();
  const [isSelfMode, setIsSelfMode] = useState<boolean | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(
      typeof window === 'undefined' ? '' : window.location.search,
    );
    setIsSelfMode(params.get('mode') === 'self');
  }, []);

  if (isSelfMode === null) return null;

  if (!isSelfMode) {
    return (
      <section className="space-y-6">
        <h2 className="font-serif italic text-4xl">{t('escrow.recover.title')}</h2>
        <p className="text-slate-400">{t('escrow.recover.subtitle')}</p>
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 space-y-3">
          <p className="text-amber-200">{t('escrow.recover.modeBanner')}</p>
          <div className="flex gap-3">
            <a
              href="/escrow/notary"
              className="bg-emerald-500/10 border border-emerald-500/30 px-4 py-2 rounded"
            >
              {t('escrow.recover.goNotary')}
            </a>
            <button
              onClick={() => {
                if (typeof window !== 'undefined') {
                  const url = new URL(window.location.href);
                  url.searchParams.set('mode', 'self');
                  window.history.replaceState({}, '', url.toString());
                }
                setIsSelfMode(true);
              }}
              className="px-4 py-2 rounded border border-slate-700 text-slate-300"
            >
              {t('escrow.recover.continueSelf')}
            </button>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="space-y-6">
      <h2 className="font-serif italic text-4xl">{t('escrow.recover.title')}</h2>
      <p className="text-slate-400">{t('escrow.recover.subtitle')}</p>
      <p
        data-testid="self-recover-form"
        className="text-sm font-mono text-slate-500 tracking-widest uppercase"
      >
        mode=self
      </p>
      <label className="block">
        {t('escrow.recover.escrowIdLabel')}
        <input
          type="text"
          className="w-full bg-slate-800 font-mono text-xs p-2 rounded mt-1"
          aria-label={t('escrow.recover.escrowIdLabel')}
        />
      </label>
      <label className="block">
        {t('escrow.recover.agentEndpointLabel')}
        <input
          type="text"
          className="w-full bg-slate-800 font-mono text-xs p-2 rounded mt-1"
          aria-label={t('escrow.recover.agentEndpointLabel')}
        />
      </label>
      <label className="block">
        {t('escrow.recover.unlockTxLabel')}
        <input
          type="text"
          className="w-full bg-slate-800 font-mono text-xs p-2 rounded mt-1"
          aria-label={t('escrow.recover.unlockTxLabel')}
        />
      </label>
      <label className="block">
        {t('escrow.recover.recipientSkLabel')}
        <input
          type="password"
          autoComplete="off"
          spellCheck={false}
          className="w-full bg-slate-800 font-mono text-xs p-2 rounded mt-1"
          aria-label={t('escrow.recover.recipientSkLabel')}
        />
      </label>
      <button className="bg-emerald-500/10 border border-emerald-500/30 px-4 py-2 rounded">
        {t('escrow.recover.run')}
      </button>
    </section>
  );
}
