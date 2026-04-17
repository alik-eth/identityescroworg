import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscrowRecover } from '../features/qie/use-escrow-recover';

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
  const [escrowId, setEscrowId] = useState('');
  const [endpoint, setEndpoint] = useState('');
  const [unlockTx, setUnlockTx] = useState('');
  const { state: recoverState, recover } = useEscrowRecover();

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
          value={escrowId}
          onChange={(e) => setEscrowId(e.target.value)}
          className="w-full bg-slate-800 font-mono text-xs p-2 rounded mt-1"
          aria-label={t('escrow.recover.escrowIdLabel')}
        />
      </label>
      <label className="block">
        {t('escrow.recover.agentEndpointLabel')}
        <input
          type="text"
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
          className="w-full bg-slate-800 font-mono text-xs p-2 rounded mt-1"
          aria-label={t('escrow.recover.agentEndpointLabel')}
        />
      </label>
      <label className="block">
        {t('escrow.recover.unlockTxLabel')}
        <input
          type="text"
          value={unlockTx}
          onChange={(e) => setUnlockTx(e.target.value)}
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
      <button
        disabled={!escrowId || !endpoint || recoverState.phase === 'collecting'}
        onClick={() =>
          recover({
            escrowId: (escrowId.startsWith('0x') ? escrowId : `0x${escrowId}`) as `0x${string}`,
            threshold: 1,
            agents: [{ agent_id: 'primary', endpoint }],
            body: { arbitrator_unlock_tx: unlockTx },
          })
        }
        className="bg-emerald-500/10 border border-emerald-500/30 px-4 py-2 rounded disabled:opacity-50"
      >
        {recoverState.phase === 'collecting'
          ? t('escrow.recover.running')
          : t('escrow.recover.run')}
      </button>
      {recoverState.phase === 'done' && (
        <p className="text-emerald-300 text-sm" data-testid="recover-status">
          {t('escrow.recover.done')}
        </p>
      )}
      {recoverState.phase === 'error' && (
        <p className="text-red-400 text-sm" data-testid="recover-error">
          {recoverState.error}
        </p>
      )}
    </section>
  );
}
