import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscrowSetup } from '../features/qie/use-escrow-setup';

/**
 * QIE `/escrow/setup` — 4-step wizard to split Phase 1 recovery material
 * across qualified custodians. MVP refinement: only the AuthorityArbitrator
 * option is shown. The TimelockArbitrator is deferred post-pilot.
 *
 * Steps:
 *   1. Custodians — pick agents + threshold.
 *   2. Recipient — paste or generate a hybrid public key.
 *   3. Arbitrator — Authority address + expiry (days).
 *   4. Review — confirm and submit.
 */
type Step = 1 | 2 | 3 | 4;

export function EscrowSetupScreen() {
  const { t } = useTranslation();
  const [step, setStep] = useState<Step>(1);
  const [threshold, setThreshold] = useState(2);
  const [recipientPk, setRecipientPk] = useState('');
  const [expiryDays, setExpiryDays] = useState(365);
  const { state: setupState, submit } = useEscrowSetup();

  return (
    <section className="space-y-8">
      <header>
        <h2 className="font-serif italic text-4xl mb-2">{t('escrow.setup.title')}</h2>
        <p className="text-slate-400">{t('escrow.setup.subtitle')}</p>
      </header>
      <nav className="flex gap-4 text-xs font-mono tracking-widest uppercase text-slate-500">
        <span className={step === 1 ? 'text-emerald-300' : ''}>{t('escrow.setup.stepAgents')}</span>
        <span className={step === 2 ? 'text-emerald-300' : ''}>{t('escrow.setup.stepRecipient')}</span>
        <span className={step === 3 ? 'text-emerald-300' : ''}>{t('escrow.setup.stepArbitrator')}</span>
        <span className={step === 4 ? 'text-emerald-300' : ''}>{t('escrow.setup.stepReview')}</span>
      </nav>

      {step === 1 && (
        <div className="space-y-4">
          <label className="flex items-center gap-3">
            <span>{t('escrow.setup.thresholdLabel')}</span>
            <input
              type="number"
              min={1}
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1 w-20"
              aria-label={t('escrow.setup.thresholdLabel')}
            />
          </label>
          <button
            onClick={() => setStep(2)}
            className="bg-emerald-500/10 border border-emerald-500/30 px-4 py-2 rounded"
          >
            {t('escrow.setup.next')}
          </button>
        </div>
      )}

      {step === 2 && (
        <div className="space-y-4">
          <label className="block">
            {t('escrow.setup.recipientPaste')}
            <input
              type="text"
              value={recipientPk}
              onChange={(e) => setRecipientPk(e.target.value)}
              className="w-full bg-slate-800 font-mono text-xs p-2 rounded mt-1"
              aria-label={t('escrow.setup.recipientPaste')}
            />
          </label>
          <div className="flex gap-2">
            <button
              onClick={() => setStep(1)}
              className="px-4 py-2 rounded border border-slate-700"
            >
              {t('escrow.setup.back')}
            </button>
            <button
              disabled={!recipientPk}
              onClick={() => setStep(3)}
              className="bg-emerald-500/10 border border-emerald-500/30 px-4 py-2 rounded disabled:opacity-50"
            >
              {t('escrow.setup.next')}
            </button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div className="space-y-4">
          <div className="space-y-2">
            <label className="flex items-center gap-2">
              <input type="radio" checked readOnly />
              <span>{t('escrow.setup.arbitratorAuthority')}</span>
            </label>
            <p className="text-sm text-slate-400">{t('escrow.setup.arbitratorAuthorityHelp')}</p>
          </div>
          <label className="block">
            {t('escrow.setup.expiryDays')}
            <input
              type="number"
              min={1}
              value={expiryDays}
              onChange={(e) => setExpiryDays(Number(e.target.value))}
              className="ml-2 bg-slate-800 border border-slate-700 rounded px-2 py-1 w-24"
              aria-label={t('escrow.setup.expiryDays')}
            />
          </label>
          <div className="flex gap-2">
            <button
              onClick={() => setStep(2)}
              className="px-4 py-2 rounded border border-slate-700"
            >
              {t('escrow.setup.back')}
            </button>
            <button
              onClick={() => setStep(4)}
              className="bg-emerald-500/10 border border-emerald-500/30 px-4 py-2 rounded"
            >
              {t('escrow.setup.next')}
            </button>
          </div>
        </div>
      )}

      {step === 4 && (
        <div className="space-y-4">
          <h3 className="font-serif italic text-2xl">{t('escrow.setup.reviewTitle')}</h3>
          <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
            <dt className="text-slate-400">{t('escrow.setup.thresholdLabel')}</dt>
            <dd className="font-mono">{threshold}</dd>
            <dt className="text-slate-400">{t('escrow.setup.recipientPaste')}</dt>
            <dd className="font-mono text-xs break-all">{recipientPk}</dd>
            <dt className="text-slate-400">{t('escrow.setup.arbitratorAuthority')}</dt>
            <dd>✓</dd>
            <dt className="text-slate-400">{t('escrow.setup.expiryDays')}</dt>
            <dd className="font-mono">{expiryDays}</dd>
          </dl>
          <div className="flex gap-2">
            <button
              onClick={() => setStep(3)}
              className="px-4 py-2 rounded border border-slate-700"
            >
              {t('escrow.setup.back')}
            </button>
            <button
              disabled={setupState.phase === 'submitting' || true}
              title="TODO(W8): wire custodian picker + recipient keygen before enabling submit"
              onClick={() =>
                // Placeholder — UI still owes a custodian picker and a
                // recipient hybrid-pk generator before it can call submit()
                // with real inputs. See W7/W8 tracking.
                submit({
                  R: new Uint8Array(0),
                  holderPk: ('0x04' + '0'.repeat(128)) as `0x04${string}`,
                  agents: [],
                  threshold,
                  recipientHybridPk: { x25519: new Uint8Array(32), mlkem: new Uint8Array(1184) },
                  arbitrator: { chainId: 11155111, address: '0x' + '0'.repeat(40) as `0x${string}`, kind: 'authority' },
                  expiry: Math.floor(Date.now() / 1000) + expiryDays * 86400,
                  jurisdiction: 'UA',
                })
              }
              className="bg-emerald-500/10 border border-emerald-500/30 px-4 py-2 rounded disabled:opacity-50"
            >
              {setupState.phase === 'submitting'
                ? t('escrow.setup.submitting')
                : t('escrow.setup.submit')}
            </button>
          </div>
          {setupState.phase === 'done' && (
            <p className="text-emerald-300 text-sm" data-testid="submit-status">
              {t('escrow.setup.submitted')}
            </p>
          )}
          {setupState.phase === 'error' && (
            <p className="text-red-400 text-sm" data-testid="submit-error">
              {setupState.error}
            </p>
          )}
        </div>
      )}
    </section>
  );
}
