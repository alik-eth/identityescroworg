import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNotaryRecover } from '../hooks/use-notary-recover';
import { buildNotaryAttest } from '../lib/notary-attest';

/**
 * QIE `/escrow/notary` — notary-driven recovery on behalf of an heir.
 *
 * Three-step wizard:
 *   1. Heir inputs (hybrid pk, escrowId, arbitrator unlock tx).
 *   2. Evidence upload (notary cert + notary .p7s over the attestation).
 *   3. Reconstruct — hook posts `on_behalf_of` to each agent and collects
 *      share ciphertexts. Displays a "Re-bind QKB" CTA linking to
 *      `/generate` for the heir's new wallet.
 */

type Step = 'inputs' | 'evidence' | 'reconstruct' | 'done';

function fileToHex(file: File): Promise<`0x${string}`> {
  // Use FileReader because jsdom-based test environments do not implement
  // File.prototype.arrayBuffer().
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error('FileReader failed'));
    reader.onload = () => {
      const buf = reader.result as ArrayBuffer;
      const u8 = new Uint8Array(buf);
      let s = '';
      for (let i = 0; i < u8.length; i++) s += u8[i]!.toString(16).padStart(2, '0');
      resolve(`0x${s}` as `0x${string}`);
    };
    reader.readAsArrayBuffer(file);
  });
}

function ensureHexPrefix(s: string): `0x${string}` {
  return (s.startsWith('0x') ? s : `0x${s}`) as `0x${string}`;
}

export function EscrowNotaryScreen() {
  const { t } = useTranslation();
  const [step, setStep] = useState<Step>('inputs');
  const [heirPk, setHeirPk] = useState('');
  const [escrowId, setEscrowId] = useState('');
  const [unlockTx, setUnlockTx] = useState('');
  const [notaryCertHex, setNotaryCertHex] = useState<`0x${string}` | ''>('');
  const [notarySigHex, setNotarySigHex] = useState<`0x${string}` | ''>('');
  const [agentEndpoint, setAgentEndpoint] = useState('');

  const { state, run } = useNotaryRecover();

  // Preview the canonical attestation payload so the notary can download
  // it as `attest.json` and sign it with Diia out-of-band.
  const attestPreview = useMemo(() => {
    if (!heirPk || !escrowId) return null;
    try {
      const bytes = buildNotaryAttest({
        recipient_pk: ensureHexPrefix(heirPk),
        escrowId: ensureHexPrefix(escrowId),
      });
      return new TextDecoder().decode(bytes);
    } catch {
      return null;
    }
  }, [heirPk, escrowId]);

  function downloadAttest() {
    if (!attestPreview) return;
    const blob = new Blob([attestPreview], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'notary-attest.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  async function submit() {
    if (!notaryCertHex || !notarySigHex || !agentEndpoint) return;
    setStep('reconstruct');
    await run({
      escrowId: ensureHexPrefix(escrowId),
      recipient_pk: ensureHexPrefix(heirPk),
      arbitrator_unlock_tx: ensureHexPrefix(unlockTx),
      notary_cert: notaryCertHex,
      notary_sig: notarySigHex,
      agents: [{ agent_id: 'primary', endpoint: agentEndpoint }],
    });
    setStep('done');
  }

  return (
    <section className="space-y-8">
      <header>
        <h2 className="font-serif italic text-4xl mb-2">{t('escrow.notary.title')}</h2>
        <p className="text-slate-400">{t('escrow.notary.subtitle')}</p>
      </header>

      {step === 'inputs' && (
        <div className="space-y-4">
          <label className="block">
            {t('escrow.notary.heirPkLabel')}
            <input
              type="text"
              value={heirPk}
              onChange={(e) => setHeirPk(e.target.value)}
              className="w-full bg-slate-800 font-mono text-xs p-2 rounded mt-1"
              aria-label={t('escrow.notary.heirPkLabel')}
            />
            <span className="text-xs text-slate-500">{t('escrow.notary.heirPkHelp')}</span>
          </label>
          <label className="block">
            {t('escrow.notary.escrowIdLabel')}
            <input
              type="text"
              value={escrowId}
              onChange={(e) => setEscrowId(e.target.value)}
              className="w-full bg-slate-800 font-mono text-xs p-2 rounded mt-1"
              aria-label={t('escrow.notary.escrowIdLabel')}
            />
            <span className="text-xs text-slate-500">{t('escrow.notary.escrowIdHelp')}</span>
          </label>
          <label className="block">
            {t('escrow.notary.unlockTxLabel')}
            <input
              type="text"
              value={unlockTx}
              onChange={(e) => setUnlockTx(e.target.value)}
              className="w-full bg-slate-800 font-mono text-xs p-2 rounded mt-1"
              aria-label={t('escrow.notary.unlockTxLabel')}
            />
            <span className="text-xs text-slate-500">{t('escrow.notary.unlockTxHelp')}</span>
          </label>
          {attestPreview && (
            <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-3 space-y-2">
              <p className="text-sm text-slate-400">{t('escrow.notary.attestReady')}</p>
              <pre
                data-testid="attest-preview"
                className="text-xs font-mono text-emerald-200 break-all whitespace-pre-wrap"
              >
                {attestPreview}
              </pre>
              <button
                onClick={downloadAttest}
                className="text-xs px-3 py-1 rounded border border-slate-600"
              >
                {t('escrow.notary.buildAttest')}
              </button>
            </div>
          )}
          <button
            disabled={!heirPk || !escrowId || !unlockTx}
            onClick={() => setStep('evidence')}
            className="bg-emerald-500/10 border border-emerald-500/30 px-4 py-2 rounded disabled:opacity-50"
          >
            {t('escrow.setup.next')}
          </button>
        </div>
      )}

      {step === 'evidence' && (
        <div className="space-y-4">
          <label className="block">
            {t('escrow.notary.notaryCertLabel')}
            <input
              type="file"
              accept=".cer,.crt,.der,application/pkix-cert,application/x-x509-ca-cert"
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (f) setNotaryCertHex(await fileToHex(f));
              }}
              aria-label={t('escrow.notary.notaryCertLabel')}
            />
          </label>
          <label className="block">
            {t('escrow.notary.notarySigLabel')}
            <input
              type="file"
              accept=".p7s,application/pkcs7-signature"
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (f) setNotarySigHex(await fileToHex(f));
              }}
              aria-label={t('escrow.notary.notarySigLabel')}
            />
            <span className="text-xs text-slate-500">{t('escrow.notary.notarySigHelp')}</span>
          </label>
          <label className="block">
            {t('escrow.recover.agentEndpointLabel')}
            <input
              type="text"
              value={agentEndpoint}
              onChange={(e) => setAgentEndpoint(e.target.value)}
              className="w-full bg-slate-800 font-mono text-xs p-2 rounded mt-1"
              aria-label={t('escrow.recover.agentEndpointLabel')}
            />
          </label>
          <div className="flex gap-2">
            <button
              onClick={() => setStep('inputs')}
              className="px-4 py-2 rounded border border-slate-700"
            >
              {t('escrow.setup.back')}
            </button>
            <button
              disabled={!notaryCertHex || !notarySigHex || !agentEndpoint}
              onClick={submit}
              className="bg-emerald-500/10 border border-emerald-500/30 px-4 py-2 rounded disabled:opacity-50"
            >
              {t('escrow.notary.run')}
            </button>
          </div>
        </div>
      )}

      {(step === 'reconstruct' || step === 'done') && (
        <div className="space-y-4">
          {state.phase === 'collecting' && (
            <p className="text-slate-400">{t('escrow.notary.running')}</p>
          )}
          {state.phase === 'done' && (
            <>
              <p className="text-emerald-300" data-testid="reconstructed-R">
                {t('escrow.notary.done')} ({state.shares.length} shares)
              </p>
              <a
                href="/generate"
                data-testid="rebind-link"
                className="inline-block bg-emerald-500/10 border border-emerald-500/30 px-4 py-2 rounded"
              >
                {t('escrow.notary.rebindLink')}
              </a>
            </>
          )}
          {state.phase === 'error' && (
            <p
              className="text-red-400"
              data-testid={state.wrongState ? 'notary-wrong-state' : 'notary-error'}
            >
              {t('escrow.notary.error')}: {state.error}
            </p>
          )}
        </div>
      )}
    </section>
  );
}
