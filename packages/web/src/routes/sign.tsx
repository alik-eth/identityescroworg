/**
 * /sign — Step 2 of the binding flow.
 *
 * Reads the canonical binding statement from sessionStorage, shows a preview
 * + sha-256 digest, and lets the user download `binding.qkb.json` (the JCS
 * bytes verbatim — no wrapper, no extra whitespace, per §4.1 of the
 * orchestration plan). Below the download is a per-jurisdiction QES-tool
 * pointer panel (UA Diia, EE SK, PL Szafir).
 *
 * The actual QES signing happens OUT OF BAND — the SPA has no way to drive a
 * smart-card reader. Users return to /upload with the emitted .p7s.
 */
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from '@tanstack/react-router';
import { sha256 } from '@noble/hashes/sha256';
import { PhaseCard } from '../components/PhaseCard';
import { loadSession, b64ToBytes, bytesToHex } from '../lib/session';

export function SignScreen() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const session = loadSession();

  const bcanon = useMemo<Uint8Array | null>(() => {
    if (!session.bcanonB64) return null;
    return b64ToBytes(session.bcanonB64);
  }, [session.bcanonB64]);

  if (!bcanon) {
    return (
      <PhaseCard step={2} total={4} accent="blue" title={t('sign.heading')}>
        <p data-testid="sign-missing" className="text-amber-300">
          {t('sign.missingBinding')}
        </p>
      </PhaseCard>
    );
  }

  const preview = new TextDecoder().decode(bcanon);
  const hashHex = bytesToHex(sha256(bcanon));

  const onDownload = (): void => {
    // Copy into a fresh ArrayBuffer so the BlobPart type is unambiguous.
    const ab = new ArrayBuffer(bcanon.byteLength);
    new Uint8Array(ab).set(bcanon);
    const blob = new Blob([ab], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'binding.qkb.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <PhaseCard step={2} total={4} accent="blue" title={t('sign.heading')}>
      <p className="text-slate-400 mb-5">{t('sign.intro')}</p>

      <button
        type="button"
        onClick={onDownload}
        data-testid="download-binding"
        className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold rounded-md transition-colors"
      >
        {t('sign.downloadButton')}
      </button>

      <div className="mt-6 space-y-1">
        <label className="block text-xs font-mono text-slate-500 uppercase tracking-widest">
          {t('sign.previewLabel')}
        </label>
        <pre
          data-testid="bcanon-preview"
          className="font-mono text-[11px] text-slate-200 rounded border border-slate-700 bg-slate-900/60 px-3 py-2 whitespace-pre-wrap break-all max-h-56 overflow-auto"
        >
          {preview}
        </pre>
      </div>

      <div className="mt-4 space-y-1">
        <label className="block text-xs font-mono text-slate-500 uppercase tracking-widest">
          {t('sign.hashLabel')}
        </label>
        <div
          data-testid="bcanon-hash"
          className="font-mono text-[11px] text-emerald-300 break-all rounded border border-slate-700 bg-slate-900/50 px-3 py-2"
        >
          0x{hashHex}
        </div>
      </div>

      <h3 className="mt-8 mb-3 text-sm font-semibold text-slate-200">
        {t('sign.toolsHeading')}
      </h3>
      <ul className="space-y-3 text-sm" data-testid="qes-tools">
        <li>
          <strong className="text-slate-100">{t('sign.toolsUaDiia')}</strong>
          <p className="text-slate-400">{t('sign.toolsUaDiiaDesc')}</p>
        </li>
        <li>
          <strong className="text-slate-100">{t('sign.toolsEeSk')}</strong>
          <p className="text-slate-400">{t('sign.toolsEeSkDesc')}</p>
        </li>
        <li>
          <strong className="text-slate-100">{t('sign.toolsPl')}</strong>
          <p className="text-slate-400">{t('sign.toolsPlDesc')}</p>
        </li>
      </ul>

      <div className="mt-8 flex gap-3">
        <button
          type="button"
          onClick={() => navigate({ to: '/generate' })}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm rounded"
        >
          {t('common.back')}
        </button>
        <button
          type="button"
          onClick={() => navigate({ to: '/upload' })}
          data-testid="sign-next"
          className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-900 text-sm font-semibold rounded-md"
        >
          {t('common.continue')}
        </button>
      </div>
    </PhaseCard>
  );
}
