/**
 * /generate — Step 1 of the binding flow.
 *
 * Generates a fresh secp256k1 keypair in-browser (see lib/keygen.ts), lets
 * the user pick a declaration locale and an optional context, then builds a
 * canonical JCS binding statement via lib/binding.ts. The binding + private
 * key are persisted into sessionStorage (lib/session.ts) so the /sign and
 * /upload screens can consume them.
 *
 * This screen is i18n-complete — every user-visible string keys through
 * react-i18next. The only exception is the rendered hex public key, which is
 * data, not copy.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from '@tanstack/react-router';
import * as secp from '@noble/secp256k1';
import { PhaseCard } from '../components/PhaseCard';
import { generateKeypair } from '../lib/keygen';
import { buildBinding, canonicalizeBinding, type Locale } from '../lib/binding';
import { saveSession, bytesToHex, bytesToB64 } from '../lib/session';
import { localizeError } from '../lib/errors';

export function GenerateScreen() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();

  const [pubkeyHex, setPubkeyHex] = useState<string | null>(null);
  const [privkeyHex, setPrivkeyHex] = useState<string | null>(null);
  const [locale, setLocale] = useState<Locale>(
    (i18n.language.startsWith('uk') ? 'uk' : 'en') as Locale,
  );
  const [error, setError] = useState<string | null>(null);

  const onGenerate = (): void => {
    setError(null);
    const kp = generateKeypair();
    const uncompressed = secp.getPublicKey(kp.privkey, false); // 65 bytes, 0x04||X||Y
    setPrivkeyHex(bytesToHex(kp.privkey));
    setPubkeyHex(bytesToHex(uncompressed));
  };

  const onCreateBinding = (): void => {
    setError(null);
    try {
      if (!pubkeyHex || !privkeyHex) {
        setError(t('generate.missingKey'));
        return;
      }
      const pk = hexToU8(pubkeyHex);
      const nonce = crypto.getRandomValues(new Uint8Array(32));
      const timestamp = Math.floor(Date.now() / 1000);
      const binding = buildBinding({ pk, timestamp, nonce, locale });
      const bcanon = canonicalizeBinding(binding);
      saveSession({
        privkeyHex,
        pubkeyUncompressedHex: pubkeyHex,
        locale,
        binding,
        bcanonB64: bytesToB64(bcanon),
      });
      navigate({ to: '/sign' });
    } catch (err) {
      setError(localizeError(err, { t }));
    }
  };

  return (
    <PhaseCard step={1} total={4} accent="emerald" title={t('generate.heading')}>
      <p className="text-slate-400 mb-6">{t('generate.intro')}</p>

      <div className="space-y-4">
        <button
          type="button"
          onClick={onGenerate}
          data-testid="generate-key"
          className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold rounded-md transition-colors"
        >
          {t('generate.generateButton')}
        </button>

        {pubkeyHex && (
          <div className="space-y-1" data-testid="pubkey-block">
            <label className="block text-xs font-mono text-slate-500 uppercase tracking-widest">
              {t('generate.pubkeyLabel')}
            </label>
            <div
              data-testid="pubkey-hex"
              className="font-mono text-[11px] text-emerald-300 break-all rounded border border-slate-700 bg-slate-900/50 px-3 py-2"
            >
              0x{pubkeyHex}
            </div>
          </div>
        )}

        <div className="space-y-1">
          <label className="block text-xs font-mono text-slate-500 uppercase tracking-widest">
            {t('generate.localeLabel')}
          </label>
          <select
            data-testid="locale-select"
            value={locale}
            onChange={(e) => setLocale(e.target.value as Locale)}
            className="bg-slate-900 border border-slate-700 text-slate-200 text-sm rounded px-2 py-1"
          >
            <option value="en">{t('lang.en')}</option>
            <option value="uk">{t('lang.uk')}</option>
          </select>
        </div>

        {error && (
          <div
            data-testid="generate-error"
            role="alert"
            className="text-red-400 text-sm border border-red-500/40 bg-red-500/10 px-3 py-2 rounded"
          >
            {error}
          </div>
        )}

        <button
          type="button"
          onClick={onCreateBinding}
          disabled={!pubkeyHex}
          data-testid="create-binding"
          className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-700 disabled:text-slate-500 text-slate-900 text-sm font-semibold rounded-md transition-colors"
        >
          {t('generate.createBinding')}
        </button>
      </div>
    </PhaseCard>
  );
}

function hexToU8(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
