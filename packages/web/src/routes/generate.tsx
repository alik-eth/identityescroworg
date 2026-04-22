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
import { recoverPubkeyFromWallet, WalletPubkeyError } from '../lib/walletPubkey';
import { pkAddressFromHex } from '../lib/pkAddress';

type KeySource = 'fresh' | 'wallet';

export function GenerateScreen() {
  const { t } = useTranslation();
  const navigate = useNavigate();

  const [pubkeyHex, setPubkeyHex] = useState<string | null>(null);
  const [privkeyHex, setPrivkeyHex] = useState<string | null>(null);
  const [keySource, setKeySource] = useState<KeySource | null>(null);
  const [walletAddress, setWalletAddress] = useState<`0x${string}` | null>(null);
  const [locale, setLocale] = useState<Locale>('en');
  const [contextText, setContextText] = useState('');
  const [error, setError] = useState<string | null>(null);

  const onGenerate = (): void => {
    setError(null);
    const kp = generateKeypair();
    const uncompressed = secp.getPublicKey(kp.privkey, false); // 65 bytes, 0x04||X||Y
    setPrivkeyHex(bytesToHex(kp.privkey));
    setPubkeyHex(bytesToHex(uncompressed));
    setKeySource('fresh');
    setWalletAddress(null);
  };

  const onUseWallet = async (): Promise<void> => {
    setError(null);
    try {
      const { pubkeyHex: recovered, address } = await recoverPubkeyFromWallet();
      setPrivkeyHex(null);
      setPubkeyHex(recovered);
      setKeySource('wallet');
      setWalletAddress(address);
    } catch (err) {
      if (err instanceof WalletPubkeyError) {
        setError(t(`generate.walletError.${err.code}`, t('generate.walletError.default')));
      } else {
        setError(localizeError(err, { t }));
      }
    }
  };

  const onCreateBinding = (): void => {
    setError(null);
    try {
      if (!pubkeyHex) {
        setError(t('generate.missingKey'));
        return;
      }
      const pk = hexToU8(pubkeyHex);
      const nonce = crypto.getRandomValues(new Uint8Array(32));
      const timestamp = Math.floor(Date.now() / 1000);
      // Optional per-app context for Sybil-resistant nullifier (§14.4). Empty
      // string ⇒ omit ⇒ binding.context = "0x" (global identity proof).
      const ctxTrim = contextText.trim();
      const binding =
        ctxTrim.length > 0
          ? buildBinding({
              pk,
              timestamp,
              nonce,
              locale,
              context: new TextEncoder().encode(ctxTrim),
            })
          : buildBinding({ pk, timestamp, nonce, locale });
      const bcanon = canonicalizeBinding(binding);
      saveSession({
        ...(privkeyHex ? { privkeyHex } : {}),
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
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={onGenerate}
            data-testid="generate-key"
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold rounded-md transition-colors"
          >
            {t('generate.generateButton')}
          </button>
          <button
            type="button"
            onClick={() => void onUseWallet()}
            data-testid="use-wallet-key"
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-100 text-sm font-semibold rounded-md transition-colors"
          >
            {t('generate.useWalletButton')}
          </button>
        </div>

        {pubkeyHex && (
          <div className="space-y-1" data-testid="pubkey-block">
            <label className="block text-xs font-mono text-slate-500 uppercase tracking-widest">
              {t('generate.pubkeyLabel')}
              {keySource === 'wallet' && walletAddress && (
                <span
                  data-testid="pubkey-source-wallet"
                  className="ml-2 inline-block rounded bg-amber-500/10 border border-amber-500/40 px-2 py-[1px] text-[10px] text-amber-300 normal-case tracking-normal"
                >
                  {t('generate.derivedFromWallet', { address: walletAddress })}
                </span>
              )}
              {keySource === 'fresh' && (
                <span
                  data-testid="pubkey-source-fresh"
                  className="ml-2 inline-block rounded bg-emerald-500/10 border border-emerald-500/40 px-2 py-[1px] text-[10px] text-emerald-300 normal-case tracking-normal"
                >
                  {t('generate.generatedFresh')}
                </span>
              )}
            </label>
            <div
              data-testid="pubkey-hex"
              className="font-mono text-[11px] text-emerald-300 break-all rounded border border-slate-700 bg-slate-900/50 px-3 py-2"
            >
              0x{pubkeyHex}
            </div>
            <div className="pt-2 space-y-1">
              <label className="block text-xs font-mono text-slate-500 uppercase tracking-widest">
                {t('generate.pkAddressLabel')}
              </label>
              <div
                data-testid="pk-address"
                className="font-mono text-[12px] text-slate-100 break-all rounded border border-slate-700 bg-slate-900/50 px-3 py-2"
              >
                {pkAddressFromHex(pubkeyHex)}
              </div>
              <p className="text-[11px] text-slate-500">
                {t('generate.pkAddressHelp')}
              </p>
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

        <div className="space-y-1">
          <label
            htmlFor="context-input"
            className="block text-xs font-mono text-slate-500 uppercase tracking-widest"
          >
            {t('generate.contextLabel')}
          </label>
          <input
            id="context-input"
            type="text"
            data-testid="context-input"
            value={contextText}
            onChange={(e) => setContextText(e.target.value)}
            placeholder={t('generate.contextPlaceholder')}
            autoComplete="off"
            spellCheck={false}
            className="w-full bg-slate-900 border border-slate-700 text-slate-200 text-sm font-mono rounded px-2 py-1"
          />
          <p className="text-[11px] text-slate-500">{t('generate.contextHelp')}</p>
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
