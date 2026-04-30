import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAccount } from 'wagmi';
import { buildUaBindingV2 } from '../../../lib/uaBindingGenerator';
import {
  recoverPubkeyFromWallet,
  WalletPubkeyError,
} from '../../../lib/walletPubkey';

export interface Step2Props {
  onAdvance: (bindingBytes: Uint8Array) => void;
  onBack: () => void;
}

type BuildState =
  | { kind: 'idle' }
  | { kind: 'recovering' }
  | { kind: 'ready'; bindingBytes: Uint8Array; bcanonText: string }
  | { kind: 'error'; message: string };

/**
 * Trigger a browser download of the JCS-canonical bcanon bytes so the
 * user can attach them to Diia (the only currently-supported QTSP) and
 * produce a CAdES-BES signature. The file is just the raw bytes — this
 * is what the V5 circuit's signed-attrs OID stream consumes verbatim,
 * and what Diia's signer hashes inside the messageDigest attribute.
 *
 * Filename `binding.qkb2.bin` matches the JSON-shape display fixture
 * (`binding.qkb2.json`) so users can pair them visually if they keep
 * a copy of the display fields.
 */
function downloadBindingFile(bytes: Uint8Array): void {
  // Copy into a fresh ArrayBuffer so the Blob owns its own memory; the
  // SharedArrayBuffer-vs-ArrayBuffer typing in some bundler outputs
  // breaks if we hand the Uint8Array directly.
  const owned = new Uint8Array(bytes.length);
  owned.set(bytes);
  const blob = new Blob([owned], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'binding.qkb2.bin';
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Defer revoke so the click finishes before the blob URL is freed.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/**
 * Step 2 — produce the QKB/2.0 binding bytes.
 *
 * Flow:
 *   1. Recover the wallet's secp256k1 public key via personal_sign +
 *      recoverPublicKey (one-time signature; the signature itself is
 *      discarded — only the recovered pubkey lands in the binding).
 *   2. Generate a 32-byte random nonce (binding-replay protection).
 *   3. Build the QKB/2.0 binding (core + display) and JCS-canonicalize
 *      to ≤ 1024 byte `bcanon` (= what Diia will sign + the V5 circuit
 *      consumes).
 *   4. Surface bcanon to the user (hex preview), pass it through
 *      onAdvance to Step 3 → Step 4.
 *
 * Detailed binding builder lives in `packages/web/src/lib/bindingV2.ts`
 * (V4-era; V5 reuses since the binding shape is locked by orchestration
 * §0). Display + extensions are OUTSIDE the proving surface — only the
 * core fields are JCS-canonicalized.
 */
export function Step2GenerateBinding({ onAdvance, onBack }: Step2Props) {
  const { t } = useTranslation();
  // Reserved: wallet address mirrored from wagmi if a Step 2 affordance
  // ever needs it. Removed from the visible UI because RainbowKit
  // already renders the truncated address pill at the page header.
  useAccount();
  const [state, setState] = useState<BuildState>({ kind: 'idle' });

  // Mock-prover mode (Playwright e2e + dev preview): the wallet mock
  // doesn't sign anything, so we synthesize a deterministic pk/nonce
  // and skip the wallet roundtrip. Mock-prover ignores bindingBytes
  // anyway; we just need a syntactically-valid binding to thread
  // through the state machine.
  const useMockProver =
    typeof import.meta !== 'undefined' &&
    import.meta.env?.VITE_USE_MOCK_PROVER === '1';

  const onGenerate = async (): Promise<void> => {
    setState({ kind: 'recovering' });
    try {
      const pk = new Uint8Array(65);
      if (useMockProver) {
        // Mock-prover synthetic pubkey: secp256k1 generator G (private
        // key 1). buildUaBindingV2 validates the pk is on-curve via
        // `@noble/secp256k1.ProjectivePoint.fromHex().assertValidity()`,
        // so we use a known-valid point rather than an arbitrary byte
        // pattern. Reference: SEC 2 §2.4.1, secp256k1 G.
        const G_HEX =
          '04' +
          '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
          '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
        for (let i = 0; i < 65; i++) {
          pk[i] = Number.parseInt(G_HEX.slice(i * 2, i * 2 + 2), 16);
        }
      } else {
        const { pubkeyHex } = await recoverPubkeyFromWallet();
        // Convert hex → Uint8Array. pubkeyHex is `04` + 64 X + 64 Y.
        for (let i = 0; i < 65; i++) {
          pk[i] = Number.parseInt(pubkeyHex.slice(i * 2, i * 2 + 2), 16);
        }
      }
      const nonce = new Uint8Array(32);
      if (useMockProver) {
        nonce.fill(0xab);
      } else {
        crypto.getRandomValues(nonce);
      }
      const timestamp = useMockProver
        ? 1777478400
        : Math.floor(Date.now() / 1000);
      const { bcanon } = buildUaBindingV2({ pk, timestamp, nonce });
      // 32-char hex preview for the UI; full bytes flow through onAdvance.
      const headHex = Array.from(bcanon.subarray(0, 16))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      const tailHex = Array.from(bcanon.subarray(bcanon.length - 16))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      const bcanonText = `${bcanon.byteLength} bytes — ${headHex}…${tailHex}`;
      setState({ kind: 'ready', bindingBytes: bcanon, bcanonText });
    } catch (err) {
      const message =
        err instanceof WalletPubkeyError
          ? `${err.message} (${err.code})`
          : err instanceof Error
            ? err.message
            : String(err);
      setState({ kind: 'error', message });
    }
  };

  const onContinue = (): void => {
    if (state.kind !== 'ready') return;
    onAdvance(state.bindingBytes);
  };

  return (
    <section aria-labelledby="step2-heading" className="space-y-6">
      <h2 id="step2-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
        {t('registerV5.step2.title')}
      </h2>
      <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
        {t(
          'registerV5.step2.body',
          'We will ask your wallet to sign a deterministic recovery message so we can include your public key in the binding. The signature itself is discarded.',
        )}
      </p>
      {state.kind === 'idle' && (
        <button
          type="button"
          onClick={() => void onGenerate()}
          data-testid="v5-generate-binding-cta"
          className="px-6 py-3 text-mono text-sm"
          style={{ background: 'var(--sovereign)', color: 'var(--bone)' }}
        >
          {t('registerV5.step2.generate', 'Generate binding')}
        </button>
      )}
      {state.kind === 'recovering' && (
        <p className="text-sm" role="status" data-testid="v5-binding-recovering">
          {t(
            'registerV5.step2.recovering',
            'Awaiting wallet signature for pubkey recovery…',
          )}
        </p>
      )}
      {state.kind === 'error' && (
        <p
          className="text-sm"
          role="alert"
          data-testid="v5-binding-error"
          style={{ color: 'var(--ink)' }}
        >
          {state.message}
        </p>
      )}
      {state.kind === 'ready' && (
        <div className="space-y-3">
          <p
            className="text-mono text-xs"
            data-testid="v5-binding-preview"
            style={{ color: 'var(--ink)' }}
          >
            {state.bcanonText}
          </p>
          <button
            type="button"
            onClick={() => downloadBindingFile(state.bindingBytes)}
            data-testid="v5-binding-download"
            className="px-6 py-3 text-mono text-sm"
            style={{
              border: '1px solid var(--sovereign)',
              color: 'var(--sovereign)',
              background: 'transparent',
            }}
          >
            {t('registerV5.step2.download', 'Download binding (.bin)')}
          </button>
          <p
            className="text-xs max-w-prose"
            style={{ color: 'var(--ink)', opacity: 0.7 }}
          >
            {t(
              'registerV5.step2.downloadHint',
              'Attach this file to Diia (or your QTSP client) and produce a CAdES-BES signature over its bytes. The .p7s file you receive goes into Step 3.',
            )}
          </p>
        </div>
      )}
      <div className="flex gap-4">
        <button
          type="button"
          onClick={onBack}
          className="px-6 py-3 text-mono text-sm"
          style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}
        >
          {t('registerV5.step2.back')}
        </button>
        <button
          type="button"
          onClick={onContinue}
          disabled={state.kind !== 'ready'}
          data-testid="v5-binding-advance-cta"
          className="px-6 py-3 text-mono text-sm disabled:opacity-50 disabled:cursor-not-allowed"
          style={{ background: 'var(--sovereign)', color: 'var(--bone)' }}
        >
          {t('registerV5.step2.advance')}
        </button>
      </div>
    </section>
  );
}
