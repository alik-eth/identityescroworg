/**
 * V5.1 SCW (smart contract wallet) passphrase opt-in modal.
 *
 * Per orchestration §1.2 wallet-secret derivation: SCWs cannot run the
 * deterministic personal_sign HKDF path because their on-chain signature
 * verification logic is non-deterministic across chain forks (an SCW
 * could change its `isValidSignature` implementation between the time
 * the secret was derived and any later rotation, breaking re-derivation).
 * SCW users instead derive the wallet-secret from a user-chosen passphrase
 * via Argon2id. The salt binds the derivation to the wallet address so
 * the same passphrase used with two different SCWs produces two different
 * secrets.
 *
 * UX gates surfaced here:
 *   - Loud warning: "if you lose this passphrase, you cannot recover your
 *     identity, even with a valid Diia QES." This is the cold truth of the
 *     SCW path; deferring or sugar-coating it would put users at material
 *     risk later.
 *   - Strength meter via zxcvbn (lazy-loaded; EOA users don't pay the
 *     bundle cost). Minimum target: ≥ 80 bits of guess-resistance per
 *     orchestration spec. The meter blocks submit until the threshold
 *     is met.
 *   - Opt-out: prominent "connect an EOA wallet instead" CTA. EOA is
 *     the recommended path for V5 alpha; SCW is opt-in.
 *
 * The modal calls back with the verified passphrase on submit. The caller
 * derives the wallet-secret via `deriveWalletSecretScw(passphrase, address)`
 * and threads it into the rest of the flow (Step4ProveAndRegister or
 * RotateWalletFlow). The modal does NOT itself derive — keeping derivation
 * close to the caller's existing walletSecret-handling code.
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

/** Minimum zxcvbn guess-log10 to satisfy the 80-bit target.
 *  log10(2^80) ≈ 24.08; we round up to 25 for headroom. zxcvbn's
 *  guesses_log10 is conservative against dictionary + pattern attacks. */
const MIN_GUESSES_LOG10 = 25;

export interface ScwPassphraseModalProps {
  /** Whether the modal is visible. Caller controls open/close state. */
  readonly open: boolean;
  /** SCW wallet address. Displayed in modal copy + used by caller for
   *  Argon2id salt binding. */
  readonly walletAddress: `0x${string}`;
  /** Submit handler. Receives the user-entered passphrase. The caller
   *  is responsible for the Argon2id derivation + threading the secret. */
  readonly onSubmit: (passphrase: string) => void | Promise<void>;
  /** Cancel handler — typically dismisses the modal AND surfaces
   *  the "connect EOA" CTA in the parent. */
  readonly onCancel: () => void;
  /** True while the parent runs the (slow) Argon2id derivation. The modal
   *  shows a status message and disables submit while this is true. */
  readonly isDeriving?: boolean;
}

interface ZxcvbnResult {
  guesses_log10: number;
  score: 0 | 1 | 2 | 3 | 4;
  feedback: { warning: string; suggestions: string[] };
}

export function ScwPassphraseModal({
  open,
  walletAddress,
  onSubmit,
  onCancel,
  isDeriving = false,
}: ScwPassphraseModalProps) {
  const { t } = useTranslation();
  const [passphrase, setPassphrase] = useState('');
  const [revealed, setRevealed] = useState(false);
  // `scoredPassphrase` holds the EXACT passphrase string that produced
  // the current `strength`. Submit is gated on `scoredPassphrase === passphrase`
  // so an async-in-flight zxcvbn call can never green-light a weakened
  // input — the score is only trusted when it provably matches what's
  // in the textbox right now.
  const [scoredPassphrase, setScoredPassphrase] = useState('');
  const [strength, setStrength] = useState<ZxcvbnResult | null>(null);
  const [zxcvbnLoading, setZxcvbnLoading] = useState(false);

  // Lazy load zxcvbn the first time the user types. Keeps the bundle
  // off the EOA path (which is the recommended/default flow).
  useEffect(() => {
    if (!open || passphrase.length === 0) {
      setStrength(null);
      setScoredPassphrase('');
      setZxcvbnLoading(false);
      return;
    }
    let cancelled = false;
    setZxcvbnLoading(true);
    void (async () => {
      const mod = await import('zxcvbn');
      if (cancelled) return;
      const result = mod.default(passphrase);
      setStrength({
        guesses_log10: result.guesses_log10,
        score: result.score,
        feedback: {
          warning: result.feedback.warning ?? '',
          suggestions: result.feedback.suggestions ?? [],
        },
      });
      setScoredPassphrase(passphrase);  // pin score to THIS input value
      setZxcvbnLoading(false);
    })().catch(() => {
      if (!cancelled) setZxcvbnLoading(false);
    });
    return () => { cancelled = true; };
  }, [passphrase, open]);

  if (!open) return null;

  // Gate: score must exist, meet threshold, AND have been computed
  // against the currently-displayed passphrase. The third condition
  // closes the React-render-vs-async-effect race window codex flagged:
  // even if `strength` is stale (recompute in flight), submit stays
  // disabled until `scoredPassphrase` catches up to the input.
  const meetsThreshold = strength !== null
    && strength.guesses_log10 >= MIN_GUESSES_LOG10
    && scoredPassphrase === passphrase;
  const canSubmit = meetsThreshold && !zxcvbnLoading && !isDeriving;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="scw-passphrase-heading"
      data-testid="scw-passphrase-modal"
      // Manual backdrop styling — Tailwind classes won't render reliably
      // for an inset-0 overlay with the package's CSS variable theme.
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 50,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(20, 19, 14, 0.7)',  // var(--ink) at 70% alpha
        padding: '1.5rem',
      }}
    >
      <div
        className="max-w-lg w-full p-8 space-y-6"
        style={{ background: 'var(--bone)', color: 'var(--ink)' }}
      >
        <h2 id="scw-passphrase-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
          {t('scwPassphrase.title')}
        </h2>
        <p className="text-base" style={{ color: 'var(--ink)' }}>
          {t('scwPassphrase.body')}
        </p>
        <p className="text-xs text-mono" style={{ color: 'var(--ink)', opacity: 0.6 }}>
          {t('scwPassphrase.walletLabel')} {walletAddress.slice(0, 6)}…{walletAddress.slice(-4)}
        </p>

        {/* Loud warning — sienna sealed border, full text. */}
        <aside
          className="p-4 space-y-2 border"
          style={{ borderColor: 'var(--seal)', color: 'var(--seal)' }}
          data-testid="scw-passphrase-warning"
        >
          <p className="text-sm font-semibold">{t('scwPassphrase.warningTitle')}</p>
          <p className="text-sm">{t('scwPassphrase.warningBody')}</p>
        </aside>

        <div className="space-y-2">
          <label htmlFor="scw-passphrase-input" className="text-sm text-mono"
            style={{ color: 'var(--ink)', opacity: 0.7 }}>
            {t('scwPassphrase.inputLabel')}
          </label>
          <input
            id="scw-passphrase-input"
            type={revealed ? 'text' : 'password'}
            data-testid="scw-passphrase-input"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            disabled={isDeriving}
            autoComplete="new-password"
            spellCheck={false}
            className="w-full p-2 text-mono text-sm"
            style={{
              background: 'var(--bone)',
              color: 'var(--ink)',
              border: '1px solid var(--ink)',
            }}
          />
          <button
            type="button"
            onClick={() => setRevealed((v) => !v)}
            disabled={isDeriving}
            className="text-xs text-mono"
            style={{ color: 'var(--ink)', opacity: 0.6, textDecoration: 'underline' }}
          >
            {revealed ? t('scwPassphrase.hide') : t('scwPassphrase.reveal')}
          </button>
        </div>

        {/* Strength meter. Uses zxcvbn guesses_log10 for a continuous
            measure rather than the 0-4 score (which collapses too many
            states for our 80-bit floor). */}
        {passphrase.length > 0 && (
          <div className="space-y-1" data-testid="scw-passphrase-strength">
            <p className="text-xs text-mono" style={{ color: 'var(--ink)', opacity: 0.6 }}>
              {zxcvbnLoading
                ? t('scwPassphrase.computing')
                : strength
                  ? t('scwPassphrase.strength', {
                      bits: Math.round(strength.guesses_log10 * 3.32193),
                      target: 80,
                    })
                  : ''}
            </p>
            {strength?.feedback.warning && (
              <p className="text-xs" style={{ color: 'var(--seal)' }}
                data-testid="scw-passphrase-feedback-warning">
                {strength.feedback.warning}
              </p>
            )}
            {strength && strength.feedback.suggestions.length > 0 && (
              <ul className="text-xs list-disc list-inside" style={{ color: 'var(--ink)', opacity: 0.7 }}>
                {strength.feedback.suggestions.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        {isDeriving && (
          <p className="text-sm" role="status" data-testid="scw-passphrase-deriving"
            style={{ color: 'var(--ink)', opacity: 0.7 }}>
            {t('scwPassphrase.deriving')}
          </p>
        )}

        <div className="flex flex-col gap-3 pt-2">
          <button
            type="button"
            onClick={() => void onSubmit(passphrase)}
            disabled={!canSubmit}
            data-testid="scw-passphrase-submit"
            className="px-6 py-3 text-mono text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ background: 'var(--sovereign)', color: 'var(--bone)' }}
          >
            {t('scwPassphrase.submit')}
          </button>
          <button
            type="button"
            onClick={onCancel}
            disabled={isDeriving}
            data-testid="scw-passphrase-use-eoa"
            className="px-6 py-3 text-mono text-sm disabled:opacity-50"
            style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}
          >
            {t('scwPassphrase.useEoaInstead')}
          </button>
        </div>
      </div>
    </div>
  );
}
