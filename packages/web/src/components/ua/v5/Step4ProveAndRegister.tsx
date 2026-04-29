import { useTranslation } from 'react-i18next';
import { isV5ArtifactsConfigured } from '../../../lib/circuitArtifacts';

export interface Step4Props {
  p7s: Uint8Array;
  onBack: () => void;
}

/**
 * Step 4 — produce the V5 proof and submit register() to QKBRegistryV5.
 *
 * Task 5 ships this as a stub: the worker entry (Task 6), pipeline
 * (Task 7), and real witness builder (Task 8) land in subsequent
 * commits. The ceremony-pump dependency is surfaced via
 * `isV5ArtifactsConfigured` so the UI shows a clear "awaiting ceremony"
 * state pre-§9.6.
 */
export function Step4ProveAndRegister({ p7s, onBack }: Step4Props) {
  const { t } = useTranslation();
  const configured = isV5ArtifactsConfigured();
  return (
    <section aria-labelledby="step4-heading" className="space-y-6">
      <h2 id="step4-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
        {t('registerV5.step4.title')}
      </h2>
      <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
        {p7s.byteLength.toLocaleString()} bytes
      </p>
      {!configured && (
        <p
          className="text-sm"
          role="status"
          data-testid="v5-ceremony-pending"
          style={{ color: 'var(--ink)', opacity: 0.7 }}
        >
          {t('registerV5.step4.ceremonyPending')}
        </p>
      )}
      <button
        type="button"
        disabled={!configured}
        className="px-6 py-3 text-mono text-sm disabled:opacity-50 disabled:cursor-not-allowed"
        style={{ background: 'var(--sovereign)', color: 'var(--paper)' }}
      >
        {t('registerV5.step4.cta')}
      </button>
      <button
        type="button"
        onClick={onBack}
        className="px-6 py-3 text-mono text-sm"
        style={{ border: '1px solid var(--ink)', color: 'var(--ink)' }}
      >
        {t('registerV5.step4.back')}
      </button>
    </section>
  );
}
