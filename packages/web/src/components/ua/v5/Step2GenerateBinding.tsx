import { useTranslation } from 'react-i18next';

export interface Step2Props {
  onAdvance: () => void;
  onBack: () => void;
}

/**
 * Step 2 — produce the QKB/2.0 binding bytes. The detailed binding
 * builder lives in `packages/web/src/lib/bindingV2.ts` (V4-era; V5
 * reuses the same canonicalisation since the binding shape is locked
 * by orchestration §0). Wiring the actual download + clipboard handoff
 * happens in Task 7 / Task 11.
 */
export function Step2GenerateBinding({ onAdvance, onBack }: Step2Props) {
  const { t } = useTranslation();
  return (
    <section aria-labelledby="step2-heading" className="space-y-6">
      <h2 id="step2-heading" className="text-3xl" style={{ color: 'var(--ink)' }}>
        {t('registerV5.step2.title')}
      </h2>
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
          onClick={onAdvance}
          className="px-6 py-3 text-mono text-sm"
          style={{ background: 'var(--sovereign)', color: 'var(--paper)' }}
        >
          {t('registerV5.step2.advance')}
        </button>
      </div>
    </section>
  );
}
