// V5 register flow has 4 stages, distinct from V4's StepIndicator
// (Install / Submit / Mint). Kept as a sibling rather than extended on
// top of StepIndicator so V4 ergonomics are unaffected during migration.
import { useTranslation } from 'react-i18next';

export interface StepIndicatorV5Props {
  current: 1 | 2 | 3 | 4;
}

// EN keys live in i18n/en.json under registerV5.indicator.{connect,
// generate, sign, prove}; UK has its own translation. The fallback
// strings below match what the page rendered before the indicator was
// localised, so any locale missing the bundle still reads correctly.
const STEP_KEYS = [
  ['registerV5.indicator.connect', 'Connect'],
  ['registerV5.indicator.generate', 'Generate'],
  ['registerV5.indicator.sign', 'Sign'],
  ['registerV5.indicator.prove', 'Prove + register'],
] as const;

export function StepIndicatorV5({ current }: StepIndicatorV5Props) {
  const { t } = useTranslation();
  return (
    <ol
      className="flex flex-wrap gap-6 text-mono text-sm"
      aria-label={t('registerV5.indicator.aria', 'Progress')}
    >
      {STEP_KEYS.map(([key, fallback], i) => {
        const idx = i + 1;
        const active = idx === current;
        const done = idx < current;
        const label = t(key, fallback);
        return (
          <li key={key} className="flex items-center gap-2">
            <span
              className="inline-block w-2 h-2 rounded-none"
              style={{
                background: done || active ? 'var(--sovereign)' : 'transparent',
                border: '1px solid var(--sovereign)',
              }}
              aria-current={active ? 'step' : undefined}
            />
            <span style={{ opacity: active ? 1 : 0.6 }}>
              {idx} — {label}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
