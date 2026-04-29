// V5 register flow has 4 stages, distinct from V4's StepIndicator
// (Install / Submit / Mint). Kept as a sibling rather than extended on
// top of StepIndicator so V4 ergonomics are unaffected during migration.
export interface StepIndicatorV5Props {
  current: 1 | 2 | 3 | 4;
}

const STEPS_V5 = ['Connect', 'Generate', 'Sign', 'Prove + register'];

export function StepIndicatorV5({ current }: StepIndicatorV5Props) {
  return (
    <ol className="flex flex-wrap gap-6 text-mono text-sm" aria-label="Progress">
      {STEPS_V5.map((label, i) => {
        const idx = i + 1;
        const active = idx === current;
        const done = idx < current;
        return (
          <li key={label} className="flex items-center gap-2">
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
