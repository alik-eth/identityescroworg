export interface StepIndicatorProps {
  current: 1 | 2 | 3;
}

const STEPS = ['Install', 'Submit', 'Mint'];

export function StepIndicator({ current }: StepIndicatorProps) {
  return (
    <ol className="flex gap-6 text-mono text-sm" aria-label="Progress">
      {STEPS.map((label, i) => {
        const idx = i + 1;
        const active = idx === current;
        const done   = idx < current;
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
