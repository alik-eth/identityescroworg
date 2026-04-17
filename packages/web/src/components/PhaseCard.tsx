import type { ReactNode } from 'react';

type Accent = 'emerald' | 'blue' | 'amber' | 'red' | 'purple';

const ACCENT: Record<Accent, { border: string; text: string }> = {
  emerald: { border: 'border-emerald-500/30', text: 'text-emerald-300' },
  blue: { border: 'border-blue-500/30', text: 'text-blue-300' },
  amber: { border: 'border-amber-500/30', text: 'text-amber-300' },
  red: { border: 'border-red-500/30', text: 'text-red-300' },
  purple: { border: 'border-purple-500/30', text: 'text-purple-300' },
};

export interface PhaseCardProps {
  step: number;
  total: number;
  title: string;
  accent?: Accent;
  children?: ReactNode;
}

export function PhaseCard({ step, total, title, accent = 'emerald', children }: PhaseCardProps) {
  const a = ACCENT[accent];
  return (
    <section
      className={`animate-fade-in bg-slate-800/50 rounded-xl border ${a.border} p-6 md:p-8 relative cred-noise`}
    >
      <div className="flex items-center gap-3 mb-5">
        <span className="font-mono text-[10px] tracking-widest text-slate-500 uppercase">
          step {String(step).padStart(2, '0')} / {String(total).padStart(2, '0')}
        </span>
        <span className={`h-px flex-1 bg-gradient-to-r from-transparent ${a.border.replace('border-', 'via-')} to-transparent`} />
      </div>
      <h2 className={`text-2xl font-semibold ${a.text} mb-4`}>{title}</h2>
      <div className="text-slate-300 text-sm leading-relaxed">{children}</div>
    </section>
  );
}
