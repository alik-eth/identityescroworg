// Copy-to-clipboard button. Civic-monumental treatment: text-only, no
// icons, no shadows. Copy state surfaces as a brief label swap; falls
// back to a stable "Copy" if the Clipboard API is unavailable (older
// Safari, sandboxed iframes).
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

export interface CopyButtonProps {
  /** The text to copy. Multi-line code blocks are fine. */
  readonly text: string;
  /** Optional aria-label override; defaults to a translated "Copy command". */
  readonly ariaLabel?: string;
  readonly testId?: string;
}

export function CopyButton({ text, ariaLabel, testId }: CopyButtonProps) {
  const { t } = useTranslation();
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');

  const onClick = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(text);
      setState('copied');
      setTimeout(() => setState('idle'), 1600);
    } catch {
      setState('failed');
      setTimeout(() => setState('idle'), 1600);
    }
  };

  const label =
    state === 'copied'
      ? t('ceremony.copy.copied', 'Copied')
      : state === 'failed'
        ? t('ceremony.copy.failed', 'Copy failed')
        : t('ceremony.copy.idle', 'Copy');

  return (
    <button
      type="button"
      onClick={() => void onClick()}
      aria-label={ariaLabel ?? t('ceremony.copy.aria', 'Copy command')}
      {...(testId ? { 'data-testid': testId } : {})}
      className="text-mono text-xs px-3 py-1"
      style={{
        color: 'var(--sovereign)',
        borderBottom: '1px solid var(--sovereign)',
        background: 'transparent',
      }}
    >
      {label}
    </button>
  );
}
