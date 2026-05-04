// CliBanner — civic-monumental info-level banner that nudges users to
// install the zkqes CLI for native proof generation. Renders only when
// `useCliPresence` reports CLI absent AND the user has not dismissed
// the banner this browser profile.
//
// Plan ref: docs/superpowers/plans/2026-05-03-qkb-cli-server-web-eng.md T3.
//
// Aesthetic: matches the existing /v5/registerV5 aside pattern
// (RotateWalletFlow's `rotate-warning-*` panels) — bordered block,
// no shadow, no icon, EB Garamond display + Inter Tight body. Info
// level uses `--rule` border (subtle separator color) rather than
// `--seal` (which is reserved for warnings/alerts).
//
// Dismiss persistence: localStorage. SessionStorage would re-show on
// every tab open, which feels pushy for an OPTIONAL upgrade. The CLI
// is genuinely optional — browser prove must remain a working path
// (CLAUDE.md V5.16).
import { useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { useCliPresence } from '../../../hooks/useCliPresence';

/** localStorage key for the dismiss flag. Namespaced so future banner
 *  additions can re-use the same prefix. */
export const CLI_BANNER_DISMISSED_KEY = 'zkqes.cliBanner.dismissed';

function readDismissed(): boolean {
  try {
    return globalThis.localStorage?.getItem(CLI_BANNER_DISMISSED_KEY) === '1';
  } catch {
    // SSR path or sandboxed iframe — treat as not-dismissed.
    return false;
  }
}

function writeDismissed(): void {
  try {
    globalThis.localStorage?.setItem(CLI_BANNER_DISMISSED_KEY, '1');
  } catch {
    // No-op — the banner just won't persist its dismissal across reloads,
    // which is the lesser evil vs throwing.
  }
}

export function CliBanner() {
  const { t } = useTranslation();
  const { status } = useCliPresence();
  const [dismissed, setDismissed] = useState<boolean>(() => readDismissed());

  // Don't render during 'detecting' (avoid a flash of the banner before
  // the CLI is detected) or 'present' (CLI is running — banner serves
  // no purpose) or after dismissal.
  if (status !== 'absent' || dismissed) return null;

  const onDismiss = (): void => {
    writeDismissed();
    setDismissed(true);
  };

  return (
    <aside
      className="p-4 space-y-2 border"
      style={{ borderColor: 'var(--rule)', color: 'var(--ink)' }}
      data-testid="cli-banner"
      role="complementary"
      aria-label={t('cliBanner.title')}
    >
      <p className="text-sm font-semibold">{t('cliBanner.title')}</p>
      <p className="text-sm" style={{ opacity: 0.85 }}>
        {t('cliBanner.body')}
      </p>
      <div className="flex items-center gap-4 text-sm">
        <Link
          to="/ua/cli"
          style={{ color: 'var(--sovereign)' }}
          data-testid="cli-banner-cta"
        >
          {t('cliBanner.cta')}
        </Link>
        <button
          type="button"
          onClick={onDismiss}
          className="text-mono text-xs"
          style={{ color: 'var(--ink)', opacity: 0.6 }}
          data-testid="cli-banner-dismiss"
        >
          {t('cliBanner.dismiss')}
        </button>
      </div>
    </aside>
  );
}
