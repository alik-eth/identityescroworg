// Out-of-gate landing page. Reached when assessDeviceCapability() returns
// `denied` at the start of the V5 register flow (see Step1ConnectWallet).
//
// Spec amendment 9c866ad (review pass 5) made mobile-browser a hard
// acceptance gate: only flagship 2024+ phones with persist() granted are
// supported. Everyone else gets routed here BEFORE the zkey download
// starts, so we never burn quota on a device that can't finish the proof.
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { DocumentFooter } from '../../components/DocumentFooter';
import { PaperGrain } from '../../components/PaperGrain';

const DESKTOP_URL = 'https://app.zkqes.org/ua/registerV5';

export function UseDesktopScreen() {
  const { t } = useTranslation();
  // Inline QR data-URL is heavy; we link out to a static QR endpoint
  // instead. Most modern phone cameras lift URLs from text — the QR is
  // a courtesy, not the primary handoff.
  const qrSrc = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(
    DESKTOP_URL,
  )}`;

  return (
    <main className="relative min-h-screen" data-testid="use-desktop-page">
      <PaperGrain />
      <div className="doc-grid pt-24 relative z-10">
        <div />
        <div className="max-w-2xl space-y-10">
          <Link to="/" className="text-mono text-xs block">
            ← back
          </Link>
          <header className="space-y-6">
            <h1
              className="text-4xl md:text-5xl leading-none"
              style={{ color: 'var(--ink)' }}
            >
              {t(
                'deviceGate.useDesktop.heading',
                "This device can't host the zero-knowledge prover.",
              )}
            </h1>
            <p
              className="text-base md:text-lg max-w-prose"
              style={{ color: 'var(--ink)' }}
            >
              {t(
                'deviceGate.useDesktop.body',
                'The prover needs about 2.5 GB of cached storage on your device — most phone browsers cap web pages well below that, so the proof would fail mid-flight. Open this page on a desktop or laptop browser instead and pick up where you left off.',
              )}
            </p>
          </header>
          <hr className="rule" />
          <section className="space-y-4">
            <p
              className="text-mono text-sm break-all"
              style={{ color: 'var(--ink)' }}
            >
              {DESKTOP_URL}
            </p>
            <img
              src={qrSrc}
              alt={t('deviceGate.useDesktop.qrCaption', 'QR code to app.zkqes.org on desktop')}
              width={200}
              height={200}
              className="border"
              style={{ borderColor: 'var(--rule)' }}
              data-testid="use-desktop-qr"
            />
            <p className="text-mono text-xs opacity-70">
              {t(
                'deviceGate.useDesktop.qrCaption',
                'Scan with another phone, or type the URL into a desktop browser.',
              )}
            </p>
          </section>
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
