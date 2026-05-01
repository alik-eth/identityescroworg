// V5 Phase 2 ceremony — landing page.
//
// Public face of the multi-contributor trusted setup. The §11 ceremony
// runs as a 7-10 contributor real Phase 2 with each contributor signing
// + uploading their intermediate zkey via signed URL. Browser cannot run
// `snarkjs zkey contribute` (~30 GB RAM peak; V8 WASM-32 cap blocks);
// the page is coordination + instructions only.
//
// Civic-monumental aesthetic: matches existing landing's tonal register
// (declarative, sovereign, document-grade). Same primitives — EB Garamond
// display, Inter Tight body, sovereign indigo / sienna seal markers,
// no icons / cards / shadows.
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { DocumentFooter } from '../../components/DocumentFooter';
import { PaperGrain } from '../../components/PaperGrain';

export function CeremonyIndex() {
  const { t } = useTranslation();
  return (
    <main className="relative min-h-screen">
      <PaperGrain />
      <div className="doc-grid pt-24 relative z-10">
        <div />
        <div className="min-w-0 max-w-3xl space-y-12">
          <header>
            <h1
              className="text-4xl sm:text-5xl md:text-6xl leading-none mb-8"
              style={{ color: 'var(--ink)' }}
            >
              {t('ceremony.landing.heading', 'A trusted setup. In public.')}
            </h1>
            <p className="text-xl max-w-2xl" style={{ color: 'var(--ink)' }}>
              {t(
                'ceremony.landing.lede',
                'The V5 prover keys are produced by a multi-contributor ceremony. So long as one contributor honestly destroys their entropy, the ceremony is sound. We are publishing every step.',
              )}
            </p>
          </header>

          <hr className="rule" />

          <section
            aria-labelledby="why-heading"
            data-testid="ceremony-why"
            className="space-y-6"
          >
            <h2
              id="why-heading"
              className="text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('ceremony.landing.whyHeading', 'Why a ceremony at all')}
            </h2>
            <p className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
              {t(
                'ceremony.landing.whyBody',
                'Groth16 proofs require a structured reference string. The string is generated once, by a specific party, with private randomness that — if known to anyone — would let that party forge proofs. A multi-party ceremony randomises the string across many independent contributors. Each adds entropy and destroys their own. The final string is sound under the assumption that at least one contributor was honest.',
              )}
            </p>
          </section>

          <hr className="rule" />

          <section
            aria-labelledby="trust-heading"
            data-testid="ceremony-trust"
            className="space-y-6"
          >
            <h2
              id="trust-heading"
              className="text-3xl"
              style={{ color: 'var(--ink)' }}
            >
              {t('ceremony.landing.trustHeading', 'What we publish')}
            </h2>
            <dl className="space-y-8">
              <div>
                <dt
                  className="text-fine text-sm mb-2"
                  style={{
                    color: 'var(--sovereign)',
                    fontVariant: 'small-caps',
                    letterSpacing: '0.08em',
                  }}
                >
                  <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                    ·
                  </span>
                  {t('ceremony.landing.publishChainLabel', 'The contributor chain')}
                </dt>
                <dd className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                  {t(
                    'ceremony.landing.publishChainBody',
                    'Every contributor’s handle, round number, and signed attestation hash. Anyone can independently verify each link.',
                  )}
                </dd>
              </div>
              <div>
                <dt
                  className="text-fine text-sm mb-2"
                  style={{
                    color: 'var(--sovereign)',
                    fontVariant: 'small-caps',
                    letterSpacing: '0.08em',
                  }}
                >
                  <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                    ·
                  </span>
                  {t('ceremony.landing.publishBeaconLabel', 'A public-randomness beacon')}
                </dt>
                <dd className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                  {t(
                    'ceremony.landing.publishBeaconBody',
                    'After the last contributor, we mix in a Bitcoin (or Ethereum mainnet) block hash. The block height is committed in advance — no one can predict the bytes.',
                  )}
                </dd>
              </div>
              <div>
                <dt
                  className="text-fine text-sm mb-2"
                  style={{
                    color: 'var(--sovereign)',
                    fontVariant: 'small-caps',
                    letterSpacing: '0.08em',
                  }}
                >
                  <span aria-hidden="true" style={{ color: 'var(--seal)', marginRight: '0.5em' }}>
                    ·
                  </span>
                  {t('ceremony.landing.publishHashLabel', 'The final zkey hash')}
                </dt>
                <dd className="text-base max-w-prose" style={{ color: 'var(--ink)' }}>
                  {t(
                    'ceremony.landing.publishHashBody',
                    'The SHA-256 of the final prover key, committed on chain alongside the verifier contract. Anyone can verify their downloaded zkey matches.',
                  )}
                </dd>
              </div>
            </dl>
          </section>

          <hr className="rule" />

          <nav
            aria-label={t('ceremony.landing.navAria', 'Ceremony sections')}
            className="space-y-4"
            data-testid="ceremony-nav"
          >
            <Link
              to="/ceremony/contribute"
              className="block text-lg"
              style={{ color: 'var(--sovereign)' }}
            >
              {t('ceremony.landing.contributeLink', 'Contribute to the ceremony →')}
            </Link>
            <Link
              to="/ceremony/status"
              className="block text-lg"
              style={{ color: 'var(--sovereign)' }}
            >
              {t('ceremony.landing.statusLink', 'Live progress →')}
            </Link>
            <Link
              to="/ceremony/verify"
              className="block text-lg"
              style={{ color: 'var(--sovereign)' }}
            >
              {t('ceremony.landing.verifyLink', 'Verify the final zkey →')}
            </Link>
          </nav>
        </div>
      </div>
      <DocumentFooter />
    </main>
  );
}
